const std = @import("std");
const posix = std.posix;
const header = @import("header.zig");
const pointer = @import("pointer.zig");
const security = @import("security.zig");

pub const WAL_MAGIC: u32 = 0x57414C46;
pub const WAL_VERSION: u32 = 1;
pub const WAL_BLOCK_SIZE: u64 = 4096;
pub const MAX_RECORDS_PER_TRANSACTION: usize = 1024;

pub const RecordType = enum(u8) {
    begin = 1,
    commit = 2,
    rollback = 3,
    allocate = 4,
    free = 5,
    write = 6,
    free_list_add = 7,
    free_list_remove = 8,
    heap_extend = 9,
    root_update = 10,
    ref_count_inc = 11,
    ref_count_dec = 12,
    gc_mark = 13,
    gc_sweep = 14,
    checkpoint = 15,
};

pub const WALHeader = extern struct {
    magic: u32,
    version: u32,
    file_size: u64,
    last_checkpoint: u64,
    transaction_counter: u64,
    head_offset: u64,
    tail_offset: u64,
    checksum: u32,
    reserved: [28]u8,

    pub fn init() WALHeader {
        return WALHeader{
            .magic = WAL_MAGIC,
            .version = WAL_VERSION,
            .file_size = @sizeOf(WALHeader),
            .last_checkpoint = 0,
            .transaction_counter = 0,
            .head_offset = @sizeOf(WALHeader),
            .tail_offset = @sizeOf(WALHeader),
            .checksum = 0,
            .reserved = [_]u8{0} ** 28,
        };
    }

    pub fn validate(self: *const WALHeader) !void {
        if (self.magic != WAL_MAGIC) return error.InvalidWALMagic;
        if (self.version > WAL_VERSION) return error.UnsupportedWALVersion;
    }

    pub fn computeChecksum(self: *const WALHeader) u32 {
        const bytes = std.mem.asBytes(self);
        var crc: u32 = 0xFFFFFFFF;
        for (bytes[0..@offsetOf(WALHeader, "checksum")]) |byte| {
            crc = crc32cByte(crc, byte);
        }
        return crc ^ 0xFFFFFFFF;
    }

    pub fn updateChecksum(self: *WALHeader) void {
        self.checksum = self.computeChecksum();
    }

    fn crc32cByte(crc: u32, byte: u8) u32 {
        const POLY: u32 = 0x82F63B78;
        var c = crc ^ @as(u32, byte);
        var j: usize = 0;
        while (j < 8) : (j += 1) {
            c = if ((c & 1) != 0) (c >> 1) ^ POLY else c >> 1;
        }
        return c;
    }
};

pub const WALRecord = extern struct {
    record_type: RecordType,
    flags: u8,
    transaction_id: u64,
    sequence: u64,
    offset: u64,
    size: u64,
    old_value_offset: u64,
    old_value_size: u64,
    data_checksum: u32,
    record_checksum: u32,

    pub fn init(
        record_type: RecordType,
        tx_id: u64,
        seq: u64,
        offset: u64,
        size: u64,
    ) WALRecord {
        return WALRecord{
            .record_type = record_type,
            .flags = 0,
            .transaction_id = tx_id,
            .sequence = seq,
            .offset = offset,
            .size = size,
            .old_value_offset = 0,
            .old_value_size = 0,
            .data_checksum = 0,
            .record_checksum = 0,
        };
    }

    pub fn computeChecksum(self: *const WALRecord) u32 {
        const bytes = std.mem.asBytes(self);
        var crc: u32 = 0xFFFFFFFF;
        for (bytes[0..@offsetOf(WALRecord, "record_checksum")]) |byte| {
            crc = crc32cByte(crc, byte);
        }
        return crc ^ 0xFFFFFFFF;
    }

    pub fn updateChecksum(self: *WALRecord) void {
        self.record_checksum = self.computeChecksum();
    }

    pub fn validate(self: *const WALRecord) !void {
        if (self.computeChecksum() != self.record_checksum) {
            return error.RecordChecksumMismatch;
        }
    }

    fn crc32cByte(crc: u32, byte: u8) u32 {
        const POLY: u32 = 0x82F63B78;
        var c = crc ^ @as(u32, byte);
        var j: usize = 0;
        while (j < 8) : (j += 1) {
            c = if ((c & 1) != 0) (c >> 1) ^ POLY else c >> 1;
        }
        return c;
    }
};

pub const Transaction = struct {
    id: u64,
    state: State,
    records: std.ArrayList(WALRecord),
    undo_data: std.ArrayList([]u8),
    start_offset: u64,
    allocator: std.mem.Allocator,

    pub const State = enum(u8) {
        active,
        committed,
        rolled_back,
        prepared,
    };

    pub fn init(allocator_ptr: std.mem.Allocator, id: u64) Transaction {
        return Transaction{
            .id = id,
            .state = .active,
            .records = std.ArrayList(WALRecord).init(allocator_ptr),
            .undo_data = std.ArrayList([]u8).init(allocator_ptr),
            .start_offset = 0,
            .allocator = allocator_ptr,
        };
    }

    pub fn deinit(self: *Transaction) void {
        for (self.undo_data.items) |data| {
            self.allocator.free(data);
        }
        self.undo_data.deinit();
        self.records.deinit();
    }

    pub fn addRecord(self: *Transaction, record: WALRecord) !void {
        try self.records.append(record);
    }

    pub fn addUndoData(self: *Transaction, data: []const u8) !void {
        const copy = try self.allocator.dupe(u8, data);
        try self.undo_data.append(copy);
    }

    pub fn getRecordCount(self: *const Transaction) usize {
        return self.records.items.len;
    }
};

pub const WAL = struct {
    file: std.fs.File,
    file_path: []const u8,
    header: *WALHeader,
    base_addr: [*]align(std.mem.page_size) u8,
    mapped_size: u64,
    current_transaction: ?Transaction,
    security: ?*security.SecurityManager,
    allocator: std.mem.Allocator,
    lock: std.Thread.Mutex,
    sequence_counter: u64,

    const Self = @This();

    pub fn init(
        allocator_ptr: std.mem.Allocator,
        file_path: []const u8,
        security_mgr: ?*security.SecurityManager,
    ) !*WAL {
        const self = try allocator_ptr.create(WAL);
        errdefer allocator_ptr.destroy(self);

        const path_copy = try allocator_ptr.dupe(u8, file_path);

        const file = std.fs.cwd().createFile(
            file_path,
            .{ .read = true, .truncate = false, .exclusive = false },
        ) catch |err| blk: {
            if (err == error.PathAlreadyExists) {
                break :blk try std.fs.cwd().openFile(file_path, .{ .mode = .read_write });
            } else {
                return err;
            }
        };
        errdefer file.close();

        const stat = try file.stat();
        const initial_size: u64 = 1024 * 1024 * 64;
        const file_size = if (stat.size == 0) initial_size else stat.size;

        if (stat.size == 0) {
            try file.setEndPos(file_size);
        }

        const base_addr = try posix.mmap(
            null,
            file_size,
            posix.PROT.READ | posix.PROT.WRITE,
            .{ .TYPE = .SHARED },
            file.handle,
            0,
        );
        errdefer posix.munmap(base_addr);

        const header_ptr: *WALHeader = @ptrCast(@alignCast(base_addr.ptr));

        if (stat.size == 0) {
            header_ptr.* = WALHeader.init();
            header_ptr.file_size = file_size;
            header_ptr.updateChecksum();
        } else {
            try header_ptr.validate();
        }

        self.* = WAL{
            .file = file,
            .file_path = path_copy,
            .header = header_ptr,
            .base_addr = @ptrCast(@alignCast(base_addr.ptr)),
            .mapped_size = file_size,
            .current_transaction = null,
            .security = security_mgr,
            .allocator = allocator_ptr,
            .lock = std.Thread.Mutex{},
            .sequence_counter = 0,
        };

        return self;
    }

    pub fn deinit(self: *WAL) void {
        self.flush() catch {};

        if (self.current_transaction) |*tx| {
            tx.deinit();
        }

        posix.munmap(self.base_addr[0..self.mapped_size]);
        self.file.close();
        self.allocator.free(self.file_path);
        self.allocator.destroy(self);
    }

    pub fn beginTransaction(self: *Self) !Transaction {
        self.lock.lock();
        defer self.lock.unlock();

        self.header.transaction_counter += 1;
        self.header.updateChecksum();

        var tx = Transaction.init(self.allocator, self.header.transaction_counter);
        tx.start_offset = self.header.tail_offset;

        const begin_record = WALRecord.init(.begin, tx.id, self.getNextSequence(), 0, 0);
        try tx.addRecord(begin_record);

        return tx;
    }

    pub fn endTransaction(self: *Self, tx: *Transaction) !void {
        self.lock.lock();
        defer self.lock.unlock();

        if (tx.state == .active) {
            tx.state = .rolled_back;
        }

        if (self.current_transaction) |*current| {
            if (current.id == tx.id) {
                current.deinit();
                self.current_transaction = null;
            }
        }

        tx.deinit();
    }

    pub fn appendRecord(self: *Self, tx: *Transaction, record_type: RecordType, offset: u64, size: u64) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const record = WALRecord.init(record_type, tx.id, self.getNextSequence(), offset, size);
        try tx.addRecord(record);
    }

    pub fn appendRecordWithData(self: *Self, tx: *Transaction, record_type: RecordType, offset: u64, size: u64, old_data: []const u8) !void {
        self.lock.lock();
        defer self.lock.unlock();

        var record = WALRecord.init(record_type, tx.id, self.getNextSequence(), offset, size);
        record.old_value_offset = self.header.tail_offset + @sizeOf(WALRecord);
        record.old_value_size = old_data.len;
        record.data_checksum = computeDataChecksum(old_data);
        record.updateChecksum();

        try tx.addRecord(record);
        try tx.addUndoData(old_data);
    }

    pub fn commitTransaction(self: *Self, tx: *Transaction) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const commit_record = WALRecord.init(.commit, tx.id, self.getNextSequence(), 0, 0);
        try tx.addRecord(commit_record);

        try self.writeTransactionRecords(tx);

        tx.state = .committed;

        try self.sync();
    }

    pub fn rollbackTransaction(self: *Self, tx: *Transaction) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const rollback_record = WALRecord.init(.rollback, tx.id, self.getNextSequence(), 0, 0);
        try tx.addRecord(rollback_record);

        try self.writeTransactionRecords(tx);

        tx.state = .rolled_back;
    }

    fn writeTransactionRecords(self: *Self, tx: *Transaction) !void {
        var offset = self.header.tail_offset;

        for (tx.records.items) |*record| {
            record.updateChecksum();

            if (offset + @sizeOf(WALRecord) > self.mapped_size) {
                try self.expandFile();
            }

            const record_ptr: *WALRecord = @ptrCast(@alignCast(self.base_addr + offset));
            record_ptr.* = record.*;
            offset += @sizeOf(WALRecord);

            self.header.tail_offset = offset;
        }

        var undo_idx: usize = 0;
        for (tx.undo_data.items) |data| {
            if (offset + data.len > self.mapped_size) {
                try self.expandFile();
            }

            @memcpy(self.base_addr[offset .. offset + data.len], data);
            offset += data.len;
            undo_idx += 1;
        }

        self.header.tail_offset = offset;
        self.header.updateChecksum();

        try self.flushHeader();
    }

    pub fn getRecords(self: *Self, start_offset: u64, max_records: usize) !std.ArrayList(WALRecord) {
        var records = std.ArrayList(WALRecord).init(self.allocator);
        errdefer records.deinit();

        var offset = start_offset;
        var count: usize = 0;

        while (offset < self.header.tail_offset and count < max_records) {
            const record_ptr: *const WALRecord = @ptrCast(@alignCast(self.base_addr + offset));

            record_ptr.validate() catch break;

            try records.append(record_ptr.*);
            offset += @sizeOf(WALRecord);
            count += 1;
        }

        return records;
    }

    pub fn getTransactions(self: *Self) !std.ArrayList(Transaction) {
        var transactions = std.ArrayList(Transaction).init(self.allocator);
        errdefer transactions.deinit();

        var offset: u64 = @sizeOf(WALHeader);
        var current_tx: ?Transaction = null;

        while (offset < self.header.tail_offset) {
            const record_ptr: *const WALRecord = @ptrCast(@alignCast(self.base_addr + offset));
            record_ptr.validate() catch break;

            switch (record_ptr.record_type) {
                .begin => {
                    if (current_tx) |*tx| {
                        try transactions.append(tx.*);
                    }
                    current_tx = Transaction.init(self.allocator, record_ptr.transaction_id);
                    current_tx.?.start_offset = offset;
                },
                .commit => {
                    if (current_tx) |*tx| {
                        tx.state = .committed;
                        try transactions.append(tx.*);
                        current_tx = null;
                    }
                },
                .rollback => {
                    if (current_tx) |*tx| {
                        tx.state = .rolled_back;
                        try transactions.append(tx.*);
                        current_tx = null;
                    }
                },
                else => {
                    if (current_tx) |*tx| {
                        try tx.addRecord(record_ptr.*);
                    }
                },
            }

            offset += @sizeOf(WALRecord);
        }

        if (current_tx) |*tx| {
            try transactions.append(tx.*);
        }

        return transactions;
    }

    pub fn checkpoint(self: *Self) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const checkpoint_record = WALRecord.init(.checkpoint, 0, self.getNextSequence(), self.header.tail_offset, 0);
        var record = checkpoint_record;
        record.updateChecksum();

        const offset = self.header.tail_offset;
        const record_ptr: *WALRecord = @ptrCast(@alignCast(self.base_addr + offset));
        record_ptr.* = record;

        self.header.tail_offset = offset + @sizeOf(WALRecord);
        self.header.head_offset = self.header.tail_offset;
        self.header.last_checkpoint = self.header.tail_offset;
        self.header.updateChecksum();

        try self.flushHeader();
        try self.sync();
    }

    pub fn truncate(self: *Self, new_offset: u64) !void {
        self.lock.lock();
        defer self.lock.unlock();

        if (new_offset < @sizeOf(WALHeader)) return error.InvalidTruncateOffset;
        if (new_offset > self.header.tail_offset) return;

        self.header.head_offset = new_offset;
        self.header.updateChecksum();

        try self.flushHeader();
    }

    pub fn flush(self: *Self) !void {
        try self.flushHeader();
    }

    fn flushHeader(self: *Self) !void {
        _ = self;
    }

    pub fn sync(self: *Self) !void {
        try posix.fsync(self.file.handle);
    }

    pub fn getSize(self: *Self) u64 {
        return self.header.tail_offset;
    }

    pub fn getTransactionCount(self: *Self) u64 {
        return self.header.transaction_counter;
    }

    pub fn getLastCheckpoint(self: *Self) u64 {
        return self.header.last_checkpoint;
    }

    fn getNextSequence(self: *Self) u64 {
        self.sequence_counter += 1;
        return self.sequence_counter;
    }

    fn expandFile(self: *Self) !void {
        const new_size = self.mapped_size * 2;

        posix.munmap(self.base_addr[0..self.mapped_size]);

        try self.file.setEndPos(new_size);

        const new_base = try posix.mmap(
            null,
            new_size,
            posix.PROT.READ | posix.PROT.WRITE,
            .{ .TYPE = .SHARED },
            self.file.handle,
            0,
        );

        self.base_addr = @ptrCast(@alignCast(new_base.ptr));
        self.mapped_size = new_size;
        self.header = @ptrCast(@alignCast(self.base_addr));
        self.header.file_size = new_size;
        self.header.updateChecksum();
    }

    pub fn getUndoData(self: *Self, record: *const WALRecord) ![]const u8 {
        if (record.old_value_size == 0) return &[_]u8{};

        const data_start = record.old_value_offset;
        const data_end = data_start + record.old_value_size;

        if (data_end > self.mapped_size) return error.InvalidUndoOffset;

        return self.base_addr[data_start..data_end];
    }
};

fn computeDataChecksum(data: []const u8) u32 {
    const POLY: u32 = 0x82F63B78;
    var crc: u32 = 0xFFFFFFFF;
    for (data) |byte| {
        crc ^= @as(u32, byte);
        var j: usize = 0;
        while (j < 8) : (j += 1) {
            crc = if ((crc & 1) != 0) (crc >> 1) ^ POLY else crc >> 1;
        }
    }
    return crc ^ 0xFFFFFFFF;
}

test "wal initialization" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_path = "/tmp/test_wal.wal";
    std.fs.cwd().deleteFile(test_path) catch {};

    var wal = try WAL.init(alloc, test_path, null);
    defer wal.deinit();

    try testing.expect(wal.header.magic == WAL_MAGIC);
}

test "transaction lifecycle" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_path = "/tmp/test_wal_tx.wal";
    std.fs.cwd().deleteFile(test_path) catch {};

    var wal = try WAL.init(alloc, test_path, null);
    defer wal.deinit();

    var tx = try wal.beginTransaction();
    defer wal.endTransaction(&tx) catch {};

    try wal.appendRecord(&tx, .write, 100, 64);
    try testing.expect(tx.getRecordCount() == 2);

    try wal.commitTransaction(&tx);
    try testing.expect(tx.state == .committed);
}
