const std = @import("std");
const wal_mod = @import("wal.zig");
const pheap = @import("pheap.zig");
const pointer = @import("pointer.zig");
const header = @import("header.zig");

pub const TransactionState = enum(u8) {
    inactive,
    active,
    prepared,
    committed,
    rolled_back,
    failed,
};

pub const OperationType = enum(u8) {
    read,
    write,
    allocate,
    free,
    root_update,
};

pub const Operation = struct {
    op_type: OperationType,
    offset: u64,
    size: u64,
    old_data: ?[]const u8,
    new_data: ?[]const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator_ptr: std.mem.Allocator, op_type: OperationType, offset: u64, size: u64) Operation {
        return Operation{
            .op_type = op_type,
            .offset = offset,
            .size = size,
            .old_data = null,
            .new_data = null,
            .allocator = allocator_ptr,
        };
    }

    pub fn deinit(self: *Operation) void {
        if (self.old_data) |data| {
            self.allocator.free(data);
        }
        if (self.new_data) |data| {
            self.allocator.free(data);
        }
    }

    pub fn setOldData(self: *Operation, data: []const u8) !void {
        if (self.old_data) |old| {
            self.allocator.free(old);
        }
        self.old_data = try self.allocator.dupe(u8, data);
    }

    pub fn setNewData(self: *Operation, data: []const u8) !void {
        if (self.new_data) |old| {
            self.allocator.free(old);
        }
        self.new_data = try self.allocator.dupe(u8, data);
    }
};

pub const PendingAllocation = struct {
    offset: u64,
    size: u64,
};

pub const Transaction = struct {
    id: u64,
    state: TransactionState,
    operations: std.ArrayList(Operation),
    wal_tx: ?wal_mod.Transaction,
    start_time: i64,
    allocator: std.mem.Allocator,
    read_set: std.ArrayList(u64),
    write_set: std.ArrayList(u64),
    pending_allocations: std.ArrayList(PendingAllocation),
    parent_tx: ?u64,

    pub fn init(allocator_ptr: std.mem.Allocator, id: u64, wal_tx: wal_mod.Transaction) Transaction {
        return Transaction{
            .id = id,
            .state = .active,
            .operations = std.ArrayList(Operation).init(allocator_ptr),
            .wal_tx = wal_tx,
            .start_time = std.time.timestamp(),
            .allocator = allocator_ptr,
            .read_set = std.ArrayList(u64).init(allocator_ptr),
            .write_set = std.ArrayList(u64).init(allocator_ptr),
            .pending_allocations = std.ArrayList(PendingAllocation).init(allocator_ptr),
            .parent_tx = null,
        };
    }

    pub fn deinit(self: *Transaction) void {
        for (self.operations.items) |*op| {
            op.deinit();
        }
        self.operations.deinit();
        self.read_set.deinit();
        self.write_set.deinit();
        self.pending_allocations.deinit();
    }

    pub fn trackAllocation(self: *Transaction, offset: u64, size: u64) !void {
        try self.pending_allocations.append(.{ .offset = offset, .size = size });
    }

    pub fn addOperation(self: *Transaction, op: Operation) !void {
        try self.operations.append(op);
    }

    pub fn addRead(self: *Transaction, offset: u64) !void {
        try self.read_set.append(offset);
    }

    pub fn addWrite(self: *Transaction, offset: u64) !void {
        try self.write_set.append(offset);
    }

    pub fn getOperationCount(self: *const Transaction) usize {
        return self.operations.items.len;
    }

    pub fn hasConflict(self: *const Transaction, other: *const Transaction) bool {
        for (self.write_set.items) |ws| {
            for (other.read_set.items) |rs| {
                if (ws == rs) return true;
            }
            for (other.write_set.items) |ows| {
                if (ws == ows) return true;
            }
        }
        for (self.read_set.items) |rs| {
            for (other.write_set.items) |ws| {
                if (rs == ws) return true;
            }
        }
        return false;
    }
};

pub const TransactionManager = struct {
    wal: *wal_mod.WAL,
    heap: *pheap.PersistentHeap,
    allocator_ref: ?*anyopaque,
    undo_allocation_fn: ?*const fn (ctx: *anyopaque, offset: u64, size: u64) anyerror!void,
    active_transactions: std.AutoHashMap(u64, Transaction),
    transaction_counter: u64,
    lock: std.Thread.RwLock,
    allocator: std.mem.Allocator,
    max_active_transactions: usize,

    pub fn setAllocatorHook(
        self: *@This(),
        ctx: *anyopaque,
        undo_fn: *const fn (ctx: *anyopaque, offset: u64, size: u64) anyerror!void,
    ) void {
        self.allocator_ref = ctx;
        self.undo_allocation_fn = undo_fn;
    }

    const Self = @This();

    pub fn init(allocator_ptr: std.mem.Allocator, wal: *wal_mod.WAL, heap: *pheap.PersistentHeap) !*TransactionManager {
        const self = try allocator_ptr.create(TransactionManager);
        errdefer allocator_ptr.destroy(self);

        self.* = TransactionManager{
            .wal = wal,
            .heap = heap,
            .allocator_ref = null,
            .undo_allocation_fn = null,
            .active_transactions = std.AutoHashMap(u64, Transaction).init(allocator_ptr),
            .transaction_counter = 0,
            .lock = std.Thread.RwLock{},
            .allocator = allocator_ptr,
            .max_active_transactions = 1024,
        };

        return self;
    }

    pub fn deinit(self: *Self) void {
        var iter = self.active_transactions.iterator();
        while (iter.next()) |entry| {
            var tx = entry.value_ptr;
            tx.deinit();
        }
        self.active_transactions.deinit();
        self.allocator.destroy(self);
    }

    pub fn begin(self: *Self) !*Transaction {
        self.lock.lock();
        defer self.lock.unlock();

        if (self.active_transactions.count() >= self.max_active_transactions) {
            return error.TooManyActiveTransactions;
        }

        self.transaction_counter += 1;
        const id = self.transaction_counter;

        const wal_tx = try self.wal.beginTransaction();

        const tx = Transaction.init(self.allocator, id, wal_tx);
        try self.active_transactions.put(id, tx);

        const entry = self.active_transactions.getPtr(id).?;
        entry.state = .active;

        return entry;
    }

    pub fn commit(self: *Self, tx: *Transaction) !void {
        self.lock.lock();
        defer self.lock.unlock();

        if (tx.state != .active) {
            return error.TransactionNotActive;
        }

        if (tx.wal_tx) |*wal_tx| {
            try self.wal.commitTransaction(wal_tx);
        }

        tx.state = .committed;

        if (self.active_transactions.fetchRemove(tx.id)) |entry| {
            var removed_tx = entry.value;
            removed_tx.deinit();
        }

        try self.heap.flush();
    }

    pub fn rollback(self: *Self, tx: *Transaction) !void {
        self.lock.lock();
        defer self.lock.unlock();

        if (tx.state != .active and tx.state != .failed) {
            return error.TransactionNotActive;
        }

        if (tx.wal_tx) |*wal_tx| {
            try self.wal.rollbackTransaction(wal_tx);
        }

        if (self.undo_allocation_fn) |undo_fn| {
            if (self.allocator_ref) |ctx| {
                for (tx.pending_allocations.items) |pa| {
                    undo_fn(ctx, pa.offset, pa.size) catch {};
                }
            }
        }

        tx.state = .rolled_back;

        if (self.active_transactions.fetchRemove(tx.id)) |entry| {
            var removed_tx = entry.value;
            removed_tx.deinit();
        }
    }

    pub fn prepare(self: *Self, tx: *Transaction) !void {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        if (tx.state != .active) {
            return error.TransactionNotActive;
        }

        tx.state = .prepared;
    }

    pub fn getActiveTransactionCount(self: *Self) usize {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.active_transactions.count();
    }

    pub fn getTransaction(self: *Self, id: u64) ?*Transaction {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.active_transactions.getPtr(id);
    }

    pub fn recordRead(self: *Self, tx: *Transaction, offset: u64) !void {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        try tx.addRead(offset);
    }

    pub fn recordWrite(self: *Self, tx: *Transaction, offset: u64, size: u64, old_data: []const u8) !void {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        var op = Operation.init(self.allocator, .write, offset, size);
        try op.setOldData(old_data);
        try tx.addOperation(op);
        try tx.addWrite(offset);

        if (tx.wal_tx) |*wal_tx| {
            try self.wal.appendRecordWithData(wal_tx, .write, offset, size, old_data);
        }
    }

    pub fn recordAllocate(self: *Self, tx: *Transaction, offset: u64, size: u64) !void {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const op = Operation.init(self.allocator, .allocate, offset, size);
        try tx.addOperation(op);

        if (tx.wal_tx) |*wal_tx| {
            try self.wal.appendRecord(wal_tx, .allocate, offset, size);
        }
    }

    pub fn recordFree(self: *Self, tx: *Transaction, offset: u64, size: u64, old_data: []const u8) !void {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        var op = Operation.init(self.allocator, .free, offset, size);
        try op.setOldData(old_data);
        try tx.addOperation(op);
        try tx.addWrite(offset);

        if (tx.wal_tx) |*wal_tx| {
            try self.wal.appendRecordWithData(wal_tx, .free, offset, size, old_data);
        }
    }

    pub fn recordRootUpdate(self: *Self, tx: *Transaction, old_root: ?pointer.PersistentPtr, new_root: pointer.PersistentPtr) !void {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        var op = Operation.init(self.allocator, .root_update, new_root.offset, @sizeOf(pointer.PersistentPtr));
        if (old_root) |root| {
            try op.setOldData(std.mem.asBytes(&root));
        }
        try op.setNewData(std.mem.asBytes(&new_root));
        try tx.addOperation(op);

        if (tx.wal_tx) |*wal_tx| {
            try self.wal.appendRecord(wal_tx, .root_update, new_root.offset, @sizeOf(pointer.PersistentPtr));
        }
    }

    pub fn getTransactionCount(self: *Self) u64 {
        return self.transaction_counter;
    }

    pub fn timeoutTransactions(self: *Self, timeout_ms: u64) !usize {
        self.lock.lock();
        defer self.lock.unlock();

        const current_time = std.time.timestamp();
        var timed_out: usize = 0;

        var to_remove = std.ArrayList(u64).init(self.allocator);
        defer to_remove.deinit();

        var iter = self.active_transactions.iterator();
        while (iter.next()) |entry| {
            const tx = entry.value_ptr;
            const elapsed_ms = @as(u64, @intCast((current_time - tx.start_time) * 1000));
            if (elapsed_ms > timeout_ms) {
                try to_remove.append(entry.key_ptr.*);
                timed_out += 1;
            }
        }

        for (to_remove.items) |id| {
            if (self.active_transactions.fetchRemove(id)) |entry| {
                var tx = entry.value;
                if (tx.wal_tx) |*wal_tx| {
                    try self.wal.rollbackTransaction(wal_tx);
                }
                tx.deinit();
            }
        }

        return timed_out;
    }
};

test "transaction manager lifecycle" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_heap_path = "/tmp/test_tx_mgr.dat";
    const test_wal_path = "/tmp/test_tx_mgr.wal";
    std.fs.cwd().deleteFile(test_heap_path) catch {};
    std.fs.cwd().deleteFile(test_wal_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, test_heap_path, 1024 * 1024, null);
    defer heap.deinit();

    var wal = try wal_mod.WAL.init(alloc, test_wal_path, null);
    defer wal.deinit();

    var tx_mgr = try TransactionManager.init(alloc, wal, heap);
    defer tx_mgr.deinit();

    const tx = try tx_mgr.begin();
    try testing.expect(tx.state == .active);
    try testing.expect(tx.id > 0);
    try tx_mgr.rollback(tx);
}

test "transaction commit" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_heap_path = "/tmp/test_tx_commit.dat";
    const test_wal_path = "/tmp/test_tx_commit.wal";
    std.fs.cwd().deleteFile(test_heap_path) catch {};
    std.fs.cwd().deleteFile(test_wal_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, test_heap_path, 1024 * 1024, null);
    defer heap.deinit();

    var wal = try wal_mod.WAL.init(alloc, test_wal_path, null);
    defer wal.deinit();

    var tx_mgr = try TransactionManager.init(alloc, wal, heap);
    defer tx_mgr.deinit();

    const tx = try tx_mgr.begin();
    try tx_mgr.recordAllocate(tx, 100, 64);
    try tx_mgr.commit(tx);

    try testing.expectEqual(@as(usize, 0), tx_mgr.getActiveTransactionCount());
}
