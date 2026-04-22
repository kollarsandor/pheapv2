const std = @import("std");
const wal_mod = @import("wal.zig");
const pheap = @import("pheap.zig");
const header = @import("header.zig");
const allocator_mod = @import("allocator.zig");

pub const RecoveryPhase = enum(u8) {
    none,
    analysis,
    redo,
    undo,
    complete,
    failed,
};

pub const RecoveryStats = struct {
    transactions_analyzed: u64,
    transactions_committed: u64,
    transactions_rolled_back: u64,
    records_redone: u64,
    records_undone: u64,
    errors: u64,
    start_time: i64,
    end_time: i64,
};

pub const RecoveryError = error{
    CorruptedWAL,
    IncompleteTransaction,
    InvalidRecord,
    HeapCorruption,
    CheckpointNotFound,
    UndoFailed,
    RedoFailed,
};

pub const RecoveryEngine = struct {
    heap: *pheap.PersistentHeap,
    wal: *wal_mod.WAL,
    phase: RecoveryPhase,
    stats: RecoveryStats,
    allocator: std.mem.Allocator,
    incomplete_transactions: std.AutoHashMap(u64, wal_mod.Transaction),
    committed_transactions: std.AutoHashMap(u64, wal_mod.Transaction),
    last_checkpoint: u64,

    const Self = @This();

    pub fn init(heap: *pheap.PersistentHeap, wal: *wal_mod.WAL) RecoveryEngine {
        return RecoveryEngine{
            .heap = heap,
            .wal = wal,
            .phase = .none,
            .stats = RecoveryStats{
                .transactions_analyzed = 0,
                .transactions_committed = 0,
                .transactions_rolled_back = 0,
                .records_redone = 0,
                .records_undone = 0,
                .errors = 0,
                .start_time = 0,
                .end_time = 0,
            },
            .allocator = heap.allocator,
            .incomplete_transactions = std.AutoHashMap(u64, wal_mod.Transaction).init(heap.allocator),
            .committed_transactions = std.AutoHashMap(u64, wal_mod.Transaction).init(heap.allocator),
            .last_checkpoint = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.incomplete_transactions.iterator();
        while (iter.next()) |entry| {
            var tx = entry.value_ptr;
            tx.deinit();
        }
        self.incomplete_transactions.deinit();

        iter = self.committed_transactions.iterator();
        while (iter.next()) |entry| {
            var tx = entry.value_ptr;
            tx.deinit();
        }
        self.committed_transactions.deinit();
    }

    pub fn recover(self: *Self) !void {
        self.stats.start_time = std.time.timestamp();

        if (!self.needsRecovery()) {
            self.phase = .complete;
            self.stats.end_time = std.time.timestamp();
            return;
        }

        try self.runAnalysisPhase();

        try self.runRedoPhase();

        try self.runUndoPhase();

        self.phase = .complete;
        self.stats.end_time = std.time.timestamp();

        try self.finalizeRecovery();
    }

    fn needsRecovery(self: *Self) bool {
        if (self.heap.header.isDirty()) {
            return true;
        }

        const transactions = self.wal.getTransactions() catch return false;
        defer {
            for (transactions.items) |*tx| {
                tx.deinit();
            }
            transactions.deinit();
        }

        for (transactions.items) |tx| {
            if (tx.state == .active) {
                return true;
            }
        }

        return false;
    }

    fn runAnalysisPhase(self: *Self) !void {
        self.phase = .analysis;

        const transactions = try self.wal.getTransactions();
        defer {
            for (transactions.items) |*tx| {
                tx.deinit();
            }
            transactions.deinit();
        }

        for (transactions.items) |tx| {
            self.stats.transactions_analyzed += 1;

            switch (tx.state) {
                .committed => {
                    try self.committed_transactions.put(tx.id, tx);
                    self.stats.transactions_committed += 1;
                },
                .active, .prepared => {
                    try self.incomplete_transactions.put(tx.id, tx);
                },
                .rolled_back => {},
            }
        }
    }

    fn runRedoPhase(self: *Self) !void {
        self.phase = .redo;

        var iter = self.committed_transactions.iterator();
        while (iter.next()) |entry| {
            const tx = entry.value_ptr;
            try self.redoTransaction(tx);
        }
    }

    fn redoTransaction(self: *Self, tx: *const wal_mod.Transaction) !void {
        for (tx.records.items) |record| {
            switch (record.record_type) {
                .allocate, .write, .free_list_add, .free_list_remove, .heap_extend, .root_update => {
                    try self.redoRecord(&record);
                    self.stats.records_redone += 1;
                },
                else => {},
            }
        }
    }

    fn redoRecord(self: *Self, record: *const wal_mod.WALRecord) !void {
        switch (record.record_type) {
            .allocate => {
                const base_addr = self.heap.getBaseAddress();
                const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + record.offset));
                obj_header.setFreed(false);
                obj_header.checksum = obj_header.computeChecksum();
                try self.heap.flushRange(record.offset + @sizeOf(header.ObjectHeader));
            },
            .write => {
                const new_data = try self.wal.getUndoData(record);
                if (new_data.len > 0) {
                    try self.heap.write(record.offset, new_data);
                }
            },
            .heap_extend => {
                if (record.size > 0) {
                    try self.heap.expand(record.size);
                }
            },
            .root_update => {
                const base_addr = self.heap.getBaseAddress();
                const root_header: *header.HeapHeader = @ptrCast(@alignCast(base_addr));
                root_header.root_offset = record.offset;
                root_header.updateChecksum();
                try self.heap.flushRange(@sizeOf(header.HeapHeader));
            },
            .free_list_add, .free_list_remove => {
                try self.heap.flushRange(record.offset + record.size);
            },
            else => {},
        }
    }

    fn runUndoPhase(self: *Self) !void {
        self.phase = .undo;

        var iter = self.incomplete_transactions.iterator();
        while (iter.next()) |entry| {
            const tx = entry.value_ptr;
            try self.undoTransaction(tx);
            self.stats.transactions_rolled_back += 1;
        }
    }

    fn undoTransaction(self: *Self, tx: *wal_mod.Transaction) !void {
        var i: usize = tx.records.items.len;
        while (i > 0) {
            i -= 1;
            const record = tx.records.items[i];

            switch (record.record_type) {
                .allocate => {
                    try self.undoAllocate(&record);
                    self.stats.records_undone += 1;
                },
                .write => {
                    try self.undoWrite(&record);
                    self.stats.records_undone += 1;
                },
                .free => {
                    try self.undoFree(&record);
                    self.stats.records_undone += 1;
                },
                else => {},
            }
        }
    }

    fn undoAllocate(self: *Self, record: *const wal_mod.WALRecord) !void {
        const base_addr = self.heap.getBaseAddress();
        const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + record.offset));
        obj_header.setFreed(true);
        obj_header.checksum = obj_header.computeChecksum();
        try self.heap.flushRange(record.offset + @sizeOf(header.ObjectHeader));
    }

    fn undoWrite(self: *Self, record: *const wal_mod.WALRecord) !void {
        const old_data = try self.wal.getUndoData(record);
        if (old_data.len > 0) {
            try self.heap.write(record.offset, old_data);
        }
    }

    fn undoFree(self: *Self, record: *const wal_mod.WALRecord) !void {
        const base_addr = self.heap.getBaseAddress();
        const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + record.offset));
        obj_header.setFreed(false);
        obj_header.checksum = obj_header.computeChecksum();
        try self.heap.flushRange(record.offset + @sizeOf(header.ObjectHeader));
    }

    fn finalizeRecovery(self: *Self) !void {
        self.heap.header.setDirty(false);
        self.heap.header.updateChecksum();
        try self.heap.flushRange(@sizeOf(header.HeapHeader));

        try self.wal.checkpoint();
        try self.heap.sync();
    }

    pub fn getStats(self: *const Self) RecoveryStats {
        return self.stats;
    }

    pub fn getPhase(self: *const Self) RecoveryPhase {
        return self.phase;
    }

    pub fn verifyHeapConsistency(self: *Self) !bool {
        try self.heap.header.validate();

        const base_addr = self.heap.getBaseAddress();
        const alloc_metadata: *allocator_mod.AllocatorMetadata = @ptrCast(@alignCast(base_addr + header.HEADER_SIZE));
        try alloc_metadata.validate();

        return true;
    }

    pub fn repairHeap(self: *Self) !usize {
        var repairs: usize = 0;

        if (self.heap.header.checksum != self.heap.header.computeChecksum()) {
            self.heap.header.updateChecksum();
            repairs += 1;
        }

        const base_addr = self.heap.getBaseAddress();
        const alloc_metadata: *allocator_mod.AllocatorMetadata = @ptrCast(@alignCast(base_addr + header.HEADER_SIZE));

        if (alloc_metadata.checksum != alloc_metadata.computeChecksum()) {
            alloc_metadata.updateChecksum();
            repairs += 1;
        }

        return repairs;
    }
};

pub const CrashSimulator = struct {
    allocator: std.mem.Allocator,
    crash_points: std.ArrayList(usize),
    current_point: usize,

    pub fn init(allocator_ptr: std.mem.Allocator) CrashSimulator {
        return CrashSimulator{
            .allocator = allocator_ptr,
            .crash_points = std.ArrayList(usize).init(allocator_ptr),
            .current_point = 0,
        };
    }

    pub fn deinit(self: *CrashSimulator) void {
        self.crash_points.deinit();
    }

    pub fn addCrashPoint(self: *CrashSimulator, point: usize) !void {
        try self.crash_points.append(point);
    }

    pub fn shouldCrash(self: *CrashSimulator) bool {
        if (self.current_point < self.crash_points.items.len) {
            const point = self.crash_points.items[self.current_point];
            self.current_point += 1;
            return point == self.current_point;
        }
        return false;
    }

    pub fn reset(self: *CrashSimulator) void {
        self.current_point = 0;
    }
};

test "recovery engine initialization" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_heap_path = "/tmp/test_recovery.dat";
    const test_wal_path = "/tmp/test_recovery.wal";
    std.fs.cwd().deleteFile(test_heap_path) catch {};
    std.fs.cwd().deleteFile(test_wal_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, test_heap_path, 1024 * 1024, null);
    defer heap.deinit();

    var wal = try wal_mod.WAL.init(alloc, test_wal_path, null);
    defer wal.deinit();

    var recovery = RecoveryEngine.init(heap, wal);
    defer recovery.deinit();

    try recovery.recover();
    try testing.expect(recovery.phase == .complete);
}
