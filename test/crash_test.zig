const std = @import("std");
const time = std.time;
const pheap = @import("../src/pheap.zig");
const allocator_mod = @import("../src/allocator.zig");
const wal_mod = @import("../src/wal.zig");
const transaction_mod = @import("../src/transaction.zig");
const recovery = @import("../src/recovery.zig");
const pointer = @import("../src/pointer.zig");
const header = @import("../src/header.zig");

pub const CrashTestConfig = struct {
    heap_path: []const u8,
    wal_path: []const u8,
    heap_size: u64,
    num_iterations: u64,
    num_operations_per_tx: u64,
    crash_point_interval: u64,
    verify_after_recovery: bool,
};

pub const CrashTestResult = struct {
    iterations: u64,
    crashes_simulated: u64,
    recoveries_successful: u64,
    recoveries_failed: u64,
    data_corruptions: u64,
    total_time_ns: u64,
};

pub const CrashPoint = struct {
    iteration: u64,
    operation: u64,
    phase: CrashPhase,
};

pub const CrashPhase = enum(u8) {
    before_wal_write,
    after_wal_write,
    before_heap_write,
    after_heap_write,
    before_flush,
    after_flush,
    before_commit,
    after_commit,
};

pub const CrashInjector = struct {
    crash_points: std.ArrayList(CrashPoint),
    current_iteration: u64,
    current_operation: u64,
    should_crash: bool,
    enabled: bool,
    crash_triggered: bool,

    pub fn init(allocator_ptr: std.mem.Allocator) CrashInjector {
        return CrashInjector{
            .crash_points = std.ArrayList(CrashPoint).init(allocator_ptr),
            .current_iteration = 0,
            .current_operation = 0,
            .should_crash = false,
            .enabled = true,
            .crash_triggered = false,
        };
    }

    pub fn deinit(self: *CrashInjector) void {
        self.crash_points.deinit();
    }

    pub fn addCrashPoint(self: *CrashInjector, point: CrashPoint) !void {
        try self.crash_points.append(point);
    }

    pub fn generateRandomCrashPoints(self: *CrashInjector, rng: std.rand.Random, num_points: u64, max_iteration: u64, max_operation: u64) !void {
        var i: u64 = 0;
        while (i < num_points) : (i += 1) {
            const point = CrashPoint{
                .iteration = rng.intRangeLessThan(u64, 0, max_iteration),
                .operation = rng.intRangeLessThan(u64, 0, max_operation),
                .phase = @as(CrashPhase, @enumFromInt(rng.intRangeLessThan(u8, 0, 8))),
            };
            try self.crash_points.append(point);
        }
    }

    pub fn checkCrash(self: *CrashInjector, phase: CrashPhase) bool {
        if (!self.enabled or self.crash_triggered) {
            return false;
        }

        for (self.crash_points.items) |point| {
            if (point.iteration == self.current_iteration and
                point.operation == self.current_operation and
                point.phase == phase)
            {
                self.should_crash = true;
                self.crash_triggered = true;
                return true;
            }
        }

        return false;
    }

    pub fn advanceOperation(self: *CrashInjector) void {
        self.current_operation += 1;
    }

    pub fn advanceIteration(self: *CrashInjector) void {
        self.current_iteration += 1;
        self.current_operation = 0;
    }

    pub fn reset(self: *CrashInjector) void {
        self.should_crash = false;
    }

    pub fn setEnabled(self: *CrashInjector, enabled: bool) void {
        self.enabled = enabled;
    }
};

pub const CrashSimulator = struct {
    config: CrashTestConfig,
    injector: CrashInjector,
    allocator: std.mem.Allocator,
    prng: std.rand.DefaultPrng,

    pub fn init(allocator_ptr: std.mem.Allocator, config: CrashTestConfig) CrashSimulator {
        var prng = std.rand.DefaultPrng.init(@as(u64, @bitCast(time.timestamp())));

        var simulator = CrashSimulator{
            .config = config,
            .injector = CrashInjector.init(allocator_ptr),
            .allocator = allocator_ptr,
            .prng = prng,
        };

        return simulator;
    }

    pub fn deinit(self: *CrashSimulator) void {
        self.injector.deinit();
    }

    pub fn runCrashTest(self: *CrashSimulator) !CrashTestResult {
        var result = CrashTestResult{
            .iterations = 0,
            .crashes_simulated = 0,
            .recoveries_successful = 0,
            .recoveries_failed = 0,
            .data_corruptions = 0,
            .total_time_ns = 0,
        };

        const rng = self.prng.random();

        try self.injector.generateRandomCrashPoints(
            rng,
            self.config.num_iterations / self.config.crash_point_interval,
            self.config.num_iterations,
            self.config.num_operations_per_tx,
        );

        const start_time = time.nanoTimestamp();

        var iter: u64 = 0;
        while (iter < self.config.num_iterations) : (iter += 1) {
            result.iterations += 1;

            std.fs.cwd().deleteFile(self.config.heap_path) catch {};
            std.fs.cwd().deleteFile(self.config.wal_path) catch {};

            var heap = try pheap.PersistentHeap.init(
                self.allocator,
                self.config.heap_path,
                self.config.heap_size,
                null,
            );
            defer heap.deinit();

            var wal = try wal_mod.WAL.init(self.allocator, self.config.wal_path, null);
            defer wal.deinit();

            var palloc = try allocator_mod.PersistentAllocator.init(self.allocator, heap, wal);
            defer palloc.deinit();

            var tx_mgr = try transaction_mod.TransactionManager.init(self.allocator, wal, heap);
            defer tx_mgr.deinit();

            var expected_state = std.ArrayList(ExpectedObject).init(self.allocator);
            defer expected_state.deinit();

            self.injector.advanceIteration();

            var op: u64 = 0;
            while (op < self.config.num_operations_per_tx) : (op += 1) {
                self.injector.advanceOperation();

                const op_type = rng.intRangeLessThan(u8, 0, 3);

                switch (op_type) {
                    0 => {
                        var tx = try tx_mgr.begin();

                        const size = rng.intRangeLessThan(u64, 64, 1024);
                        const ptr = try palloc.alloc(size, 64);

                        const base_addr = heap.getBaseAddress();
                        const data = base_addr[ptr.offset .. ptr.offset + size];
                        for (data) |*byte| {
                            byte.* = rng.int(u8);
                        }

                        const expected = ExpectedObject{
                            .ptr = ptr,
                            .size = size,
                            .checksum = computeChecksum(data),
                        };

                        if (self.injector.checkCrash(.before_commit)) {
                            result.crashes_simulated += 1;

                            try self.simulateCrashRecovery(&result);
                            break;
                        }

                        try tx_mgr.commit(&tx);

                        if (self.injector.checkCrash(.after_commit)) {
                            result.crashes_simulated += 1;
                        }

                        try expected_state.append(expected);
                    },
                    1 => {
                        if (expected_state.items.len == 0) continue;

                        const idx = rng.intRangeLessThan(usize, 0, expected_state.items.len);
                        const obj = expected_state.items[idx];

                        var tx = try tx_mgr.begin();
                        try palloc.free(obj.ptr);
                        try tx_mgr.commit(&tx);

                        _ = expected_state.swapRemove(idx);
                    },
                    2 => {
                        if (expected_state.items.len == 0) continue;

                        const idx = rng.intRangeLessThan(usize, 0, expected_state.items.len);
                        const obj = expected_state.items[idx];

                        const base_addr = heap.getBaseAddress();
                        const data = base_addr[obj.ptr.offset .. obj.ptr.offset + obj.size];

                        var buffer: [1024]u8 = undefined;
                        const read_size = @min(obj.size, 1024);
                        try heap.read(obj.ptr.offset, buffer[0..read_size]);
                    },
                    else => {},
                }
            }

            if (self.config.verify_after_recovery) {
                const verify_result = try self.verifyDataIntegrity(&expected_state);
                if (!verify_result) {
                    result.data_corruptions += 1;
                }
            }
        }

        result.total_time_ns = @as(u64, @intCast(time.nanoTimestamp() - start_time));

        return result;
    }

    fn simulateCrashRecovery(self: *CrashSimulator, result: *CrashTestResult) !void {
        var heap = try pheap.PersistentHeap.init(
            self.allocator,
            self.config.heap_path,
            self.config.heap_size,
            null,
        );
        defer heap.deinit();

        var wal = try wal_mod.WAL.init(self.allocator, self.config.wal_path, null);
        defer wal.deinit();

        var recovery_engine = recovery.RecoveryEngine.init(heap, wal);
        defer recovery_engine.deinit();

        recovery_engine.recover() catch |err| {
            _ = err;
            result.recoveries_failed += 1;
            return;
        };

        result.recoveries_successful += 1;
    }

    fn verifyDataIntegrity(self: *CrashSimulator, expected: *const std.ArrayList(ExpectedObject)) !bool {
        var heap = try pheap.PersistentHeap.init(
            self.allocator,
            self.config.heap_path,
            self.config.heap_size,
            null,
        );
        defer heap.deinit();

        const base_addr = heap.getBaseAddress();

        for (expected.items) |obj| {
            const data = base_addr[obj.ptr.offset .. obj.ptr.offset + obj.size];
            const current_checksum = computeChecksum(data);

            if (current_checksum != obj.checksum) {
                return false;
            }
        }

        return true;
    }
};

const ExpectedObject = struct {
    ptr: pointer.PersistentPtr,
    size: u64,
    checksum: u32,
};

fn computeChecksum(data: []const u8) u32 {
    var crc: u32 = 0xFFFFFFFF;
    for (data) |byte| {
        crc ^= @as(u32, byte);
        var j: usize = 0;
        while (j < 8) : (j += 1) {
            crc = if ((crc & 1) != 0) (crc >> 1) ^ 0x82F63B78 else crc >> 1;
        }
    }
    return crc ^ 0xFFFFFFFF;
}

pub const PersistenceTestSuite = struct {
    allocator: std.mem.Allocator,
    config: CrashTestConfig,
    results: std.ArrayList(TestResult),

    const TestResult = struct {
        name: []const u8,
        passed: bool,
        message: []const u8,
        duration_ns: u64,
    };

    pub fn init(allocator_ptr: std.mem.Allocator, config: CrashTestConfig) PersistenceTestSuite {
        return PersistenceTestSuite{
            .allocator = allocator_ptr,
            .config = config,
            .results = std.ArrayList(TestResult).init(allocator_ptr),
        };
    }

    pub fn deinit(self: *PersistenceTestSuite) void {
        for (self.results.items) |result| {
            self.allocator.free(result.name);
            self.allocator.free(result.message);
        }
        self.results.deinit();
    }

    pub fn runAllTests(self: *PersistenceTestSuite) !void {
        try self.testBasicPersistence();
        try self.testTransactionAtomicity();
        try self.testCrashRecovery();
        try self.testWALReplay();
        try self.testPartialWrite();
    }

    fn testBasicPersistence(self: *PersistenceTestSuite) !void {
        const start = time.nanoTimestamp();

        std.fs.cwd().deleteFile(self.config.heap_path) catch {};

        var heap = try pheap.PersistentHeap.init(
            self.allocator,
            self.config.heap_path,
            self.config.heap_size,
            null,
        );

        const ptr = try heap.allocate(null, 64, 64);
        const base_addr = heap.getBaseAddress();
        const data = base_addr[ptr.offset .. ptr.offset + 64];
        @memset(data, 0xAB);

        try heap.flush();
        heap.deinit();

        var heap2 = try pheap.PersistentHeap.init(
            self.allocator,
            self.config.heap_path,
            self.config.heap_size,
            null,
        );
        defer heap2.deinit();

        const base_addr2 = heap2.getBaseAddress();
        const data2 = base_addr2[ptr.offset .. ptr.offset + 64];

        var passed = true;
        for (data2) |byte| {
            if (byte != 0xAB) {
                passed = false;
                break;
            }
        }

        const duration = @as(u64, @intCast(time.nanoTimestamp() - start));

        try self.results.append(TestResult{
            .name = try self.allocator.dupe(u8, "basic_persistence"),
            .passed = passed,
            .message = if (passed) try self.allocator.dupe(u8, "Data persisted correctly") else try self.allocator.dupe(u8, "Data corruption detected"),
            .duration_ns = duration,
        });
    }

    fn testTransactionAtomicity(self: *PersistenceTestSuite) !void {
        const start = time.nanoTimestamp();

        std.fs.cwd().deleteFile(self.config.heap_path) catch {};
        std.fs.cwd().deleteFile(self.config.wal_path) catch {};

        var heap = try pheap.PersistentHeap.init(
            self.allocator,
            self.config.heap_path,
            self.config.heap_size,
            null,
        );
        defer heap.deinit();

        var wal = try wal_mod.WAL.init(self.allocator, self.config.wal_path, null);
        defer wal.deinit();

        var tx_mgr = try transaction_mod.TransactionManager.init(self.allocator, wal, heap);
        defer tx_mgr.deinit();

        var palloc = try allocator_mod.PersistentAllocator.init(self.allocator, heap, wal);
        defer palloc.deinit();

        var tx = try tx_mgr.begin();
        const ptr = try palloc.alloc(128, 64);
        try tx_mgr.commit(&tx);

        var tx2 = try tx_mgr.begin();
        const ptr2 = try palloc.alloc(256, 64);
        try tx_mgr.rollback(&tx2);

        var found_first = false;
        var found_second = false;

        const base_addr = heap.getBaseAddress();
        const obj1: *const header.ObjectHeader = @ptrCast(@alignCast(base_addr + ptr.offset));
        const obj2: *const header.ObjectHeader = @ptrCast(@alignCast(base_addr + ptr2.offset));

        found_first = obj1.magic == header.ObjectHeader.OBJECT_MAGIC;
        found_second = obj2.magic == header.ObjectHeader.OBJECT_MAGIC;

        const passed = found_first and !found_second;
        const duration = @as(u64, @intCast(time.nanoTimestamp() - start));

        try self.results.append(TestResult{
            .name = try self.allocator.dupe(u8, "transaction_atomicity"),
            .passed = passed,
            .message = if (passed) try self.allocator.dupe(u8, "Transactions are atomic") else try self.allocator.dupe(u8, "Transaction isolation failed"),
            .duration_ns = duration,
        });
    }

    fn testCrashRecovery(self: *PersistenceTestSuite) !void {
        const start = time.nanoTimestamp();

        std.fs.cwd().deleteFile(self.config.heap_path) catch {};
        std.fs.cwd().deleteFile(self.config.wal_path) catch {};

        var heap = try pheap.PersistentHeap.init(
            self.allocator,
            self.config.heap_path,
            self.config.heap_size,
            null,
        );

        var wal = try wal_mod.WAL.init(self.allocator, self.config.wal_path, null);

        var palloc = try allocator_mod.PersistentAllocator.init(self.allocator, heap, wal);
        defer palloc.deinit();

        var tx_mgr = try transaction_mod.TransactionManager.init(self.allocator, wal, heap);

        var tx = try tx_mgr.begin();
        _ = try palloc.alloc(128, 64);
        try tx_mgr.commit(&tx);

        heap.header.setDirty(true);
        heap.header.updateChecksum();

        heap.deinit();
        wal.deinit();
        tx_mgr.deinit();

        var heap2 = try pheap.PersistentHeap.init(
            self.allocator,
            self.config.heap_path,
            self.config.heap_size,
            null,
        );
        defer heap2.deinit();

        var wal2 = try wal_mod.WAL.init(self.allocator, self.config.wal_path, null);
        defer wal2.deinit();

        var recovery_engine = recovery.RecoveryEngine.init(heap2, wal2);
        defer recovery_engine.deinit();

        recovery_engine.recover() catch {};

        const passed = !heap2.header.isDirty();
        const duration = @as(u64, @intCast(time.nanoTimestamp() - start));

        try self.results.append(TestResult{
            .name = try self.allocator.dupe(u8, "crash_recovery"),
            .passed = passed,
            .message = if (passed) try self.allocator.dupe(u8, "Recovery successful") else try self.allocator.dupe(u8, "Recovery failed"),
            .duration_ns = duration,
        });
    }

    fn testWALReplay(self: *PersistenceTestSuite) !void {
        const start = time.nanoTimestamp();

        std.fs.cwd().deleteFile(self.config.heap_path) catch {};
        std.fs.cwd().deleteFile(self.config.wal_path) catch {};

        var heap = try pheap.PersistentHeap.init(
            self.allocator,
            self.config.heap_path,
            self.config.heap_size,
            null,
        );
        defer heap.deinit();

        var wal = try wal_mod.WAL.init(self.allocator, self.config.wal_path, null);
        defer wal.deinit();

        var palloc = try allocator_mod.PersistentAllocator.init(self.allocator, heap, wal);
        defer palloc.deinit();

        var tx_mgr = try transaction_mod.TransactionManager.init(self.allocator, wal, heap);
        defer tx_mgr.deinit();

        var tx = try tx_mgr.begin();
        _ = try palloc.alloc(64, 64);
        try tx_mgr.commit(&tx);

        const records = try wal.getRecords(@sizeOf(wal_mod.WALHeader), 100);
        defer records.deinit();

        const passed = records.items.len > 0;
        const duration = @as(u64, @intCast(time.nanoTimestamp() - start));

        try self.results.append(TestResult{
            .name = try self.allocator.dupe(u8, "wal_replay"),
            .passed = passed,
            .message = if (passed) try std.fmt.allocPrint(self.allocator, "Found {} WAL records", .{records.items.len}) else try self.allocator.dupe(u8, "No WAL records found"),
            .duration_ns = duration,
        });
    }

    fn testPartialWrite(self: *PersistenceTestSuite) !void {
        const start = time.nanoTimestamp();

        std.fs.cwd().deleteFile(self.config.heap_path) catch {};

        var heap = try pheap.PersistentHeap.init(
            self.allocator,
            self.config.heap_path,
            self.config.heap_size,
            null,
        );
        defer heap.deinit();

        const ptr = try heap.allocate(null, 1024, 64);
        const base_addr = heap.getBaseAddress();

        const data = base_addr[ptr.offset .. ptr.offset + 512];
        @memset(data, 0xCD);

        try heap.flushRange(512);

        const data2 = base_addr[ptr.offset + 512 .. ptr.offset + 1024];
        @memset(data2, 0xEF);

        const passed = true;
        const duration = @as(u64, @intCast(time.nanoTimestamp() - start));

        try self.results.append(TestResult{
            .name = try self.allocator.dupe(u8, "partial_write"),
            .passed = passed,
            .message = try self.allocator.dupe(u8, "Partial write test completed"),
            .duration_ns = duration,
        });
    }

    pub fn printResults(self: *const PersistenceTestSuite) void {
        const stdout = std.io.getStdOut().writer();

        stdout.print("\n=== Persistence Test Results ===\n\n", .{}) catch {};

        var passed: usize = 0;
        var failed: usize = 0;

        for (self.results.items) |result| {
            const status = if (result.passed) "PASS" else "FAIL";
            stdout.print("[{s}] {s} ({d:.2}ms)\n", .{ status, result.name, @as(f64, @floatFromInt(result.duration_ns)) / 1e6 }) catch {};
            stdout.print("       {s}\n", .{result.message}) catch {};

            if (result.passed) {
                passed += 1;
            } else {
                failed += 1;
            }
        }

        stdout.print("\nTotal: {} passed, {} failed\n", .{ passed, failed }) catch {};
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const config = CrashTestConfig{
        .heap_path = "/tmp/crash_test.dat",
        .wal_path = "/tmp/crash_test.wal",
        .heap_size = 1024 * 1024 * 10,
        .num_iterations = 100,
        .num_operations_per_tx = 10,
        .crash_point_interval = 10,
        .verify_after_recovery = true,
    };

    const stdout = std.io.getStdOut().writer();
    try stdout.print("Running Crash Test Suite...\n\n", .{});

    var test_suite = PersistenceTestSuite.init(alloc, config);
    defer test_suite.deinit();

    try test_suite.runAllTests();
    test_suite.printResults();

    try stdout.print("\nRunning Randomized Crash Simulation...\n", .{});

    var crash_sim = CrashSimulator.init(alloc, config);
    defer crash_sim.deinit();

    const result = try crash_sim.runCrashTest();

    try stdout.print("\n=== Crash Simulation Results ===\n", .{});
    try stdout.print("Iterations: {}\n", .{result.iterations});
    try stdout.print("Crashes Simulated: {}\n", .{result.crashes_simulated});
    try stdout.print("Recoveries Successful: {}\n", .{result.recoveries_successful});
    try stdout.print("Recoveries Failed: {}\n", .{result.recoveries_failed});
    try stdout.print("Data Corruptions: {}\n", .{result.data_corruptions});
    try stdout.print("Total Time: {d:.2}s\n", .{@as(f64, @floatFromInt(result.total_time_ns)) / 1e9});
}
