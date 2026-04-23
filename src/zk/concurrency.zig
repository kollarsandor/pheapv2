const std = @import("std");
const atomic = std.atomic;
const header = @import("header.zig");
const wal_mod = @import("wal.zig");

pub const LOCK_MAGIC: u32 = 0x4C4F434B;
pub const LOCK_VERSION: u32 = 1;

pub const PMutex = extern struct {
    magic: u32,
    version: u32,
    state: u32,
    owner: u64,
    waiters: u32,
    spin_count: u32,
    checksum: u32,
    reserved: [36]u8,

    const STATE_UNLOCKED: u32 = 0;
    const STATE_LOCKED: u32 = 1;
    const STATE_CONTENDED: u32 = 2;

    pub fn init() PMutex {
        return PMutex{
            .magic = LOCK_MAGIC,
            .version = LOCK_VERSION,
            .state = STATE_UNLOCKED,
            .owner = 0,
            .waiters = 0,
            .spin_count = 100,
            .checksum = 0,
            .reserved = [_]u8{0} ** 36,
        };
    }

    pub fn lock(self: *PMutex) !void {
        const tid = @as(u64, std.Thread.getCurrentId());

        if (self.owner == tid) {
            return error.Deadlock;
        }

        var spins: u32 = 0;
        while (spins < self.spin_count) : (spins += 1) {
            if (atomic.cmpxchgStrong(
                &self.state,
                STATE_UNLOCKED,
                STATE_LOCKED,
                .acquire,
                .monotonic,
            ) == null) {
                self.owner = tid;
                return;
            }
            std.Thread.spinLoopHint();
        }

        while (true) {
            const old_state = atomic.atomicLoad(u32, &self.state, .monotonic);
            if (old_state == STATE_UNLOCKED) {
                if (atomic.cmpxchgStrong(
                    &self.state,
                    STATE_UNLOCKED,
                    STATE_LOCKED,
                    .acquire,
                    .monotonic,
                ) == null) {
                    self.owner = tid;
                    return;
                }
            } else {
                _ = atomic.cmpxchgStrong(
                    &self.state,
                    old_state,
                    STATE_CONTENDED,
                    .release,
                    .monotonic,
                );
            }

            std.Thread.Futex.wait(&self.state, STATE_CONTENDED, null) catch {};
        }
    }

    pub fn tryLock(self: *PMutex) bool {
        const tid = @as(u64, std.Thread.getCurrentId());

        if (atomic.cmpxchgStrong(
            &self.state,
            STATE_UNLOCKED,
            STATE_LOCKED,
            .acquire,
            .monotonic,
        ) != null) {
            return false;
        }

        self.owner = tid;
        return true;
    }

    pub fn unlock(self: *PMutex) void {
        const tid = @as(u64, std.Thread.getCurrentId());

        if (self.owner != tid) {
            @panic("Mutex not owned by current thread");
        }

        self.owner = 0;

        const old_state = atomic.swap(&self.state, STATE_UNLOCKED, .release);

        if (old_state == STATE_CONTENDED) {
            std.Thread.Futex.wake(&self.state, 1);
        }
    }

    pub fn isLocked(self: *const PMutex) bool {
        return atomic.atomicLoad(u32, &self.state, .monotonic) != STATE_UNLOCKED;
    }

    pub fn getOwner(self: *const PMutex) u64 {
        return self.owner;
    }

    pub fn reset(self: *PMutex) void {
        self.state = STATE_UNLOCKED;
        self.owner = 0;
        self.waiters = 0;
    }
};

pub const PRWLock = extern struct {
    magic: u32,
    version: u32,
    readers: u32,
    writer: u64,
    write_waiters: u32,
    read_waiters: u32,
    state: u32,
    checksum: u32,
    reserved: [32]u8,

    const STATE_UNLOCKED: u32 = 0;
    const STATE_READ_LOCKED: u32 = 1;
    const STATE_WRITE_LOCKED: u32 = 2;
    const STATE_WRITE_WAITING: u32 = 3;

    pub fn init() PRWLock {
        return PRWLock{
            .magic = LOCK_MAGIC,
            .version = LOCK_VERSION,
            .readers = 0,
            .writer = 0,
            .write_waiters = 0,
            .read_waiters = 0,
            .state = STATE_UNLOCKED,
            .checksum = 0,
            .reserved = [_]u8{0} ** 32,
        };
    }

    pub fn lockRead(self: *PRWLock) !void {
        while (true) {
            const current_state = atomic.atomicLoad(u32, &self.state, .monotonic);

            switch (current_state) {
                STATE_UNLOCKED => {
                    if (atomic.cmpxchgStrong(
                        &self.state,
                        STATE_UNLOCKED,
                        STATE_READ_LOCKED,
                        .acquire,
                        .monotonic,
                    ) == null) {
                        _ = atomic.fetchAdd(&self.readers, 1, .monotonic);
                        return;
                    }
                },
                STATE_READ_LOCKED => {
                    if (self.write_waiters == 0) {
                        _ = atomic.fetchAdd(&self.readers, 1, .monotonic);
                        return;
                    }
                    _ = atomic.fetchAdd(&self.read_waiters, 1, .monotonic);
                    std.Thread.Futex.wait(&self.state, STATE_READ_LOCKED, null) catch {};
                    _ = atomic.fetchSub(&self.read_waiters, 1, .monotonic);
                },
                STATE_WRITE_LOCKED, STATE_WRITE_WAITING => {
                    _ = atomic.fetchAdd(&self.read_waiters, 1, .monotonic);
                    std.Thread.Futex.wait(&self.state, current_state, null) catch {};
                    _ = atomic.fetchSub(&self.read_waiters, 1, .monotonic);
                },
                else => {},
            }
        }
    }

    pub fn tryLockRead(self: *PRWLock) bool {
        const current_state = atomic.atomicLoad(u32, &self.state, .monotonic);

        if (current_state == STATE_UNLOCKED or (current_state == STATE_READ_LOCKED and self.write_waiters == 0)) {
            if (atomic.cmpxchgStrong(
                &self.state,
                current_state,
                STATE_READ_LOCKED,
                .acquire,
                .monotonic,
            ) == null) {
                _ = atomic.fetchAdd(&self.readers, 1, .monotonic);
                return true;
            }
        }

        return false;
    }

    pub fn unlockRead(self: *PRWLock) void {
        const old_readers = atomic.fetchSub(&self.readers, 1, .release);

        if (old_readers == 1) {
            atomic.store(&self.state, STATE_UNLOCKED, .release);

            if (atomic.atomicLoad(u32, &self.write_waiters, .monotonic) > 0) {
                std.Thread.Futex.wake(&self.state, 1);
            } else if (atomic.atomicLoad(u32, &self.read_waiters, .monotonic) > 0) {
                std.Thread.Futex.wake(&self.state, std.math.maxInt(u32));
            }
        }
    }

    pub fn lockWrite(self: *PRWLock) !void {
        const tid = @as(u64, std.Thread.getCurrentId());

        if (self.writer == tid) {
            return error.Deadlock;
        }

        _ = atomic.fetchAdd(&self.write_waiters, 1, .monotonic);

        while (true) {
            const current_state = atomic.atomicLoad(u32, &self.state, .monotonic);

            if (current_state == STATE_UNLOCKED) {
                if (atomic.cmpxchgStrong(
                    &self.state,
                    STATE_UNLOCKED,
                    STATE_WRITE_LOCKED,
                    .acquire,
                    .monotonic,
                ) == null) {
                    _ = atomic.fetchSub(&self.write_waiters, 1, .monotonic);
                    self.writer = tid;
                    return;
                }
            }

            atomic.store(&self.state, STATE_WRITE_WAITING, .monotonic);
            std.Thread.Futex.wait(&self.state, STATE_WRITE_WAITING, null) catch {};
        }
    }

    pub fn tryLockWrite(self: *PRWLock) bool {
        const tid = @as(u64, std.Thread.getCurrentId());

        if (self.writer == tid) {
            return false;
        }

        if (atomic.cmpxchgStrong(
            &self.state,
            STATE_UNLOCKED,
            STATE_WRITE_LOCKED,
            .acquire,
            .monotonic,
        ) == null) {
            self.writer = tid;
            return true;
        }

        return false;
    }

    pub fn unlockWrite(self: *PRWLock) void {
        const tid = @as(u64, std.Thread.getCurrentId());

        if (self.writer != tid) {
            @panic("RWLock not owned by current thread");
        }

        self.writer = 0;
        atomic.store(&self.state, STATE_UNLOCKED, .release);

        if (atomic.atomicLoad(u32, &self.write_waiters, .monotonic) > 0) {
            std.Thread.Futex.wake(&self.state, 1);
        } else if (atomic.atomicLoad(u32, &self.read_waiters, .monotonic) > 0) {
            std.Thread.Futex.wake(&self.state, std.math.maxInt(u32));
        }
    }

    pub fn isWriteLocked(self: *const PRWLock) bool {
        return atomic.atomicLoad(u32, &self.state, .monotonic) == STATE_WRITE_LOCKED;
    }

    pub fn getReaderCount(self: *const PRWLock) u32 {
        return atomic.atomicLoad(u32, &self.readers, .monotonic);
    }

    pub fn reset(self: *PRWLock) void {
        self.readers = 0;
        self.writer = 0;
        self.write_waiters = 0;
        self.read_waiters = 0;
        self.state = STATE_UNLOCKED;
    }
};

pub const PCondVar = extern struct {
    magic: u32,
    version: u32,
    waiters: u32,
    signals: u32,
    generation: u64,
    checksum: u32,
    reserved: [40]u8,

    pub fn init() PCondVar {
        return PCondVar{
            .magic = LOCK_MAGIC,
            .version = LOCK_VERSION,
            .waiters = 0,
            .signals = 0,
            .generation = 0,
            .checksum = 0,
            .reserved = [_]u8{0} ** 40,
        };
    }

    pub fn wait(self: *PCondVar, mutex: *PMutex) !void {
        _ = atomic.fetchAdd(&self.waiters, 1, .monotonic);
        const my_generation = atomic.atomicLoad(u64, &self.generation, .monotonic);

        mutex.unlock();

        while (atomic.atomicLoad(u64, &self.generation, .monotonic) == my_generation) {
            std.Thread.Futex.wait(
                @ptrCast(&self.generation),
                @truncate(my_generation),
                null,
            ) catch {};
        }

        _ = atomic.fetchSub(&self.waiters, 1, .monotonic);

        try mutex.lock();
    }

    pub fn signal(self: *PCondVar) void {
        _ = atomic.fetchAdd(&self.generation, 1, .release);
        std.Thread.Futex.wake(@ptrCast(&self.generation), 1);
    }

    pub fn broadcast(self: *PCondVar) void {
        _ = atomic.fetchAdd(&self.generation, 1, .release);
        std.Thread.Futex.wake(@ptrCast(&self.generation), std.math.maxInt(u32));
    }

    pub fn reset(self: *PCondVar) void {
        self.waiters = 0;
        self.signals = 0;
    }
};

pub const Semaphore = struct {
    value: atomic.Value(u32),
    max: u32,

    pub fn init(initial: u32, max_val: u32) Semaphore {
        return Semaphore{
            .value = atomic.Value(u32).init(initial),
            .max = max_val,
        };
    }

    pub fn wait(self: *Semaphore) void {
        while (true) {
            const current = self.value.load(.monotonic);
            if (current == 0) {
                std.Thread.Futex.wait(&self.value, 0, null) catch {};
                continue;
            }
            if (self.value.cmpxchgWeak(
                current,
                current - 1,
                .acquire,
                .monotonic,
            ) == null) {
                return;
            }
        }
    }

    pub fn tryWait(self: *Semaphore) bool {
        while (true) {
            const current = self.value.load(.monotonic);
            if (current == 0) return false;
            if (self.value.cmpxchgWeak(
                current,
                current - 1,
                .acquire,
                .monotonic,
            ) == null) {
                return true;
            }
        }
    }

    pub fn post(self: *Semaphore) !void {
        while (true) {
            const current = self.value.load(.monotonic);
            if (current >= self.max) {
                return error.SemaphoreOverflow;
            }
            if (self.value.cmpxchgWeak(
                current,
                current + 1,
                .release,
                .monotonic,
            ) == null) {
                std.Thread.Futex.wake(&self.value, 1);
                return;
            }
        }
    }

    pub fn getValue(self: *const Semaphore) u32 {
        return self.value.load(.monotonic);
    }
};

pub const SpinLock = struct {
    locked: atomic.Value(bool),

    pub fn init() SpinLock {
        return SpinLock{
            .locked = atomic.Value(bool).init(false),
        };
    }

    pub fn lock(self: *SpinLock) void {
        while (self.locked.cmpxchgWeak(
            false,
            true,
            .acquire,
            .monotonic,
        ) != null) {
            std.Thread.spinLoopHint();
        }
    }

    pub fn tryLock(self: *SpinLock) bool {
        return self.locked.cmpxchgStrong(
            false,
            true,
            .acquire,
            .monotonic,
        ) == null;
    }

    pub fn unlock(self: *SpinLock) void {
        self.locked.store(false, .release);
    }

    pub fn isLocked(self: *const SpinLock) bool {
        return self.locked.load(.monotonic);
    }
};

pub const LockGuard = struct {
    mutex: *PMutex,

    pub fn init(mutex: *PMutex) !LockGuard {
        try mutex.lock();
        return LockGuard{ .mutex = mutex };
    }

    pub fn deinit(self: *LockGuard) void {
        self.mutex.unlock();
    }
};

pub const ReadGuard = struct {
    lock: *PRWLock,

    pub fn init(lock: *PRWLock) !ReadGuard {
        try lock.lockRead();
        return ReadGuard{ .lock = lock };
    }

    pub fn deinit(self: *ReadGuard) void {
        self.lock.unlockRead();
    }
};

pub const WriteGuard = struct {
    lock: *PRWLock,

    pub fn init(lock: *PRWLock) !WriteGuard {
        try lock.lockWrite();
        return WriteGuard{ .lock = lock };
    }

    pub fn deinit(self: *WriteGuard) void {
        self.lock.unlockWrite();
    }
};

test "pmutex basic operations" {
    const testing = std.testing;
    var mutex = PMutex.init();

    try mutex.lock();
    try testing.expect(mutex.isLocked());
    try testing.expectEqual(@as(u64, std.Thread.getCurrentId()), mutex.getOwner());

    mutex.unlock();
    try testing.expect(!mutex.isLocked());
}

test "pmutex try lock" {
    const testing = std.testing;
    var mutex = PMutex.init();

    try testing.expect(mutex.tryLock());
    try testing.expect(!mutex.tryLock());

    mutex.unlock();
    try testing.expect(mutex.tryLock());
    mutex.unlock();
}

test "prwlock read operations" {
    const testing = std.testing;
    var rwlock = PRWLock.init();

    try rwlock.lockRead();
    try testing.expectEqual(@as(u32, 1), rwlock.getReaderCount());

    try rwlock.lockRead();
    try testing.expectEqual(@as(u32, 2), rwlock.getReaderCount());

    rwlock.unlockRead();
    try testing.expectEqual(@as(u32, 1), rwlock.getReaderCount());

    rwlock.unlockRead();
    try testing.expectEqual(@as(u32, 0), rwlock.getReaderCount());
}

test "prwlock write operations" {
    const testing = std.testing;
    var rwlock = PRWLock.init();

    try rwlock.lockWrite();
    try testing.expect(rwlock.isWriteLocked());

    rwlock.unlockWrite();
    try testing.expect(!rwlock.isWriteLocked());
}
