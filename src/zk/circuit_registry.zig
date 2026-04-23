const std = @import("std");
const pheap = @import("pheap.zig");
const schema = @import("schema.zig");

pub const CircuitRegistry = struct {
    allocator: std.mem.Allocator,
    heap: *pheap.PersistentHeap,
    circuits: std.StringHashMap(CircuitEntry),

    const CircuitEntry = struct {
        r1cs_offset: u64,
        proving_key_offset: u64,
        verification_key_offset: u64,
        size: u64,
    };

    pub fn init(allocator: std.mem.Allocator, heap: *pheap.PersistentHeap) !CircuitRegistry {
        return CircuitRegistry{
            .allocator = allocator,
            .heap = heap,
            .circuits = std.StringHashMap(CircuitEntry).init(allocator),
        };
    }

    pub fn deinit(self: *CircuitRegistry) void {
        var iter = self.circuits.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.circuits.deinit();
    }

    pub fn registerFromSchema(self: *CircuitRegistry, comptime T: type, name: []const u8) !void {
        const name_dup = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_dup);
        const schema_id = schema.getSchemaId(T);
        const r1cs_data = try self.generateR1CSFromSchema(T);
        errdefer self.allocator.free(r1cs_data);
        const pk = try self.generateProvingKey(T);
        errdefer self.allocator.free(pk);
        const vk = try self.generateVerificationKey(T);
        errdefer self.allocator.free(vk);
        const total_size = r1cs_data.len + pk.len + vk.len;
        var tx = try self.heap.beginTransaction();
        defer self.heap.endTransaction(&tx) catch {};
        const offset = try self.heap.allocate(&tx, total_size, 64);
        const base = self.heap.getBaseAddress();
        @memcpy(base[offset..][0..r1cs_data.len], r1cs_data);
        @memcpy(base[offset + r1cs_data.len..][0..pk.len], pk);
        @memcpy(base[offset + r1cs_data.len + pk.len..][0..vk.len], vk);
        try self.circuits.put(name_dup, CircuitEntry{
            .r1cs_offset = offset,
            .proving_key_offset = offset + r1cs_data.len,
            .verification_key_offset = offset + r1cs_data.len + pk.len,
            .size = total_size,
        });
    }

    fn generateR1CSFromSchema(self: *CircuitRegistry, comptime T: type) ![]u8 {
        const size = @sizeOf(T);
        const data = try self.allocator.alloc(u8, size);
        @memcpy(data, std.mem.asBytes(&@as(T, undefined)));
        return data;
    }

    fn generateProvingKey(self: *CircuitRegistry, comptime T: type) ![]u8 {
        const size = 8192;
        const data = try self.allocator.alloc(u8, size);
        @memset(data, 0);
        return data;
    }

    fn generateVerificationKey(self: *CircuitRegistry, comptime T: type) ![]u8 {
        const size = 4096;
        const data = try self.allocator.alloc(u8, size);
        @memset(data, 0);
        return data;
    }

    pub fn getCircuit(self: *const CircuitRegistry, name: []const u8) ?CircuitEntry {
        return self.circuits.get(name);
    }
};
