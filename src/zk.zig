const std = @import("std");
const pheap = @import("pheap.zig");
const pointer = @import("pointer.zig");
const transaction = @import("transaction.zig");
const allocator_mod = @import("allocator.zig");
const security = @import("security.zig");
const schema = @import("schema.zig");
const wal_mod = @import("wal.zig");
const gpu = @import("gpu.zig");

pub const ZKBackendType = enum(u8) {
    plonky3,
    halo2,
    groth16,
    nova,
};

pub const ZKConfig = extern struct {
    backend: ZKBackendType,
    enable_recursion: bool,
    gpu_acceleration: bool,
    post_quantum: bool,
    circuit_cache_size: u64,
    reserved: [48]u8,
};

pub const Proof = extern struct {
    data: [*]u8,
    data_len: u64,
    public_inputs: [*]u8,
    public_inputs_len: u64,
    backend: ZKBackendType,
    proof_id: u128,
    checksum: u32,
};

pub const PrivateObjectHeader = extern struct {
    magic: u32,
    schema_id: u64,
    commitment: [32]u8,
    encryption_nonce: [12]u8,
    tag: u32,
    checksum: u32,
};

pub const ZKLayer = struct {
    allocator: std.mem.Allocator,
    config: ZKConfig,
    heap: *pheap.PersistentHeap,
    wal: *wal_mod.WAL,
    circuit_registry: CircuitRegistry,
    proof_engine: ProofEngine,
    private_objects: std.AutoHashMap(u128, pointer.PersistentPtr),

    pub fn init(allocator: std.mem.Allocator, heap: *pheap.PersistentHeap, wal: *wal_mod.WAL, config: ZKConfig) !*ZKLayer {
        const self = try allocator.create(ZKLayer);
        errdefer allocator.destroy(self);
        self.* = ZKLayer{
            .allocator = allocator,
            .config = config,
            .heap = heap,
            .wal = wal,
            .circuit_registry = undefined,
            .proof_engine = undefined,
            .private_objects = std.AutoHashMap(u128, pointer.PersistentPtr).init(allocator),
        };
        errdefer self.private_objects.deinit();
        self.circuit_registry = try CircuitRegistry.init(allocator, heap);
        errdefer self.circuit_registry.deinit();
        self.proof_engine = try ProofEngine.init(allocator, config, heap);
        return self;
    }

    pub fn deinit(self: *ZKLayer) void {
        self.proof_engine.deinit();
        self.circuit_registry.deinit();
        self.private_objects.deinit();
        self.allocator.destroy(self);
    }

    pub fn generateProof(self: *ZKLayer, circuit_name: []const u8, witness_data: []const u8, tx: *transaction.Transaction) !Proof {
        const proof = try self.proof_engine.generateProof(circuit_name, witness_data);
        const record_data = try self.allocator.alloc(u8, proof.data_len + proof.public_inputs_len + @sizeOf(ZKBackendType) + @sizeOf(u128) + @sizeOf(u32));
        defer self.allocator.free(record_data);
        var offset: usize = 0;
        @memcpy(record_data[offset..][0..proof.data_len], proof.data[0..proof.data_len]);
        offset += proof.data_len;
        @memcpy(record_data[offset..][0..proof.public_inputs_len], proof.public_inputs[0..proof.public_inputs_len]);
        offset += proof.public_inputs_len;
        @memcpy(record_data[offset..][0..@sizeOf(ZKBackendType)], std.mem.asBytes(&proof.backend));
        offset += @sizeOf(ZKBackendType);
        @memcpy(record_data[offset..][0..@sizeOf(u128)], std.mem.asBytes(&proof.proof_id));
        offset += @sizeOf(u128);
        @memcpy(record_data[offset..][0..@sizeOf(u32)], std.mem.asBytes(&proof.checksum));
        try self.wal.appendRecord(tx, .zk_proof, @intFromPtr(record_data.ptr), record_data.len);
        return proof;
    }

    pub fn verifyProof(self: *ZKLayer, proof: Proof) !bool {
        return self.proof_engine.verifyProof(proof);
    }

    pub fn createPrivateObject(self: *ZKLayer, comptime T: type, value: T, tx: *transaction.Transaction) !pointer.PersistentPtr {
        const header_size = @sizeOf(PrivateObjectHeader);
        const data_size = @sizeOf(T);
        const total_size = header_size + data_size;
        const ptr = try self.heap.allocate(tx, total_size, 64);
        const base = self.heap.getBaseAddress();
        const header_ptr: *PrivateObjectHeader = @ptrCast(@alignCast(base + ptr.offset));
        header_ptr.magic = 0x5A4B5052;
        header_ptr.schema_id = schema.getSchemaId(T);
        const commitment = security.computeCommitment(std.mem.asBytes(&value));
        @memcpy(&header_ptr.commitment, &commitment);
        var nonce: [12]u8 = undefined;
        std.crypto.random.bytes(&nonce);
        @memcpy(&header_ptr.encryption_nonce, &nonce);
        header_ptr.tag = 0;
        const encrypted = security.encrypt(std.mem.asBytes(&value), &nonce);
        @memcpy((base + ptr.offset + header_size)[0..data_size], encrypted[0..data_size]);
        header_ptr.checksum = computeChecksum(header_ptr);
        try self.private_objects.put(ptr.hash(), ptr);
        return ptr;
    }

    pub fn provePrivateProperty(self: *ZKLayer, ptr: pointer.PersistentPtr, property_circuit: []const u8, public_inputs: []const u8, tx: *transaction.Transaction) !Proof {
        const base = self.heap.getBaseAddress();
        const header: *const PrivateObjectHeader = @ptrCast(@alignCast(base + ptr.offset));
        if (header.magic != 0x5A4B5052) return error.InvalidPrivateObject;
        const header_size = @sizeOf(PrivateObjectHeader);
        const data_start = ptr.offset + header_size;
        const data = base[data_start..data_start + @sizeOf(@TypeOf(header.schema_id))];
        const witness = try std.mem.concat(self.allocator, u8, &.{ std.mem.asBytes(&header.schema_id), data, public_inputs });
        defer self.allocator.free(witness);
        return self.generateProof(property_circuit, witness, tx);
    }
};

fn computeChecksum(header: *const PrivateObjectHeader) u32 {
    var crc: u32 = 0xFFFFFFFF;
    const bytes = std.mem.asBytes(header);
    for (bytes[0..@offsetOf(PrivateObjectHeader, "checksum")]) |byte| {
        crc = crc32cByte(crc, byte);
    }
    return crc ^ 0xFFFFFFFF;
}

fn crc32cByte(crc: u32, byte: u8) u32 {
    const POLY: u32 = 0x82F63B78;
    var c = crc ^ @as(u32, byte);
    var j: usize = 0;
    while (j < 8) : (j += 1) {
        if ((c & 1) != 0) {
            c = (c >> 1) ^ POLY;
        } else {
            c = c >> 1;
        }
    }
    return c;
}

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

    pub fn registerCircuit(self: *CircuitRegistry, name: []const u8, r1cs_data: []const u8, proving_key: []const u8, verification_key: []const u8) !void {
        const name_dup = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_dup);
        const total_size = r1cs_data.len + proving_key.len + verification_key.len;
        var tx = try self.heap.beginTransaction();
        defer self.heap.endTransaction(&tx) catch {};
        const offset = try self.heap.allocate(&tx, total_size, 64);
        const base = self.heap.getBaseAddress();
        @memcpy(base[offset..][0..r1cs_data.len], r1cs_data);
        @memcpy(base[offset + r1cs_data.len..][0..proving_key.len], proving_key);
        @memcpy(base[offset + r1cs_data.len + proving_key.len..][0..verification_key.len], verification_key);
        try self.circuits.put(name_dup, CircuitEntry{
            .r1cs_offset = offset,
            .proving_key_offset = offset + r1cs_data.len,
            .verification_key_offset = offset + r1cs_data.len + proving_key.len,
            .size = total_size,
        });
    }

    pub fn getCircuit(self: *const CircuitRegistry, name: []const u8) ?CircuitEntry {
        return self.circuits.get(name);
    }
};

pub const ProofEngine = struct {
    allocator: std.mem.Allocator,
    config: ZKConfig,
    heap: *pheap.PersistentHeap,
    gpu_ctx: ?*gpu.GPUContext,

    pub fn init(allocator: std.mem.Allocator, config: ZKConfig, heap: *pheap.PersistentHeap) !ProofEngine {
        var engine = ProofEngine{
            .allocator = allocator,
            .config = config,
            .heap = heap,
            .gpu_ctx = null,
        };
        if (config.gpu_acceleration) {
            engine.gpu_ctx = try gpu.GPUContext.init(allocator, "compute.fut");
        }
        return engine;
    }

    pub fn deinit(self: *ProofEngine) void {
        if (self.gpu_ctx) |ctx| {
            ctx.deinit();
        }
    }

    pub fn generateProof(self: *ProofEngine, circuit_name: []const u8, witness_data: []const u8) !Proof {
        if (self.gpu_ctx) |ctx| {
            const input = gpu.GPUValue{ .array_i64 = witness_data };
            const result = try ctx.runKernel(circuit_name, &[_]gpu.GPUValue{input}, .array_i64);
            const proof_bytes = result.array_i64;
            return Proof{
                .data = proof_bytes.ptr,
                .data_len = proof_bytes.len,
                .public_inputs = witness_data.ptr,
                .public_inputs_len = witness_data.len,
                .backend = self.config.backend,
                .proof_id = std.hash.Wyhash.hash(0, witness_data),
                .checksum = computeProofChecksum(proof_bytes),
            };
        }
        const proof_bytes = try self.allocator.alloc(u8, witness_data.len * 2);
        @memcpy(proof_bytes[0..witness_data.len], witness_data);
        @memcpy(proof_bytes[witness_data.len..], witness_data);
        return Proof{
            .data = proof_bytes.ptr,
            .data_len = proof_bytes.len,
            .public_inputs = witness_data.ptr,
            .public_inputs_len = witness_data.len,
            .backend = self.config.backend,
            .proof_id = std.hash.Wyhash.hash(0, witness_data),
            .checksum = computeProofChecksum(proof_bytes),
        };
    }

    pub fn verifyProof(self: *ProofEngine, proof: Proof) !bool {
        const computed = computeProofChecksum(proof.data[0..proof.data_len]);
        return computed == proof.checksum;
    }

    fn computeProofChecksum(data: []const u8) u32 {
        var crc: u32 = 0xFFFFFFFF;
        for (data) |byte| {
            crc = crc32cByte(crc, byte);
        }
        return crc ^ 0xFFFFFFFF;
    }

    fn crc32cByte(crc: u32, byte: u8) u32 {
        const POLY: u32 = 0x82F63B78;
        var c = crc ^ @as(u32, byte);
        var j: usize = 0;
        while (j < 8) : (j += 1) {
            if ((c & 1) != 0) c = (c >> 1) ^ POLY else c = c >> 1;
        }
        return c;
    }
};

pub const PrivatePtr = extern struct {
    inner: pointer.PersistentPtr,
    commitment: [32]u8,
    nonce: [12]u8,
};

pub const ZKTransaction = struct {
    inner: transaction.Transaction,
    proof: ?Proof,
};
