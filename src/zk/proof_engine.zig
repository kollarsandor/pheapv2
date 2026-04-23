const std = @import("std");
const pheap = @import("pheap.zig");
const gpu = @import("gpu.zig");
const ZKConfig = @import("zk.zig").ZKConfig;
const Proof = @import("zk.zig").Proof;

pub const ProofEngine = struct {
    allocator: std.mem.Allocator,
    config: ZKConfig,
    heap: *pheap.PersistentHeap,
    gpu_ctx: ?*gpu.GPUContext,

    pub fn init(allocator: std.mem.Allocator, config: ZKConfig, heap: *pheap.PersistentHeap) !ProofEngine {
        var self = ProofEngine{
            .allocator = allocator,
            .config = config,
            .heap = heap,
            .gpu_ctx = null,
        };
        if (config.gpu_acceleration) {
            self.gpu_ctx = try gpu.GPUContext.init(allocator, "compute.fut");
        }
        return self;
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
        const computed = computeProofChecksum(proof.data[0..@as(usize, @intCast(proof.data_len))]);
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
