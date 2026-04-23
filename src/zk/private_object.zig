const std = @import("std");
const pointer = @import("pointer.zig");
const security = @import("security.zig");

pub const PrivatePtr = extern struct {
    inner: pointer.PersistentPtr,
    commitment: [32]u8,
    nonce: [12]u8,

    pub fn init(inner: pointer.PersistentPtr, commitment: [32]u8, nonce: [12]u8) PrivatePtr {
        return PrivatePtr{
            .inner = inner,
            .commitment = commitment,
            .nonce = nonce,
        };
    }

    pub fn decrypt(self: PrivatePtr, key: []const u8, base_addr: [*]u8) ![]u8 {
        const offset = self.inner.offset;
        const header_size = @sizeOf(@This());
        const encrypted = base_addr[offset + header_size ..];
        return security.decrypt(encrypted, key, self.nonce);
    }
};
