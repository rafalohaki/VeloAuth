package net.rafalohaki.veloauth.premium;

import io.netty.buffer.ByteBuf;
import javax.annotation.Nullable;

/**
 * Decoded serverbound {@code chat_session_update} ("Player Session") packet body.
 * <p>
 * Wire format (PLAY, 1.19.3+): session UUID, expiry (long), public key (VarInt-prefixed bytes,
 * max 512), Mojang signature (VarInt-prefixed bytes, max 4096). The packet id differs between
 * game versions, so the parser identifies the packet structurally: a raw serverbound packet whose
 * body matches this layout exactly, and whose signature later verifies against Mojang's key, is
 * the session packet - no other vanilla packet can satisfy both conditions.
 *
 * @param expiresAt key expiry in epoch milliseconds
 * @param publicKey X.509 encoded RSA public key
 * @param signature Mojang signature over {@code profile + expiry + key}
 */
public record ProfileKeyPacket(long expiresAt, byte[] publicKey, byte[] signature) {

    private static final int MAX_KEY = 512;
    private static final int MAX_SIGNATURE = 4096;
    private static final int UUID_BYTES = 16;

    /**
     * Tries to decode a raw serverbound packet (reader index at the packet id). Never throws;
     * returns {@code null} unless the body matches the session layout exactly.
     */
    @Nullable
    public static ProfileKeyPacket tryParse(ByteBuf raw) {
        return tryParse(raw, -1);
    }

    /**
     * Like {@link #tryParse(ByteBuf)} but additionally requires the packet id to equal
     * {@code expectedId} (pass a negative value to accept any id).
     */
    @Nullable
    public static ProfileKeyPacket tryParse(ByteBuf raw, int expectedId) {
        if (raw == null) {
            return null;
        }
        ByteBuf buf = raw.duplicate();
        try {
            return hasExpectedHeader(buf, expectedId) ? readBody(buf) : null;
        } catch (RuntimeException malformed) {
            return null;
        }
    }

    private static boolean hasExpectedHeader(ByteBuf buf, int expectedId) {
        int id = readVarInt(buf);
        boolean idOk = id >= 0 && (expectedId < 0 || id == expectedId);
        return idOk && buf.readableBytes() >= UUID_BYTES + Long.BYTES + 2;
    }

    @Nullable
    private static ProfileKeyPacket readBody(ByteBuf buf) {
        buf.skipBytes(UUID_BYTES);
        long expiresAt = buf.readLong();
        byte[] key = readBlock(buf, MAX_KEY, false);
        byte[] signature = key.length == 0 ? key : readBlock(buf, MAX_SIGNATURE, true);
        return signature.length == 0 ? null : new ProfileKeyPacket(expiresAt, key, signature);
    }

    /** VarInt-prefixed byte block; empty when the length is implausible. */
    private static byte[] readBlock(ByteBuf buf, int maxLength, boolean mustBeLast) {
        int length = readVarInt(buf);
        boolean sizeOk = mustBeLast ? length == buf.readableBytes() : length <= buf.readableBytes();
        if (length <= 0 || length > maxLength || !sizeOk) {
            return new byte[0];
        }
        byte[] block = new byte[length];
        buf.readBytes(block);
        return block;
    }

    /** Reads a VarInt; returns -1 when malformed. */
    static int readVarInt(ByteBuf buf) {
        int value = 0;
        int position = 0;
        while (true) {
            if (!buf.isReadable()) {
                return -1;
            }
            byte current = buf.readByte();
            value |= (current & 0x7F) << position;
            if ((current & 0x80) == 0) {
                return value;
            }
            position += 7;
            if (position >= 32) {
                return -1;
            }
        }
    }
}
