package net.rafalohaki.veloauth.premium;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ProfileKeyPacketTest {

    private static void writeVarInt(ByteBuf buf, int value) {
        int remaining = value;
        while ((remaining & ~0x7F) != 0) {
            buf.writeByte((remaining & 0x7F) | 0x80);
            remaining >>>= 7;
        }
        buf.writeByte(remaining);
    }

    private static ByteBuf sessionPacket(int packetId, byte[] key, byte[] sig) {
        ByteBuf buf = Unpooled.buffer();
        writeVarInt(buf, packetId);
        UUID session = UUID.randomUUID();
        buf.writeLong(session.getMostSignificantBits());
        buf.writeLong(session.getLeastSignificantBits());
        buf.writeLong(1_700_000_000_000L);
        writeVarInt(buf, key.length);
        buf.writeBytes(key);
        writeVarInt(buf, sig.length);
        buf.writeBytes(sig);
        return buf;
    }

    @Test
    void parsesWellFormedPacketRegardlessOfId() {
        byte[] key = new byte[294];
        byte[] sig = new byte[512];
        key[0] = 0x30;
        sig[511] = 7;
        for (int id : new int[] {0x06, 0x0A, 0x0B, 0x44}) {
            ByteBuf raw = sessionPacket(id, key, sig);
            int readerIndex = raw.readerIndex();
            ProfileKeyPacket packet = ProfileKeyPacket.tryParse(raw);
            assertNotNull(packet, "id " + id);
            assertEquals(1_700_000_000_000L, packet.expiresAt());
            assertArrayEquals(key, packet.publicKey());
            assertArrayEquals(sig, packet.signature());
            assertEquals(readerIndex, raw.readerIndex(), "parser must not consume the buffer");
        }
    }

    @Test
    void rejectsTrailingBytesAndShortPackets() {
        ByteBuf trailing = sessionPacket(0x0A, new byte[294], new byte[512]).writeByte(0);
        assertNull(ProfileKeyPacket.tryParse(trailing));
        assertNull(ProfileKeyPacket.tryParse(Unpooled.buffer().writeByte(0x0A)));
        assertNull(ProfileKeyPacket.tryParse(Unpooled.buffer()));
        assertNull(ProfileKeyPacket.tryParse(null));
    }

    @Test
    void rejectsOversizedOrEmptyFields() {
        assertNull(ProfileKeyPacket.tryParse(sessionPacket(0x0A, new byte[513], new byte[512])));
        assertNull(ProfileKeyPacket.tryParse(sessionPacket(0x0A, new byte[294], new byte[4097])));
        assertNull(ProfileKeyPacket.tryParse(sessionPacket(0x0A, new byte[0], new byte[512])));
        assertNull(ProfileKeyPacket.tryParse(sessionPacket(0x0A, new byte[294], new byte[0])));
    }

    @Test
    void expectedIdIsEnforcedWhenGiven() {
        ByteBuf raw = sessionPacket(0x0A, new byte[294], new byte[512]);
        assertNotNull(ProfileKeyPacket.tryParse(raw, 0x0A));
        assertNull(ProfileKeyPacket.tryParse(raw, 0x09));
        assertNotNull(ProfileKeyPacket.tryParse(raw, -1));
    }

    @Test
    void rejectsUnrelatedPackets() {
        // Chat message: id + string + long + long + ...
        ByteBuf chat = Unpooled.buffer();
        writeVarInt(chat, 0x08);
        writeVarInt(chat, 5);
        chat.writeBytes("hello".getBytes());
        chat.writeLong(1L).writeLong(2L).writeBoolean(false);
        assertNull(ProfileKeyPacket.tryParse(chat));
        // Keep-alive: id + long
        assertNull(ProfileKeyPacket.tryParse(Unpooled.buffer().writeByte(0x1B).writeLong(42L)));
    }
}
