package net.rafalohaki.veloauth.authserver;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.geysermc.mcprotocollib.network.packet.Packet;
import org.geysermc.mcprotocollib.network.packet.PacketRegistry;
import org.geysermc.mcprotocollib.protocol.data.ProtocolState;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class LegacyProtocolCodecTest {

    @Test
    void ignoredGamePackets_RepeatedMovement_ShouldReuseStatelessPacket() {
        PacketRegistry registry = LegacyProtocolCodec.CODEC.getCodec(ProtocolState.GAME);
        ByteBuf firstPayload = Unpooled.wrappedBuffer(new byte[25]);
        ByteBuf secondPayload = Unpooled.wrappedBuffer(new byte[25]);
        try {
            Packet first = registry.createServerboundPacket(0x04, firstPayload);
            Packet second = registry.createServerboundPacket(0x04, secondPayload);

            assertSame(first, second,
                    "Ignored movement packets must not allocate one empty object per client tick");
            assertEquals(0, firstPayload.readableBytes());
            assertEquals(0, secondPayload.readableBytes());
        } finally {
            firstPayload.release();
            secondPayload.release();
        }
    }

    @Test
    void keepAlive_Minecraft18Wire_ShouldUseVarIntInBothDirections() {
        ByteBuf encoded = Unpooled.buffer();
        try {
            new LegacyProtocolCodec.KeepAlive(300).serialize(encoded);

            assertEquals(2, encoded.readableBytes());
            assertEquals(0xAC, encoded.readUnsignedByte());
            assertEquals(0x02, encoded.readUnsignedByte());
        } finally {
            encoded.release();
        }

        ByteBuf incoming = Unpooled.wrappedBuffer(new byte[]{(byte) 0xAC, 0x02});
        try {
            LegacyProtocolCodec.KeepAlive decoded = new LegacyProtocolCodec.KeepAlive(incoming);

            assertEquals(300, decoded.challenge());
            assertEquals(0, incoming.readableBytes());
        } finally {
            incoming.release();
        }
    }

    @Test
    void keepAlive_NegativeChallenge_ShouldRoundTripFiveByteVarInt() {
        ByteBuf buffer = Unpooled.buffer();
        try {
            new LegacyProtocolCodec.KeepAlive(-1).serialize(buffer);

            byte[] encoded = new byte[buffer.readableBytes()];
            buffer.getBytes(buffer.readerIndex(), encoded);
            assertArrayEquals(new byte[]{
                    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x0F
            }, encoded);
            assertEquals(-1, new LegacyProtocolCodec.KeepAlive(buffer).challenge());
            assertEquals(0, buffer.readableBytes());
        } finally {
            buffer.release();
        }
    }

    @Test
    void playerAbilities_SpectatorWire_ShouldUseProtocol47PacketAndFields() {
        PacketRegistry registry = LegacyProtocolCodec.CODEC.getCodec(ProtocolState.GAME);
        assertEquals(0x39, registry.getClientboundId(LegacyProtocolCodec.PlayerAbilities.class));

        ByteBuf encoded = Unpooled.buffer();
        try {
            new LegacyProtocolCodec.PlayerAbilities(
                    true, true, true, false, 0.05F, 0.1F).serialize(encoded);

            assertEquals(0x07, encoded.readUnsignedByte());
            assertEquals(0.05F, encoded.readFloat());
            assertEquals(0.1F, encoded.readFloat());
            assertEquals(0, encoded.readableBytes());
        } finally {
            encoded.release();
        }
    }

    @Test
    void pluginMessage_BrandWire_ShouldEncodeChannelAndPayloadAsStrings() {
        PacketRegistry registry = LegacyProtocolCodec.CODEC.getCodec(ProtocolState.GAME);
        assertEquals(0x3F, registry.getClientboundId(LegacyProtocolCodec.PluginMessage.class));

        ByteBuf encoded = Unpooled.buffer();
        try {
            new LegacyProtocolCodec.PluginMessage("MC|Brand", "VeloAuth").serialize(encoded);

            byte[] actual = new byte[encoded.readableBytes()];
            encoded.readBytes(actual);
            assertArrayEquals(new byte[]{
                    0x08, 'M', 'C', '|', 'B', 'r', 'a', 'n', 'd',
                    0x08, 'V', 'e', 'l', 'o', 'A', 'u', 't', 'h'
            }, actual);
        } finally {
            encoded.release();
        }
    }
}
