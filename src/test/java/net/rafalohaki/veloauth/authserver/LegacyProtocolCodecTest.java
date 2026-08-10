package net.rafalohaki.veloauth.authserver;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class LegacyProtocolCodecTest {

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
}
