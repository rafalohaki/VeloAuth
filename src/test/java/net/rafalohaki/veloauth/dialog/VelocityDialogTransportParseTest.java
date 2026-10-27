package net.rafalohaki.veloauth.dialog;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import net.kyori.adventure.nbt.BinaryTagIO;
import net.kyori.adventure.nbt.CompoundBinaryTag;
import org.junit.jupiter.api.Test;

/**
 * Verifies that serverbound {@code custom_click_action} bodies are parsed exactly as the vanilla
 * client encodes them: identifier, VarInt payload size, nameless NBT (TAG_End when absent).
 */
class VelocityDialogTransportParseTest {

    private static void writeVarInt(ByteArrayOutputStream out, int value) {
        int remaining = value;
        while ((remaining & ~0x7F) != 0) {
            out.write((remaining & 0x7F) | 0x80);
            remaining >>>= 7;
        }
        out.write(remaining);
    }

    private static void writeString(ByteArrayOutputStream out, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writeVarInt(out, bytes.length);
        out.write(bytes, 0, bytes.length);
    }

    private static ByteBuf body(String id, CompoundBinaryTag payload) throws IOException {
        ByteArrayOutputStream nbt = new ByteArrayOutputStream();
        if (payload == null) {
            nbt.write(0); // TAG_End = no payload
        } else {
            BinaryTagIO.writer().writeNameless(payload, (java.io.DataOutput) new DataOutputStream(nbt));
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeString(out, id);
        writeVarInt(out, nbt.size());
        out.write(nbt.toByteArray(), 0, nbt.size());
        return Unpooled.wrappedBuffer(out.toByteArray());
    }

    @Test
    void parsesVanillaRegisterClickWithInputs() throws IOException {
        CompoundBinaryTag payload = CompoundBinaryTag.builder()
                .putString("password", "secret123")
                .putString("confirm", "secret123")
                .build();
        DialogClick click = DialogPacketCodec.parseClick(body("veloauth:register", payload));
        assertNotNull(click);
        assertEquals("register", click.action());
        assertEquals("secret123", click.text("password"));
        assertEquals("secret123", click.text("confirm"));
    }

    @Test
    void parsesClickWithoutPayload() throws IOException {
        DialogClick click = DialogPacketCodec.parseClick(body("veloauth:exit", null));
        assertNotNull(click);
        assertEquals("exit", click.action());
        assertTrue(click.payload().size() == 0);
    }

    @Test
    void ignoresForeignNamespace() throws IOException {
        CompoundBinaryTag payload = CompoundBinaryTag.builder().putString("x", "y").build();
        assertNull(DialogPacketCodec.parseClick(body("otherplugin:thing", payload)));
    }
}
