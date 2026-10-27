package net.rafalohaki.veloauth.dialog;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import io.netty.buffer.ByteBufOutputStream;
import io.netty.buffer.Unpooled;
import net.kyori.adventure.nbt.BinaryTag;
import net.kyori.adventure.nbt.BinaryTagIO;
import net.kyori.adventure.nbt.CompoundBinaryTag;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Wire-level helpers for the dialog packets: per-protocol packet ids, VarInt / string / network
 * NBT codecs and the {@code custom_click_action} body parser. Stateless.
 */
final class DialogPacketCodec {

    static final int PROTOCOL_26_3 = VelocityDialogTransport.PROTOCOL_26_3;
    static final int PROTOCOL_26_1 = VelocityDialogTransport.PROTOCOL_26_1;
    static final int PROTOCOL_1_21_9 = VelocityDialogTransport.PROTOCOL_1_21_9;
    static final int MAX_CLICK_PAYLOAD = 65_536;
    private static final byte NBT_TYPE_COMPOUND = 10;

    private DialogPacketCodec() {
    }

    // PLAY ids per protocol, taken from Mojang's packet reports (1.21.6=771 ... 26.3=777; 26.2 shares
    // the 26.1 ids). Velocity does not register these packets in PLAY, so they are written raw.

    /** Clientbound PLAY {@code show_dialog} id; body is {@code VarInt 0 (inline) + NBT}. */
    static int playShowDialogId(int protocol) {
        if (protocol >= PROTOCOL_26_3) {
            return 0x8F;
        }
        if (protocol >= PROTOCOL_26_1) {
            return 0x8C;
        }
        if (protocol >= PROTOCOL_1_21_9) {
            return 0x8A;
        }
        return 0x85;
    }

    /** Clientbound PLAY {@code clear_dialog} id. */
    static int playClearDialogId(int protocol) {
        return playShowDialogId(protocol) - 1;
    }

    /** Serverbound PLAY {@code custom_click_action} id. */
    static int playCustomClickId(int protocol) {
        return protocol >= PROTOCOL_26_1 ? 0x44 : 0x41;
    }

    /** Serverbound PLAY {@code chat_session_update} (profile key) id. */
    static int playChatSessionId(int protocol) {
        return protocol >= PROTOCOL_26_1 ? 0x0A : 0x09;
    }

    static ByteBuf rawPlayShowPacket(int protocol, BinaryTag nbt) throws IOException {
        ByteBuf buf = Unpooled.buffer();
        writeVarInt(buf, playShowDialogId(protocol));
        writeVarInt(buf, 0); // inline dialog (not a registry id)
        writeNbt(buf, nbt);
        return buf;
    }

    /** Clientbound CONFIGURATION {@code show_dialog} id (the NBT follows directly, no holder). */
    static int showDialogId(int protocol) {
        return protocol >= PROTOCOL_26_3 ? 0x13 : 0x12;
    }

    /** Clientbound CONFIGURATION {@code clear_dialog} id. */
    static int clearDialogId(int protocol) {
        return protocol >= PROTOCOL_26_3 ? 0x12 : 0x11;
    }

    /** Builds a raw framed packet body: varint id + optional network NBT (nameless root). */
    static ByteBuf rawPacket(int packetId, BinaryTag nbt) throws IOException {
        ByteBuf buf = Unpooled.buffer();
        writeVarInt(buf, packetId);
        if (nbt != null) {
            writeNbt(buf, nbt);
        }
        return buf;
    }

    /**
     * Writes a network ("nameless") compound tag. Deliberately avoids invoking methods on
     * {@code BinaryTagType}: it is an abstract class in Adventure 4.x (Velocity 3.x) but an
     * interface in Adventure 5.x (Velocity 4.x), so such calls would throw
     * {@link IncompatibleClassChangeError} on one of the two proxies. {@code BinaryTagIO}
     * exposes the same operation through a stable interface.
     */
    static void writeNbt(ByteBuf buf, BinaryTag tag) throws IOException {
        if (!(tag instanceof CompoundBinaryTag compound)) {
            throw new IOException("Dialog payloads must be compound tags, got " + tag.getClass().getSimpleName());
        }
        try (DataOutputStream out = new DataOutputStream(new ByteBufOutputStream(buf))) {
            BinaryTagIO.writer().writeNameless(compound, (java.io.DataOutput) out);
        }
    }

    static void writeVarInt(ByteBuf buf, int value) {
        int remaining = value;
        while ((remaining & ~0x7F) != 0) {
            buf.writeByte((remaining & 0x7F) | 0x80);
            remaining >>>= 7;
        }
        buf.writeByte(remaining);
    }

    static int readVarInt(ByteBuf buf) {
        int result = 0;
        int shift = 0;
        while (true) {
            if (!buf.isReadable()) {
                throw new IllegalArgumentException("VarInt truncated");
            }
            byte b = buf.readByte();
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return result;
            }
            shift += 7;
            if (shift > 35) {
                throw new IllegalArgumentException("VarInt too big");
            }
        }
    }

    static String readString(ByteBuf buf, int maxLength) {
        int length = readVarInt(buf);
        if (length < 0 || length > maxLength * 4 || length > buf.readableBytes()) {
            throw new IllegalArgumentException("Bad string length " + length);
        }
        String value = buf.toString(buf.readerIndex(), length, StandardCharsets.UTF_8);
        buf.skipBytes(length);
        return value;
    }

    /**
     * Parses the body of a serverbound {@code custom_click_action}: identifier, then the
     * VarInt-prefixed nameless NBT payload (TAG_End when the action carries no data).
     *
     * @return the click, or {@code null} when the identifier is not in the {@code veloauth} namespace
     */
    static DialogClick parseClick(ByteBuf body) throws IOException {
        String id = readString(body, 32_767);
        int colon = id.indexOf(':');
        String namespace = colon >= 0 ? id.substring(0, colon) : "minecraft";
        if (!DialogNbt.ACTION_NAMESPACE.equals(namespace.toLowerCase(Locale.ROOT))) {
            return null;
        }
        String path = colon >= 0 ? id.substring(colon + 1) : id;
        return new DialogClick(path, readClickPayload(body));
    }

    private static CompoundBinaryTag readClickPayload(ByteBuf body) throws IOException {
        if (!body.isReadable()) {
            return CompoundBinaryTag.empty();
        }
        // Wire format (1.21.6+): VarInt payload size, then a nameless NBT tag; TAG_End (0) = no payload.
        int length = readVarInt(body);
        if (length < 0 || length > MAX_CLICK_PAYLOAD || length > body.readableBytes()) {
            throw new IllegalArgumentException("Bad click payload length " + length);
        }
        ByteBuf block = body.readSlice(length);
        if (!block.isReadable()) {
            return CompoundBinaryTag.empty();
        }
        BinaryTag tag = readNbt(block);
        return tag instanceof CompoundBinaryTag compound ? compound : CompoundBinaryTag.empty();
    }

    /**
     * Reads a network ("nameless") NBT tag. Only compound payloads are meaningful for dialog
     * clicks (the client always sends a compound with one entry per input), everything else is
     * skipped and reported as {@code null}.
     */
    static BinaryTag readNbt(ByteBuf buf) throws IOException {
        byte typeId = buf.getByte(buf.readerIndex());
        if (typeId == 0) {
            buf.readByte();
            return null;
        }
        if (typeId != NBT_TYPE_COMPOUND) {
            // Non-compound payload: not something a dialog produces; ignore the remaining bytes.
            buf.skipBytes(buf.readableBytes());
            return null;
        }
        try (DataInputStream in = new DataInputStream(new ByteBufInputStream(buf))) {
            return BinaryTagIO.reader(MAX_CLICK_PAYLOAD).readNameless((java.io.DataInput) in);
        }
    }

}
