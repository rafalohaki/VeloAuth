package net.rafalohaki.veloauth.authserver;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/** Small raw-wire client shared by embedded protocol compatibility and hardening tests. */
final class MinecraftWireTestSupport {

    private MinecraftWireTestSupport() {
    }

    static Socket connect(int port) throws IOException {
        Socket socket = new Socket();
        socket.connect(LoopbackAddress.socket(port), 2_000);
        socket.setSoTimeout(5_000);
        return socket;
    }

    static void sendLogin(Socket socket, int protocol, String username) throws IOException {
        sendHandshake(socket, protocol, 2);
        ByteArrayOutputStream login = packet(0x00);
        writeString(login, username);
        writeFrame(socket, login);
    }

    static void sendHandshake(Socket socket, int protocol, int intent) throws IOException {
        ByteArrayOutputStream handshake = packet(0x00);
        writeVarInt(handshake, protocol);
        writeString(handshake, "localhost");
        new DataOutputStream(handshake).writeShort(socket.getPort());
        writeVarInt(handshake, intent);
        writeFrame(socket, handshake);
    }

    static ByteArrayOutputStream packet(int packetId) {
        ByteArrayOutputStream packet = new ByteArrayOutputStream();
        writeVarInt(packet, packetId);
        return packet;
    }

    static void writeFrame(Socket socket, ByteArrayOutputStream packet) throws IOException {
        byte[] bytes = packet.toByteArray();
        ByteArrayOutputStream frame = new ByteArrayOutputStream();
        writeVarInt(frame, bytes.length);
        frame.writeBytes(bytes);
        socket.getOutputStream().write(frame.toByteArray());
        socket.getOutputStream().flush();
    }

    static void writeDeclaredFrameLength(Socket socket, int length) throws IOException {
        ByteArrayOutputStream declaration = new ByteArrayOutputStream();
        writeVarInt(declaration, length);
        socket.getOutputStream().write(declaration.toByteArray());
        socket.getOutputStream().flush();
    }

    static Frame readFrame(Socket socket) throws IOException {
        DataInputStream input = new DataInputStream(socket.getInputStream());
        int length = readVarInt(input);
        byte[] bytes = input.readNBytes(length);
        if (bytes.length != length) {
            throw new EOFException("Truncated Minecraft frame");
        }
        DataInputStream payload = new DataInputStream(new ByteArrayInputStream(bytes));
        return new Frame(readVarInt(payload), payload);
    }

    static String readString(DataInputStream input) throws IOException {
        int length = readVarInt(input);
        if (length < 0 || length > 32_767) {
            throw new IllegalArgumentException("Invalid string length");
        }
        byte[] bytes = input.readNBytes(length);
        if (bytes.length != length) {
            throw new EOFException("Truncated string");
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static int readVarInt(DataInputStream input) throws IOException {
        int value = 0;
        int shift = 0;
        while (shift < 35) {
            int current = input.readUnsignedByte();
            value |= (current & 0x7F) << shift;
            if ((current & 0x80) == 0) {
                return value;
            }
            shift += 7;
        }
        throw new IllegalArgumentException("VarInt is too long");
    }

    private static void writeString(ByteArrayOutputStream output, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writeVarInt(output, bytes.length);
        output.writeBytes(bytes);
    }

    private static void writeVarInt(ByteArrayOutputStream output, int value) {
        int remaining = value;
        while ((remaining & ~0x7F) != 0) {
            output.write((remaining & 0x7F) | 0x80);
            remaining >>>= 7;
        }
        output.write(remaining);
    }

    record Frame(int packetId, DataInputStream payload) {
    }
}
