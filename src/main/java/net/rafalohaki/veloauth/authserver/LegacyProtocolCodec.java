package net.rafalohaki.veloauth.authserver;

import io.netty.buffer.ByteBuf;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.gson.GsonComponentSerializer;
import org.geysermc.mcprotocollib.protocol.codec.MinecraftPacket;
import org.geysermc.mcprotocollib.protocol.codec.MinecraftPacketRegistry;
import org.geysermc.mcprotocollib.protocol.codec.PacketCodec;
import org.geysermc.mcprotocollib.protocol.data.ProtocolState;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.UUID;

/** Minimal Minecraft 1.8 wire codec used as ViaVersion's stable translation target. */
final class LegacyProtocolCodec {

    static final int PROTOCOL_VERSION = 47;
    static final String MINECRAFT_VERSION = "1.8.x";
    private static final int END_DIMENSION_ID = 1;
    private static final int SPECTATOR_GAME_MODE_ID = 3;
    private static final int PLAYER_ABILITIES_PACKET_ID = 0x39;
    private static final int PLUGIN_MESSAGE_PACKET_ID = 0x3F;
    private static final int LAST_SERVERBOUND_GAME_PACKET = 0x19;

    static final PacketCodec CODEC = PacketCodec.builder()
            .protocolVersion(PROTOCOL_VERSION)
            .minecraftVersion(MINECRAFT_VERSION)
            .state(ProtocolState.HANDSHAKE, handshakeRegistry())
            .state(ProtocolState.STATUS, statusRegistry())
            .state(ProtocolState.LOGIN, loginRegistry())
            .state(ProtocolState.GAME, gameRegistry())
            .build();

    private LegacyProtocolCodec() {
    }

    private static MinecraftPacketRegistry handshakeRegistry() {
        return MinecraftPacketRegistry.builder()
                .registerServerboundPacket(Handshake.class, Handshake::new);
    }

    private static MinecraftPacketRegistry statusRegistry() {
        return MinecraftPacketRegistry.builder()
                .registerClientboundPacket(StatusResponse.class, StatusResponse::new)
                .registerClientboundPacket(Pong.class, Pong::new)
                .registerServerboundPacket(StatusRequest.class, StatusRequest::new)
                .registerServerboundPacket(Ping.class, Ping::new);
    }

    private static MinecraftPacketRegistry loginRegistry() {
        return MinecraftPacketRegistry.builder()
                .registerClientboundPacket(LoginDisconnect.class, LoginDisconnect::new)
                .registerClientboundPacket(UnusedClientboundPacket.class, UnusedClientboundPacket::new)
                .registerClientboundPacket(LoginSuccess.class, LoginSuccess::new)
                .registerServerboundPacket(LoginStart.class, LoginStart::new);
    }

    private static MinecraftPacketRegistry gameRegistry() {
        MinecraftPacketRegistry registry = MinecraftPacketRegistry.builder()
                .registerClientboundPacket(KeepAlive.class, KeepAlive::new)
                .registerClientboundPacket(JoinGame.class, JoinGame::new);
        for (int packetId = 2; packetId < 8; packetId++) {
            registry.registerClientboundPacket(UnusedClientboundPacket.class, UnusedClientboundPacket::new);
        }
        registry.registerClientboundPacket(PlayerPosition.class, PlayerPosition::new);
        for (int packetId = 9; packetId < PLAYER_ABILITIES_PACKET_ID; packetId++) {
            registry.registerClientboundPacket(UnusedClientboundPacket.class, UnusedClientboundPacket::new);
        }
        registry.registerClientboundPacket(PlayerAbilities.class, PlayerAbilities::new);
        for (int packetId = PLAYER_ABILITIES_PACKET_ID + 1;
             packetId < PLUGIN_MESSAGE_PACKET_ID; packetId++) {
            registry.registerClientboundPacket(UnusedClientboundPacket.class, UnusedClientboundPacket::new);
        }
        registry.registerClientboundPacket(PluginMessage.class, PluginMessage::new);

        registry.registerServerboundPacket(KeepAlive.class, KeepAlive::new);
        for (int packetId = 1; packetId <= LAST_SERVERBOUND_GAME_PACKET; packetId++) {
            registry.registerServerboundPacket(
                    IgnoredServerboundPacket.class, LegacyProtocolCodec::ignoredServerboundPacket);
        }
        return registry;
    }

    private static IgnoredServerboundPacket ignoredServerboundPacket(ByteBuf input) {
        input.skipBytes(input.readableBytes());
        return IgnoredServerboundPacket.INSTANCE;
    }

    record Handshake(int protocolVersion, String hostname, int port, Intent intent)
            implements MinecraftPacket {
        Handshake(ByteBuf input) {
            this(readVarInt(input), readString(input, 255), input.readUnsignedShort(),
                    Intent.fromId(readVarInt(input)));
        }

        Handshake {
            Objects.requireNonNull(hostname, "hostname");
            Objects.requireNonNull(intent, "intent");
        }

        @Override
        public void serialize(ByteBuf output) {
            writeVarInt(output, protocolVersion);
            writeString(output, hostname);
            output.writeShort(port);
            writeVarInt(output, intent.id());
        }

        @Override
        public boolean isTerminal() {
            return true;
        }
    }

    enum Intent {
        STATUS(1),
        LOGIN(2);

        private final int id;

        Intent(int id) {
            this.id = id;
        }

        int id() {
            return id;
        }

        static Intent fromId(int id) {
            return switch (id) {
                case 1 -> STATUS;
                case 2 -> LOGIN;
                default -> throw new IllegalArgumentException("Unsupported Minecraft handshake intent");
            };
        }
    }

    record StatusRequest() implements MinecraftPacket {
        StatusRequest(ByteBuf input) {
            this();
            requireEmpty(input);
        }

        @Override
        public void serialize(ByteBuf output) {
            // Empty packet.
        }
    }

    record StatusResponse(String json) implements MinecraftPacket {
        StatusResponse(ByteBuf input) {
            this(readString(input, 32_767));
        }

        StatusResponse(String versionName, Component description, int maximumPlayers, int onlinePlayers) {
            this("{\"version\":{\"name\":"
                    + GsonComponentSerializer.gson().serialize(Component.text(versionName))
                    + ",\"protocol\":47},"
                    + "\"players\":{\"max\":" + maximumPlayers + ",\"online\":" + onlinePlayers
                    + ",\"sample\":[]},\"description\":"
                    + GsonComponentSerializer.gson().serialize(description) + '}');
        }

        StatusResponse {
            Objects.requireNonNull(json, "json");
        }

        @Override
        public void serialize(ByteBuf output) {
            writeString(output, json);
        }
    }

    record Ping(long value) implements MinecraftPacket {
        Ping(ByteBuf input) {
            this(input.readLong());
        }

        @Override
        public void serialize(ByteBuf output) {
            output.writeLong(value);
        }
    }

    record Pong(long value) implements MinecraftPacket {
        Pong(ByteBuf input) {
            this(input.readLong());
        }

        @Override
        public void serialize(ByteBuf output) {
            output.writeLong(value);
        }
    }

    record LoginStart(String username) implements MinecraftPacket {
        LoginStart(ByteBuf input) {
            this(readString(input, 16));
        }

        LoginStart {
            if (username == null || username.isEmpty() || username.length() > 16) {
                throw new IllegalArgumentException("Invalid Minecraft username");
            }
        }

        @Override
        public void serialize(ByteBuf output) {
            writeString(output, username);
        }
    }

    record LoginSuccess(UUID uniqueId, String username) implements MinecraftPacket {
        LoginSuccess(ByteBuf input) {
            this(UUID.fromString(readString(input, 36)), readString(input, 16));
        }

        LoginSuccess {
            Objects.requireNonNull(uniqueId, "uniqueId");
            Objects.requireNonNull(username, "username");
        }

        @Override
        public void serialize(ByteBuf output) {
            writeString(output, uniqueId.toString());
            writeString(output, username);
        }
    }

    record LoginDisconnect(Component reason) implements MinecraftPacket {
        LoginDisconnect(ByteBuf input) {
            this(GsonComponentSerializer.gson().deserialize(readString(input, 32_767)));
        }

        LoginDisconnect {
            Objects.requireNonNull(reason, "reason");
        }

        @Override
        public void serialize(ByteBuf output) {
            writeString(output, GsonComponentSerializer.gson().serialize(reason));
        }
    }

    record KeepAlive(int challenge) implements MinecraftPacket {
        KeepAlive(ByteBuf input) {
            this(readVarInt(input));
        }

        @Override
        public void serialize(ByteBuf output) {
            writeVarInt(output, challenge);
        }
    }

    record JoinGame(int entityId) implements MinecraftPacket {
        JoinGame(ByteBuf input) {
            this(input.readInt());
            input.skipBytes(input.readableBytes());
        }

        @Override
        public void serialize(ByteBuf output) {
            output.writeInt(entityId);
            // Spectator keeps vanilla clients suspended in a chunkless void without server ticks.
            output.writeByte(SPECTATOR_GAME_MODE_ID);
            output.writeByte(END_DIMENSION_ID);
            output.writeByte(0); // Peaceful.
            output.writeByte(1); // Advertised maximum players.
            writeString(output, "default");
            output.writeBoolean(false); // Reduced debug info.
        }
    }

    record PlayerPosition(double x, double y, double z, float yaw, float pitch)
            implements MinecraftPacket {
        PlayerPosition(ByteBuf input) {
            this(input.readDouble(), input.readDouble(), input.readDouble(),
                    input.readFloat(), input.readFloat());
            input.readUnsignedByte();
        }

        @Override
        public void serialize(ByteBuf output) {
            output.writeDouble(x);
            output.writeDouble(y);
            output.writeDouble(z);
            output.writeFloat(yaw);
            output.writeFloat(pitch);
            output.writeByte(0); // All coordinates are absolute.
        }
    }

    record PlayerAbilities(
            boolean invulnerable,
            boolean flying,
            boolean canFly,
            boolean creative,
            float flySpeed,
            float walkSpeed) implements MinecraftPacket {

        private static final int FLAG_INVULNERABLE = 0x01;
        private static final int FLAG_FLYING = 0x02;
        private static final int FLAG_CAN_FLY = 0x04;
        private static final int FLAG_CREATIVE = 0x08;

        PlayerAbilities(ByteBuf input) {
            this(input.readUnsignedByte(), input.readFloat(), input.readFloat());
        }

        private PlayerAbilities(int flags, float flySpeed, float walkSpeed) {
            this((flags & FLAG_INVULNERABLE) != 0,
                    (flags & FLAG_FLYING) != 0,
                    (flags & FLAG_CAN_FLY) != 0,
                    (flags & FLAG_CREATIVE) != 0,
                    flySpeed,
                    walkSpeed);
        }

        PlayerAbilities {
            if (!Float.isFinite(flySpeed) || !Float.isFinite(walkSpeed)
                    || flySpeed < 0.0F || walkSpeed < 0.0F) {
                throw new IllegalArgumentException("Player ability speeds must be finite and non-negative");
            }
        }

        @Override
        public void serialize(ByteBuf output) {
            int flags = (invulnerable ? FLAG_INVULNERABLE : 0)
                    | (flying ? FLAG_FLYING : 0)
                    | (canFly ? FLAG_CAN_FLY : 0)
                    | (creative ? FLAG_CREATIVE : 0);
            output.writeByte(flags);
            output.writeFloat(flySpeed);
            output.writeFloat(walkSpeed);
        }
    }

    /** Legacy string-payload plugin message used for the protocol-47 server brand. */
    record PluginMessage(String channel, String stringPayload) implements MinecraftPacket {
        PluginMessage(ByteBuf input) {
            this(readString(input, 20), readString(input, 32_767));
            requireEmpty(input);
        }

        PluginMessage {
            if (channel == null || channel.isEmpty() || channel.length() > 20) {
                throw new IllegalArgumentException("Plugin channel must contain 1-20 characters");
            }
            Objects.requireNonNull(stringPayload, "stringPayload");
        }

        @Override
        public void serialize(ByteBuf output) {
            writeString(output, channel);
            writeString(output, stringPayload);
        }
    }

    private enum IgnoredServerboundPacket implements MinecraftPacket {
        INSTANCE;

        @Override
        public void serialize(ByteBuf output) {
            // Never emitted by the server.
        }
    }

    private record UnusedClientboundPacket() implements MinecraftPacket {
        private UnusedClientboundPacket(ByteBuf input) {
            this();
            input.skipBytes(input.readableBytes());
        }

        @Override
        public void serialize(ByteBuf output) {
            throw new UnsupportedOperationException("Reserved packet id cannot be emitted");
        }
    }

    private static int readVarInt(ByteBuf input) {
        int value = 0;
        for (int index = 0; index < 5; index++) {
            int current = input.readUnsignedByte();
            value |= (current & 0x7F) << (index * 7);
            if ((current & 0x80) == 0) {
                return value;
            }
        }
        throw new IllegalArgumentException("Minecraft VarInt exceeds five bytes");
    }

    private static void writeVarInt(ByteBuf output, int value) {
        int remaining = value;
        do {
            int current = remaining & 0x7F;
            remaining >>>= 7;
            if (remaining != 0) {
                current |= 0x80;
            }
            output.writeByte(current);
        } while (remaining != 0);
    }

    private static String readString(ByteBuf input, int maximumCharacters) {
        int byteLength = readVarInt(input);
        int maximumBytes = maximumCharacters * 4;
        if (byteLength < 0 || byteLength > maximumBytes || byteLength > input.readableBytes()) {
            throw new IllegalArgumentException("Invalid Minecraft string length");
        }
        String value = input.readCharSequence(byteLength, StandardCharsets.UTF_8).toString();
        if (value.length() > maximumCharacters) {
            throw new IllegalArgumentException("Minecraft string exceeds character limit");
        }
        return value;
    }

    private static void writeString(ByteBuf output, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writeVarInt(output, bytes.length);
        output.writeBytes(bytes);
    }

    private static void requireEmpty(ByteBuf input) {
        if (input.isReadable()) {
            throw new IllegalArgumentException("Packet contains unexpected trailing bytes");
        }
    }
}
