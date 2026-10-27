package net.rafalohaki.veloauth.dialog;

import com.velocitypowered.api.proxy.Player;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufHolder;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelPipeline;
import io.netty.util.ReferenceCountUtil;
import net.kyori.adventure.nbt.CompoundBinaryTag;
import org.slf4j.Logger;

import java.io.IOException;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.util.function.Consumer;

/**
 * Sends dialogs to, and receives dialog clicks from, a client that is still in the
 * CONFIGURATION phase (i.e. before Velocity has connected it to any backend).
 *
 * <p>Velocity's public API declares {@code Player#showDialog} but does not implement it, so this
 * class talks to a handful of well-known proxy internals (identical on Velocity 3.4.x, 3.5.x and
 * 4.x). All internal access is resolved once, through method handles, and any failure disables
 * the dialog feature with a clear log line instead of breaking authentication; the classic
 * auth-server + {@code /login} flow is always available as fallback.
 *
 * <p>Protocol facts (1.21.6 / protocol 771 up to 26.3 / protocol 777):
 * <ul>
 *   <li>clientbound {@code show_dialog} in CONFIGURATION carries the dialog NBT directly
 *       (no registry holder), id {@code 0x12} (771-776) / {@code 0x13} (777);</li>
 *   <li>clientbound {@code clear_dialog} id {@code 0x11} (771-776) / {@code 0x12} (777);</li>
 *   <li>serverbound {@code custom_click_action} id {@code 0x08}: identifier + length-prefixed
 *       optional NBT payload.</li>
 * </ul>
 * Velocity registers these packets itself; VeloAuth prefers Velocity's own packet classes so new
 * protocol ids are picked up automatically and only falls back to the table above when needed.
 */
public final class VelocityDialogTransport {

    /** First protocol version that understands dialogs (Minecraft 1.21.6). */
    public static final int MIN_DIALOG_PROTOCOL = 771;
    /** Minecraft 26.3. */
    public static final int PROTOCOL_26_3 = 777;
    /** Minecraft 26.1 (26.2 = 776 shares its ids). */
    public static final int PROTOCOL_26_1 = 775;
    /** Minecraft 1.21.9 (1.21.11 = 774 shares its ids). */
    public static final int PROTOCOL_1_21_9 = 773;

    private static final String HANDLER_NAME = "veloauth-dialog-click";
    private static final String MINECRAFT_DECODER = "minecraft-decoder";
    private static final String MINECRAFT_ENCODER = "minecraft-encoder";
    private static final String JOIN_GAME_HANDLER_NAME = "veloauth-joingame-online";
    private static final String CHAT_MUTE_HANDLER_NAME = "veloauth-chat-mute";
    private static final String CLS_SYSTEM_CHAT = "com.velocitypowered.proxy.protocol.packet.chat.SystemChatPacket";
    private static final String CLS_JOIN_GAME = "com.velocitypowered.proxy.protocol.packet.JoinGamePacket";
    private static final String CLS_CONNECTED_PLAYER = "com.velocitypowered.proxy.connection.client.ConnectedPlayer";
    private static final String CLS_MINECRAFT_CONNECTION = "com.velocitypowered.proxy.connection.MinecraftConnection";
    private static final String CLS_STATE_REGISTRY = "com.velocitypowered.proxy.protocol.StateRegistry";
    private static final String CLS_DIALOG_SHOW = "com.velocitypowered.proxy.protocol.packet.DialogShowPacket";
    private static final String CLS_DIALOG_CLEAR = "com.velocitypowered.proxy.protocol.packet.DialogClearPacket";
    private static final String CLS_CUSTOM_CLICK = "com.velocitypowered.proxy.protocol.packet.ServerboundCustomClickActionPacket";
    /** NBT tag id of TAG_Compound; kept as a literal to avoid BinaryTagType method calls (see writeNbt). */

    private final Logger logger;
    private final boolean available;
    private final String unavailableReason;

    // Resolved internals (null when unavailable)
    private final Class<?> connectedPlayerClass;
    private final MethodHandle getConnection;
    private final MethodHandle sendKeepAlive;
    private final MethodHandle connectionWrite;
    private final MethodHandle connectionGetChannel;
    private final MethodHandle connectionGetState;
    private final MethodHandle connectionIsClosed;
    private final Object stateConfig;
    private final Object statePlay;
    private final MethodHandle dialogShowCtor;      // (StateRegistry) -> DialogShowPacket, may be null
    private final Field dialogShowNbtField;         // may be null
    private final Field dialogShowIdField;          // may be null
    private final Object dialogClearInstance;       // may be null
    private final Class<?> customClickClass;

    public VelocityDialogTransport(Logger logger) {
        this.logger = logger;
        Internals resolved = null;
        String reason = null;
        try {
            resolved = resolveInternals(logger);
        } catch (ReflectiveOperationException | RuntimeException e) {
            reason = e.toString();
        }
        Internals safe = resolved == null ? Internals.NONE : resolved;
        this.connectedPlayerClass = safe.connectedPlayerClass();
        this.getConnection = safe.getConnection();
        this.sendKeepAlive = safe.sendKeepAlive();
        this.connectionWrite = safe.connectionWrite();
        this.connectionGetChannel = safe.connectionGetChannel();
        this.connectionGetState = safe.connectionGetState();
        this.connectionIsClosed = safe.connectionIsClosed();
        this.stateConfig = safe.stateConfig();
        this.statePlay = safe.statePlay();
        this.customClickClass = safe.customClickClass();
        this.dialogShowCtor = safe.packets().showCtor();
        this.dialogShowNbtField = safe.packets().nbtField();
        this.dialogShowIdField = safe.packets().idField();
        this.dialogClearInstance = safe.packets().clearInstance();
        this.available = resolved != null;
        this.unavailableReason = reason;
        if (available) {
            logger.info("Dialog transport ready (velocity internals: {}, encoder: {})",
                    "ok", dialogShowCtor != null ? "velocity-packets" : "raw");
        } else {
            logger.warn("Dialog transport unavailable - GUI login disabled, classic /login flow stays active: {}", reason);
        }
    }

    /** Resolved Velocity internals; all members non-null except in {@link #NONE}. */
    private record Internals(Class<?> connectedPlayerClass, MethodHandle getConnection, MethodHandle sendKeepAlive,
                             MethodHandle connectionWrite, MethodHandle connectionGetChannel,
                             MethodHandle connectionGetState, MethodHandle connectionIsClosed, Object stateConfig,
                             Object statePlay, Class<?> customClickClass, DialogPackets packets) {
        static final Internals NONE = new Internals(null, null, null, null, null, null, null, null, null, null,
                DialogPackets.NONE);
    }

    /** Velocity's own dialog packet classes (preferred encoder); {@link #NONE} when absent. */
    private record DialogPackets(MethodHandle showCtor, Field nbtField, Field idField, Object clearInstance) {
        static final DialogPackets NONE = new DialogPackets(null, null, null, null);
    }

    private static Internals resolveInternals(Logger logger) throws ReflectiveOperationException {
        ClassLoader loader = Player.class.getClassLoader();
        MethodHandles.Lookup lookup = MethodHandles.publicLookup();
        Class<?> cpClass = Class.forName(CLS_CONNECTED_PLAYER, false, loader);
        Class<?> mcClass = Class.forName(CLS_MINECRAFT_CONNECTION, false, loader);
        Class<?> stateClass = Class.forName(CLS_STATE_REGISTRY, false, loader);
        Class<?> clickClass = Class.forName(CLS_CUSTOM_CLICK, false, loader);
        Object config = null;
        Object play = null;
        for (Object constant : stateClass.getEnumConstants()) {
            String name = ((Enum<?>) constant).name();
            if ("CONFIG".equals(name)) {
                config = constant;
            } else if ("PLAY".equals(name)) {
                play = constant;
            }
        }
        if (config == null || play == null) {
            throw new IllegalStateException("StateRegistry.CONFIG/PLAY not found");
        }
        return new Internals(
                cpClass,
                lookup.findVirtual(cpClass, "getConnection", MethodType.methodType(mcClass)),
                lookup.findVirtual(cpClass, "sendKeepAlive", MethodType.methodType(void.class)),
                lookup.findVirtual(mcClass, "write", MethodType.methodType(io.netty.channel.ChannelFuture.class, Object.class)),
                lookup.findVirtual(mcClass, "getChannel", MethodType.methodType(Channel.class)),
                lookup.findVirtual(mcClass, "getState", MethodType.methodType(stateClass)),
                lookup.findVirtual(mcClass, "isClosed", MethodType.methodType(boolean.class)),
                config,
                play,
                clickClass,
                resolveDialogPackets(logger, loader, lookup, stateClass));
    }

    // DialogShowPacket keeps its id/nbt behind package-private setters-less fields; writing them
    // reflectively is the only way to reuse Velocity's own encoder (which is the most robust
    // option across protocol versions). Falls back to raw encoding when inaccessible.
    @SuppressWarnings("PMD.AvoidAccessibilityAlteration")
    private static DialogPackets resolveDialogPackets(Logger logger, ClassLoader loader,
                                                      MethodHandles.Lookup lookup, Class<?> stateClass) {
        try {
            Class<?> showClass = Class.forName(CLS_DIALOG_SHOW, false, loader);
            MethodHandle showCtor = lookup.findConstructor(showClass, MethodType.methodType(void.class, stateClass));
            Field nbtField = showClass.getDeclaredField("nbt");
            nbtField.setAccessible(true);
            Field idField = showClass.getDeclaredField("id");
            idField.setAccessible(true);
            Class<?> clearClass = Class.forName(CLS_DIALOG_CLEAR, false, loader);
            Object clearInstance = clearClass.getField("INSTANCE").get(null);
            return new DialogPackets(showCtor, nbtField, idField, clearInstance);
        } catch (ReflectiveOperationException | RuntimeException optional) {
            logger.debug("Velocity dialog packet classes unavailable, using raw packet encoding: {}",
                    optional.toString());
            return DialogPackets.NONE;
        }
    }

    /**
     * Rewrites the {@code onlineMode} flag of the clientbound Login (play) packet to {@code true}
     * for this connection. Since 26.2 the client prepares and sends its Mojang profile key only
     * when that flag is set; Velocity copies it from the connection, which is offline during the
     * premium ownership check. Older Velocity builds without the flag are a no-op.
     *
     * @return {@code true} when the rewriter is installed
     */
    public boolean forceOnlineModeInJoinGame(Player player) {
        try {
            ClassLoader loader = Player.class.getClassLoader();
            Class<?> joinGameClass = Class.forName(CLS_JOIN_GAME, false, loader);
            java.lang.reflect.Method setter;
            try {
                setter = joinGameClass.getMethod("setOnlineMode", boolean.class);
            } catch (NoSuchMethodException older) {
                return false;
            }
            Object connection = openConnection(player);
            if (connection == null) {
                return false;
            }
            ChannelPipeline pipeline = pipelineOf(connection);
            if (pipeline.get(JOIN_GAME_HANDLER_NAME) != null) {
                return true;
            }
            ChannelOutboundHandlerAdapter rewriter = new ChannelOutboundHandlerAdapter() {
                @Override
                public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
                    if (joinGameClass.isInstance(msg)) {
                        try {
                            setter.invoke(msg, true);
                        } catch (ReflectiveOperationException | RuntimeException e) {
                            logger.debug("JoinGame onlineMode rewrite failed: {}", e.toString());
                        }
                    }
                    super.write(ctx, msg, promise);
                }
            };
            if (pipeline.get(MINECRAFT_ENCODER) != null) {
                pipeline.addAfter(MINECRAFT_ENCODER, JOIN_GAME_HANDLER_NAME, rewriter);
            } else {
                pipeline.addLast(JOIN_GAME_HANDLER_NAME, rewriter);
            }
            return true;
        } catch (Throwable t) {
            logger.debug("Cannot install JoinGame rewriter for {}: {}", player.getUsername(), t.toString());
            return false;
        }
    }

    /**
     * Stops plain chat lines (clientbound {@code system_chat} without the action-bar overlay) from
     * reaching this player while a dialog session is on screen: the GUI replaces every chat
     * instruction, and neither VeloAuth's nor the auth server's chat spam should appear behind
     * the form. Action bars, titles and dialogs are unaffected. Idempotent.
     */
    public boolean muteChat(Player player) {
        try {
            ClassLoader loader = connectedPlayerClass.getClassLoader();
            Class<?> systemChatClass = Class.forName(CLS_SYSTEM_CHAT, false, loader);
            java.lang.reflect.Method getType = systemChatClass.getMethod("getType");
            Object connection = openConnection(player);
            if (connection == null) {
                return false;
            }
            ChannelPipeline pipeline = pipelineOf(connection);
            if (pipeline.get(CHAT_MUTE_HANDLER_NAME) != null) {
                return true;
            }
            ChannelOutboundHandlerAdapter mute = new ChannelOutboundHandlerAdapter() {
                @Override
                public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
                    if (systemChatClass.isInstance(msg) && isPlainChat(msg)) {
                        promise.trySuccess();
                        return;
                    }
                    super.write(ctx, msg, promise);
                }

                private boolean isPlainChat(Object packet) {
                    try {
                        Object type = getType.invoke(packet);
                        return type == null || !"GAME_INFO".equals(String.valueOf(type));
                    } catch (ReflectiveOperationException | RuntimeException e) {
                        return false;
                    }
                }
            };
            if (pipeline.get(MINECRAFT_ENCODER) != null) {
                pipeline.addAfter(MINECRAFT_ENCODER, CHAT_MUTE_HANDLER_NAME, mute);
            } else {
                pipeline.addLast(CHAT_MUTE_HANDLER_NAME, mute);
            }
            return true;
        } catch (Throwable t) {
            logger.debug("Cannot mute chat for {}: {}", player.getUsername(), t.toString());
            return false;
        }
    }

    /** Removes the chat filter installed by {@link #muteChat}. */
    public void unmuteChat(Player player) {
        try {
            removeHandler(player, CHAT_MUTE_HANDLER_NAME);
        } catch (Throwable t) {
            logger.debug("Cannot unmute chat for {}: {}", player.getUsername(), t.toString());
        }
    }

    /** Whether the proxy internals needed for dialogs were found. */
    public boolean isAvailable() {
        return available;
    }

    public String unavailableReason() {
        return unavailableReason;
    }

    /** Whether this connection can receive dialogs right now (supported client, CONFIG or PLAY phase). */
    public boolean supports(Player player) {
        if (!available || player == null || !connectedPlayerClass.isInstance(player)) {
            return false;
        }
        if (player.getProtocolVersion().getProtocol() < MIN_DIALOG_PROTOCOL) {
            return false;
        }
        try {
            Object connection = openConnection(player);
            if (connection == null) {
                return false;
            }
            return dialogState(connectionGetState.invoke(connection)) != null;
        } catch (Throwable t) {
            logger.debug("Cannot inspect connection state of {}: {}", player.getUsername(), t.toString());
            return false;
        }
    }

    /**
     * Returns the state constant when dialogs can be sent in it. CONFIG uses Velocity's own
     * packet classes; PLAY uses raw frames because Velocity registers {@code DialogShowPacket} /
     * {@code DialogClearPacket} for CONFIG only (writing them in PLAY fails silently).
     */
    private Object dialogState(Object state) {
        if (stateConfig.equals(state)) {
            return stateConfig;
        }
        if (statePlay.equals(state)) {
            return statePlay;
        }
        return null;
    }

    /** Whether the raw PLAY dialog frames are known for this protocol. */
    static boolean supportsPlayDialogs(int protocol) {
        return protocol >= MIN_DIALOG_PROTOCOL && protocol <= PROTOCOL_26_3;
    }

    /** Sends (or replaces) the dialog currently displayed by the client. */
    public boolean show(Player player, CompoundBinaryTag dialog) {
        return sendDialogPacket(player, "send dialog to", (state, protocol) -> statePlay.equals(state)
                ? DialogPacketCodec.rawPlayShowPacket(protocol, dialog)
                : buildShowPacket(player, dialog, state));
    }

    /** Closes whatever dialog the client is showing. */
    public boolean clear(Player player) {
        return sendDialogPacket(player, "clear dialog for", (state, protocol) -> {
            if (statePlay.equals(state)) {
                return DialogPacketCodec.rawPacket(DialogPacketCodec.playClearDialogId(protocol), null);
            }
            return dialogClearInstance != null
                    ? dialogClearInstance
                    : DialogPacketCodec.rawPacket(DialogPacketCodec.clearDialogId(protocol), null);
        });
    }

    /** Builds a dialog packet for the connection's current state (CONFIG or PLAY). */
    @FunctionalInterface
    private interface DialogPacketFactory {
        Object create(Object state, int protocol) throws Throwable;
    }

    private boolean sendDialogPacket(Player player, String action, DialogPacketFactory factory) {
        try {
            Object connection = openConnection(player);
            if (connection == null) {
                return false;
            }
            Object state = dialogState(connectionGetState.invoke(connection));
            int protocol = player.getProtocolVersion().getProtocol();
            if (state == null || (statePlay.equals(state) && !supportsPlayDialogs(protocol))) {
                return false;
            }
            connectionWrite.invoke(connection, factory.create(state, protocol));
            return true;
        } catch (Throwable t) {
            logger.debug("Failed to {} {}: {}", action, player.getUsername(), t.toString());
            return false;
        }
    }

    /** Sends a keep-alive so neither side's read timeout fires while the player types. */
    public void keepAlive(Player player) {
        try {
            sendKeepAlive.invoke(player);
        } catch (Throwable t) {
            logger.debug("Keep-alive to {} failed: {}", player.getUsername(), t.toString());
        }
    }

    /**
     * Installs a pipeline handler that consumes {@code veloauth:*} custom click actions for this
     * connection and forwards everything else untouched. Idempotent per connection.
     *
     * @return {@code true} when the handler is (now) installed
     */
    public boolean attachClickListener(Player player, Consumer<DialogClick> listener) {
        return attachClickListener(player, listener, null);
    }

    /**
     * Like {@link #attachClickListener(Player, Consumer)} but additionally lets {@code rawListener}
     * inspect (never consume) every serverbound packet Velocity does not decode itself, e.g. the
     * {@code chat_session_update} profile-key packet.
     */
    public boolean attachClickListener(Player player, Consumer<DialogClick> listener,
                                       Consumer<ByteBuf> rawListener) {
        try {
            Object connection = getConnection.invoke(player);
            if (connection == null) {
                return false;
            }
            ChannelPipeline pipeline = pipelineOf(connection);
            if (pipeline.get(HANDLER_NAME) != null) {
                return true;
            }
            ClickInterceptor interceptor = new ClickInterceptor(listener, rawListener, connection,
                    player.getProtocolVersion().getProtocol());
            if (pipeline.get(MINECRAFT_DECODER) != null) {
                pipeline.addAfter(MINECRAFT_DECODER, HANDLER_NAME, interceptor);
            } else {
                pipeline.addLast(HANDLER_NAME, interceptor);
            }
            return true;
        } catch (Throwable t) {
            logger.warn("Failed to attach dialog click listener for {}: {}", player.getUsername(), t.toString());
            return false;
        }
    }

    /** Removes the click handler installed by {@link #attachClickListener}. */
    public void detachClickListener(Player player) {
        try {
            removeHandler(player, HANDLER_NAME);
        } catch (Throwable t) {
            logger.debug("Failed to detach dialog click listener for {}: {}", player.getUsername(), t.toString());
        }
    }

    // ------------------------------------------------------------------ connection helpers

    /** The player's Velocity connection, or {@code null} when absent or already closed. */
    private Object openConnection(Player player) throws Throwable {
        Object connection = getConnection.invoke(player);
        if (connection == null || (boolean) connectionIsClosed.invoke(connection)) {
            return null;
        }
        return connection;
    }

    private ChannelPipeline pipelineOf(Object connection) throws Throwable {
        Channel channel = (Channel) connectionGetChannel.invoke(connection);
        return channel.pipeline();
    }

    private void removeHandler(Player player, String handlerName) throws Throwable {
        Object connection = getConnection.invoke(player);
        if (connection == null) {
            return;
        }
        ChannelPipeline pipeline = pipelineOf(connection);
        if (pipeline.get(handlerName) != null) {
            pipeline.remove(handlerName);
        }
    }

    // ------------------------------------------------------------------ encoding helpers

    private Object buildShowPacket(Player player, CompoundBinaryTag dialog, Object state) throws Throwable {
        if (dialogShowCtor != null) {
            Object packet = dialogShowCtor.invoke(state);
            dialogShowIdField.setInt(packet, 0);
            dialogShowNbtField.set(packet, dialog);
            return packet;
        }
        return DialogPacketCodec.rawPacket(DialogPacketCodec.showDialogId(player.getProtocolVersion().getProtocol()), dialog);
    }

    /** Netty handler placed right after Velocity's packet decoder. */
    private final class ClickInterceptor extends ChannelInboundHandlerAdapter {
        private final Consumer<DialogClick> listener;
        private final Consumer<ByteBuf> rawListener;
        private final Object connection;
        private final int protocol;

        private ClickInterceptor(Consumer<DialogClick> listener, Consumer<ByteBuf> rawListener,
                                 Object connection, int protocol) {
            this.listener = listener;
            this.rawListener = rawListener;
            this.connection = connection;
            this.protocol = protocol;
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            DialogClick click = null;
            if (msg instanceof ByteBuf raw && !(msg instanceof ByteBufHolder)) {
                offerRaw(raw);
                // Velocity decodes custom_click_action in CONFIG only; in PLAY it passes through raw.
                click = parsePlayClick(raw);
            } else if (customClickClass.isInstance(msg) && msg instanceof ByteBufHolder holder) {
                click = parseConfigClick(holder);
            }
            if (click == null) {
                ctx.fireChannelRead(msg);
                return;
            }
            ReferenceCountUtil.release(msg);
            try {
                listener.accept(click);
            } catch (RuntimeException e) {
                logger.warn("Dialog click handler failed", e);
            }
        }

        private void offerRaw(ByteBuf raw) {
            if (rawListener == null) {
                return;
            }
            try {
                rawListener.accept(raw.duplicate());
            } catch (RuntimeException e) {
                logger.debug("Raw packet listener failed: {}", e.toString());
            }
        }

        private DialogClick parseConfigClick(ByteBufHolder holder) {
            try {
                return DialogPacketCodec.parseClick(holder.content().duplicate());
            } catch (IOException | RuntimeException e) {
                logger.debug("Ignoring malformed custom click action: {}", e.toString());
                return null;
            }
        }

        private DialogClick parsePlayClick(ByteBuf raw) {
            try {
                if (!statePlay.equals(connectionGetState.invoke(connection))) {
                    return null;
                }
                ByteBuf body = raw.duplicate();
                if (DialogPacketCodec.readVarInt(body) != DialogPacketCodec.playCustomClickId(protocol)) {
                    return null;
                }
                return DialogPacketCodec.parseClick(body);
            } catch (Throwable notOurs) {
                return null;
            }
        }

        @Override
        public boolean isSharable() {
            return false;
        }
    }
}
