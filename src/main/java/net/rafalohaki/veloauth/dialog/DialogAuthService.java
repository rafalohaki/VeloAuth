package net.rafalohaki.veloauth.dialog;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.command.DialogAuthBridge;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.i18n.MinecraftLocales;
import net.rafalohaki.veloauth.util.FloodgateDetector;
import net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * GUI authentication for Minecraft 1.21.6+ clients (protocol 771 … 777 / 26.3).
 *
 * <p>Life cycle of one connection:
 * <ol>
 *   <li>{@code PostLoginEvent}: the listener asks {@link #shouldHandle(Player)} and, when positive,
 *       prepares the session with {@link #begin(Player)} (click listener only, nothing shown).
 *       The player then takes VeloAuth's regular unauthenticated route to the auth server.</li>
 *   <li>{@code ServerConnectedEvent} on the auth server: a short "checking your account" action
 *       bar, then - depending on the database - the login or the registration form, in the
 *       client's language ({@link MinecraftLocales}). Clicks are executed through
 *       {@link DialogAuthBridge}, i.e. by the very same code the chat commands use (brute-force
 *       limits, IP limits, BCrypt, 2FA, audit…).</li>
 *   <li>On success VeloAuth's own post-auth flow transfers the player to the backend (as after
 *       {@code /login}); errors re-open the form behind a localized notice; the exit button and the
 *       timeouts disconnect the player. Typed commands / chat bring the form back.</li>
 *   <li>Premium nick without a record: the ownership check (action bar + Mojang profile key) and
 *       the "pick another name" notice run on the same auth server.</li>
 * </ol>
 */
public final class DialogAuthService implements DialogSessionHost {

    private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");
    private static final long KEEP_ALIVE_SECONDS = 10L;
    private static final long LOCALE_POLL_MILLIS = 50L;
    private static final int MAX_PENDING_CLICKS = 4;
    private final com.github.benmanes.caffeine.cache.Cache<String, String> recentLanguages =
            com.github.benmanes.caffeine.cache.Caffeine.newBuilder()
                    .maximumSize(10_000)
                    .expireAfterWrite(java.time.Duration.ofHours(6))
                    .build();
    static final int NOTICE_TIMEOUT_SECONDS = 30;
    static final String PREMIUM_NAME_KICK_KEY = "connection.premium_name.kick";
    /** Kick after the notice: "Kicked from {0}" with the configured network name. */
    static final String PREMIUM_NAME_KICKED_KEY = "connection.premium_name.kicked";

    private final VeloAuth plugin;
    private final ProxyServer server;
    private final Logger logger;
    private final Settings settings;
    private final Messages messages;
    private final VelocityDialogTransport transport;
    private final DialogAuthBridge bridge;
    private final DialogForms forms;
    private final DialogForwardingGuard forwarding;
    private final DialogFormFlow formFlow;
    private final PremiumCheckFlow premiumCheckFlow;
    private final ConcurrentHashMap<UUID, DialogSession> sessions = new ConcurrentHashMap<>();
    private final Set<UUID> authenticatedPreJoin = ConcurrentHashMap.newKeySet();
    /** Connections that used a dialog (form, check or notice): no plugin chat lines for them. */
    private final Set<UUID> dialogConnections = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean closed = new AtomicBoolean();

    public DialogAuthService(VeloAuth plugin, Settings settings, Messages messages,
                             VelocityDialogTransport transport, DialogAuthBridge bridge) {
        this.plugin = plugin;
        this.server = plugin.getServer();
        this.logger = plugin.getLogger();
        this.settings = settings;
        this.messages = messages;
        this.transport = transport;
        this.bridge = bridge;
        this.forms = new DialogForms(messages, settings, () -> bridge.passwordSettings().maxLength());
        this.forwarding = new DialogForwardingGuard(plugin, bridge::isAuthenticated, closed::get);
        this.formFlow = new DialogFormFlow(bridge, forms, transport, messages, settings, logger, this);
        this.premiumCheckFlow = new PremiumCheckFlow(plugin, settings, transport, forms, messages, this);
    }

    // ------------------------------------------------------------------ public API

    /** Whether the feature is switched on and the proxy supports it. */
    public boolean isEnabled() {
        return !closed.get() && settings.getDialogSettings().isEnabled() && transport.isAvailable();
    }

    /**
     * Decides whether this freshly logged-in connection should authenticate through a dialog.
     * Premium (Mojang-verified) and Floodgate players never need it; clients older than 1.21.6
     * cannot display dialogs and keep the classic flow.
     */
    public boolean shouldHandle(Player player) {
        if (!isEnabled() || player == null || !player.isActive()) {
            return false;
        }
        if (player.isOnlineMode()) {
            return false;
        }
        if (FloodgateDetector.isBedrockPlayer(player.getUniqueId())) {
            return false;
        }
        if (bridge.isAuthenticated(player)) {
            return false;
        }
        return transport.supports(player);
    }

    /**
     * Prepares the dialog session for a cracked connection. Nothing is shown yet: the player is
     * routed by VeloAuth's regular unauthenticated flow to the auth server (the waiting place) and
     * {@link #onServerConnected} opens the login / register form there, exactly where the
     * premium-name notice appears. The click listener is attached now so no click can be missed.
     * The returned future completes when the session ends.
     */
    public CompletableFuture<Void> begin(Player player) {
        DialogSession session = newSession(player);
        if (!transport.attachClickListener(player, click -> onClick(session, click))) {
            logger.warn(AUTH_MARKER, "Dialog login unavailable for {} - falling back to the auth server flow",
                    player.getUsername());
            session.finish();
            return session.done;
        }
        markDialogConnection(player);
        if (logger.isDebugEnabled()) {
            logger.debug(AUTH_MARKER, "Dialog session prepared for {} - form opens on the auth server",
                    player.getUsername());
        }
        return session.done;
    }

    /** The GUI replaces chat: plugin/auth-server chat lines are filtered until the backend. */
    private void markDialogConnection(Player player) {
        dialogConnections.add(player.getUniqueId());
        transport.muteChat(player);
    }

    /** True while the player has an open login / register form session (not a notice). */
    public boolean isFormSession(UUID playerId) {
        DialogSession session = playerId == null ? null : sessions.get(playerId);
        return session != null && !session.noticeOnly && session.premiumCheck == null && !session.finished.get();
    }

    /**
     * Re-opens the current form after the player typed a command or chat message instead of
     * using the dialog. A player who meanwhile authenticated (e.g. via {@code /login}) ends the
     * session; VeloAuth's own post-auth flow transfers them.
     */
    public void reshowForm(UUID playerId) {
        DialogSession session = playerId == null ? null : sessions.get(playerId);
        if (session == null || session.noticeOnly || session.premiumCheck != null
                || session.finished.get() || !session.formShown) {
            return;
        }
        if (bridge.isAuthenticated(session.player)) {
            transport.clear(session.player);
            session.finish();
            return;
        }
        runAsync(session, () -> formFlow.showForm(session, session.form));
    }

    /** Auth-server arrival of a prepared form session: the form opens immediately. */
    private void startFormInPlay(DialogSession session) {
        Player player = session.player;
        if (session.finished.get() || !player.isActive()) {
            return;
        }
        if (bridge.isAuthenticated(player)) {
            session.finish(); // session auto-login etc. - VeloAuth transfers the player itself
            return;
        }
        resolveAndRememberLanguage(session);
        session.timeoutTask = server.getScheduler()
                .buildTask(plugin, () -> onTimeout(session))
                .delay(settings.getDialogSettings().getTimeoutSeconds(), TimeUnit.SECONDS)
                .schedule();
        runAsync(session, () -> showInitialForm(session));
    }

    /**
     * True when this player can receive dialogs at all (1.21.6+ Java client in CONFIGURATION),
     * regardless of authentication state.
     */
    public boolean supportsDialogs(Player player) {
        // Independent of dialog.format: notices are shown as a GUI even in chat_system mode.
        return !closed.get() && transport.isAvailable() && player != null && player.isActive()
                && !FloodgateDetector.isBedrockPlayer(player.getUniqueId())
                && transport.supports(player);
    }

    /**
     * Shows a localized "this nickname belongs to a premium account" notice and disconnects the
     * player when they acknowledge it (or after a short timeout). The connection is never
     * authenticated; the returned future completes when the player is gone.
     */
    public CompletableFuture<Void> showPremiumNameNotice(Player player) {
        DialogSession session = newSession(player);
        session.noticeOnly = true;
        if (!transport.attachClickListener(player, click -> onClick(session, click))) {
            disconnect(session, PREMIUM_NAME_KICK_KEY, player.getUsername());
            return session.done;
        }
        session.keepAliveTask = server.getScheduler()
                .buildTask(plugin, () -> transport.keepAlive(player))
                .delay(KEEP_ALIVE_SECONDS, TimeUnit.SECONDS)
                .repeat(KEEP_ALIVE_SECONDS, TimeUnit.SECONDS)
                .schedule();
        session.timeoutTask = server.getScheduler()
                .buildTask(plugin, () -> disconnect(session, PREMIUM_NAME_KICK_KEY, player.getUsername()))
                .delay(NOTICE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .schedule();
        awaitLanguageThenShow(session);
        return session.done;
    }

    // ------------------------------------------------------------------ premium ownership check

    /**
     * Starts the premium-nick ownership check for an offline connection whose nickname belongs to
     * a Mojang account that has no VeloAuth record yet. Called from PostLogin (CONFIGURATION):
     * the listener is attached now so the client's profile-key packet - sent right after it
     * enters PLAY on the auth server - cannot be missed. Velocity then routes the player to the
     * auth server as usual; once there a centred "checking your account" dialog is shown, and
     * after at most {@code dialog.premium-name-notice.check-seconds}:
     * <ul>
     *   <li>a Mojang-signed profile key for exactly {@code premiumUuid} was seen → the connection
     *       is proven to belong to the premium owner: {@code onVerified} runs (the listener
     *       re-admits the player through the normal Mojang-verified premium flow);</li>
     *   <li>otherwise → cracked client: the localized "pick another name" notice, button → kick.</li>
     * </ul>
     * Nothing is ever authenticated inside this session.
     */
    public CompletableFuture<Void> beginPremiumCheck(Player player, UUID premiumUuid, Runnable onVerified) {
        DialogSession session = newSession(player);
        session.noticeOnly = true;
        DialogSession.PremiumCheck check = new DialogSession.PremiumCheck(premiumUuid, onVerified);
        session.premiumCheck = check;
        boolean attached = transport.attachClickListener(player,
                click -> onClick(session, click),
                raw -> premiumCheckFlow.onRawPacket(session, raw));
        if (!attached) {
            disconnect(session, PREMIUM_NAME_KICK_KEY, player.getUsername());
            return session.done;
        }
        markDialogConnection(player);
        // 26.2+ clients send their Mojang profile key only when Login(play) says onlineMode=true;
        // Velocity fills that flag from the (offline) connection, so it is rewritten for this check.
        transport.forceOnlineModeInJoinGame(player);
        int checkSeconds = Math.max(1, settings.getDialogSettings().getPremiumCheckSeconds());
        // Hard limit: if the player never reaches the auth server (or the key never comes) the
        // check still ends with the notice, and the notice itself ends with a kick.
        session.timeoutTask = server.getScheduler()
                .buildTask(plugin, () -> premiumCheckFlow.decide(session))
                .delay(checkSeconds + NOTICE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .schedule();
        if (logger.isInfoEnabled()) {
            logger.info(AUTH_MARKER, "[PREMIUM CHECK] Waiting for {} to reach the auth server to verify ownership of premium nick (profile {})",
                    player.getUsername(), premiumUuid);
        }
        return session.done;
    }

    /** True when the Mojang session public key is bundled, i.e. profile keys can be verified. */
    public boolean isPremiumCheckAvailable() {
        return net.rafalohaki.veloauth.premium.MojangProfileKeyVerifier.isAvailable();
    }

    /** True while the player is looking at the premium-name notice (or still being checked). */
    public boolean isPremiumNameNotice(UUID playerId) {
        DialogSession session = playerId == null ? null : sessions.get(playerId);
        return session != null && session.noticeOnly && !session.finished.get();
    }

    /**
     * Re-opens the notice for a player who tried to get around it (chat, {@code /login},
     * {@code /register}, ...). The dialog is the only thing this connection may interact with.
     */
    public void reshowPremiumNameNotice(UUID playerId) {
        DialogSession session = playerId == null ? null : sessions.get(playerId);
        if (session == null || !session.noticeOnly || session.finished.get() || session.premiumCheck != null) {
            return;
        }
        if (session.language == null) {
            session.language = resolveLanguage(session.player);
        }
        transport.show(session.player, forms.premiumName(session.language, session.player.getUsername()));
    }

    public boolean isPremiumCheck(UUID playerId) {
        DialogSession session = playerId == null ? null : sessions.get(playerId);
        return session != null && session.premiumCheck != null && !session.finished.get();
    }

    /** Resolves the message language for a player exactly like the dialog flow does. */
    public String languageFor(Player player) {
        return resolveLanguage(player);
    }

    /**
     * Last language resolved for {@code ip|nick}, or {@code null}. Lets pre-login denials (brute
     * force block, etc.) - where the client has not sent its settings yet - reuse the language
     * seen in the player's previous dialog session.
     */
    public String rememberedLanguage(String ip, String nickname) {
        if (ip == null || nickname == null) {
            return null;
        }
        return recentLanguages.getIfPresent(ip + '|' + nickname.toLowerCase(Locale.ROOT));
    }

    @Override
    public void resolveAndRememberLanguage(DialogSession session) {
        session.language = resolveLanguage(session.player);
        rememberLanguage(session.player, session.language);
    }

    private void rememberLanguage(Player player, String language) {
        if (language == null) {
            return;
        }
        recentLanguages.put(net.rafalohaki.veloauth.util.PlayerAddressUtils.getPlayerIp(player)
                + '|' + player.getUsername().toLowerCase(Locale.ROOT), language);
    }

    /** True while the player is inside a dialog session and not yet on any server. */
    public boolean isPreJoinSession(UUID playerId) {
        DialogSession session = playerId == null ? null : sessions.get(playerId);
        return session != null && !session.finished.get() && session.player.getCurrentServer().isEmpty();
    }

    /**
     * Consumes the "authenticated via dialog" mark for the initial server connection. Returns
     * {@code true} exactly once per successful dialog session, and only while the authorization is
     * still valid.
     */
    public boolean consumeAuthenticated(Player player) {
        if (player == null || !authenticatedPreJoin.contains(player.getUniqueId())) {
            return false;
        }
        // The mark stays until the player actually reaches a server (see onServerConnected) so a
        // retried initial connection is still routed to the backend instead of the auth server.
        return bridge.isAuthenticated(player);
    }

    /**
     * Server arrival: premium check / form session continue on the auth server, end elsewhere.
     *
     * @return {@code true} when a dialog-format connection reached a backend server - the chat
     *         filter ends there and the caller must not send the classic chat welcome
     */
    public boolean onServerConnected(Player player, boolean authServer) {
        if (player == null) {
            return false;
        }
        UUID playerId = player.getUniqueId();
        authenticatedPreJoin.remove(playerId);
        boolean backendReached = !authServer && dialogConnections.contains(playerId);
        if (backendReached) {
            // Backend reached: the backend's own chat must arrive again.
            transport.unmuteChat(player);
        }
        DialogSession session = sessions.get(playerId);
        if (session != null && !session.finished.get()) {
            continueSessionOnServer(session, authServer);
        }
        return backendReached;
    }

    private void continueSessionOnServer(DialogSession session, boolean authServer) {
        if (session.premiumCheck != null) {
            premiumCheckFlow.onInPlay(session);
        } else if (!session.noticeOnly) {
            // The notice itself stays open wherever the player is.
            continueFormOnServer(session, authServer);
        }
    }

    private void continueFormOnServer(DialogSession session, boolean authServer) {
        if (authServer) {
            startFormInPlay(session);
        } else {
            transport.clear(session.player);
            session.finish();
        }
    }

    /** Clears per-connection state when the player leaves. */
    public void onDisconnect(UUID playerId) {
        authenticatedPreJoin.remove(playerId);
        dialogConnections.remove(playerId);
        DialogSession session = sessions.get(playerId);
        if (session != null) {
            session.finish();
        }
    }

    public void shutdown() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        sessions.values().forEach(DialogSession::finish);
        sessions.clear();
        authenticatedPreJoin.clear();
        dialogConnections.clear();
    }

    public int activeSessions() {
        return sessions.size();
    }

    // ------------------------------------------------------------------ language

    @Override
    public void awaitLanguageThenShow(DialogSession session) {
        long deadline = System.nanoTime()
                + TimeUnit.MILLISECONDS.toNanos(settings.getDialogSettings().getLocaleWaitMillis());
        resolveLanguageThenShow(session, deadline);
    }

    private void resolveLanguageThenShow(DialogSession session, long deadlineNanos) {
        if (session.finished.get()) {
            return;
        }
        Player player = session.player;
        if (!player.isActive()) {
            session.finish();
            return;
        }
        if (hasClientSettings(player) || System.nanoTime() >= deadlineNanos) {
            resolveAndRememberLanguage(session);
            if (logger.isDebugEnabled()) {
                logger.debug(AUTH_MARKER, "Dialog language for {}: client={} -> {}",
                        player.getUsername(), MinecraftLocales.toMinecraftCode(clientLocale(player)), session.language);
            }
            runAsync(session, () -> showInitialForm(session));
            return;
        }
        server.getScheduler()
                .buildTask(plugin, () -> resolveLanguageThenShow(session, deadlineNanos))
                .delay(LOCALE_POLL_MILLIS, TimeUnit.MILLISECONDS)
                .schedule();
    }

    private static boolean hasClientSettings(Player player) {
        try {
            return player.hasSentPlayerSettings();
        } catch (RuntimeException | LinkageError olderApi) {
            return player.getEffectiveLocale() != null;
        }
    }

    private static Locale clientLocale(Player player) {
        try {
            Locale locale = player.getEffectiveLocale();
            if (locale == null && player.getPlayerSettings() != null) {
                locale = player.getPlayerSettings().getLocale();
            }
            return locale;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private String resolveLanguage(Player player) {
        String fallback = messages.getCurrentLanguage();
        if (!settings.isDetectClientLanguage()) {
            return fallback;
        }
        return MinecraftLocales.resolve(clientLocale(player), messages::isLanguageSupported, fallback);
    }

    // ------------------------------------------------------------------ forms

    private void showInitialForm(DialogSession session) {
        if (session.premiumCheck != null) {
            premiumCheckFlow.showActionBar(session);
            return;
        }
        if (session.noticeOnly) {
            if (logger.isInfoEnabled()) {
                logger.info(AUTH_MARKER, "Showing premium-name notice to cracked client {} (language {})",
                        session.player.getUsername(), session.language);
            }
            if (!transport.show(session.player, forms.premiumName(session.language, session.player.getUsername()))) {
                disconnect(session, PREMIUM_NAME_KICK_KEY, session.player.getUsername());
            }
            return;
        }
        formFlow.showInitialForm(session);
    }

    private Component text(String language, String key, NamedTextColor color, Object... args) {
        return messages.componentForLanguage(language, key, color, args);
    }

    // ------------------------------------------------------------------ clicks

    private void onClick(DialogSession session, DialogClick click) {
        if (session.finished.get()) {
            return;
        }
        // Clicks are processed strictly in order on a per-session chain. A dialog response is
        // sent *inside* the previous step, so a fast client may answer before that step has
        // fully returned - queueing (instead of dropping) keeps such clicks.
        if (session.pending.incrementAndGet() > MAX_PENDING_CLICKS) {
            session.pending.decrementAndGet();
            if (logger.isDebugEnabled()) {
                logger.debug(AUTH_MARKER, "Ignoring dialog click '{}' from {} - too many queued actions",
                        click.action(), session.player.getUsername());
            }
            return;
        }
        session.chainLock.lock();
        try {
            session.chain = session.chain.handle((ignored, throwable) -> null).thenRunAsync(() -> {
                try {
                    if (!session.finished.get()) {
                        handleClick(session, click);
                    }
                } finally {
                    session.pending.decrementAndGet();
                }
            }, VirtualThreadExecutorProvider.getVirtualExecutor()).exceptionally(throwable -> {
                logger.error(AUTH_MARKER, "Dialog authentication step failed for {}",
                        session.player.getUsername(), throwable);
                disconnect(session, "connection.error.generic");
                return null;
            });
        } finally {
            session.chainLock.unlock();
        }
    }

    private void handleClick(DialogSession session, DialogClick click) {
        if (logger.isDebugEnabled()) {
            logger.debug(AUTH_MARKER, "Dialog click '{}' from {} (form {})", click.action(),
                    session.player.getUsername(), session.form);
        }
        if (session.premiumCheck != null) {
            return; // still checking - the dialog has no actionable button
        }
        if (session.noticeOnly) {
            handleNoticeClick(session, click);
        } else {
            formFlow.handleClick(session, click);
        }
    }

    private void handleNoticeClick(DialogSession session, DialogClick click) {
        // Single "Got it" button: the client closes the dialog itself (after_action=close) and the
        // proxy disconnects the connection right away. Nothing is authenticated.
        if (logger.isInfoEnabled()) {
            logger.info(AUTH_MARKER, "{} acknowledged premium-name notice ({}) - disconnecting",
                    session.player.getUsername(), click.action());
        }
        disconnect(session, PREMIUM_NAME_KICKED_KEY, settings.getDialogSettings().getServerName());
    }

    @Override
    public void authenticated(DialogSession session, Form form) {
        Player player = session.player;
        authenticatedPreJoin.add(player.getUniqueId());
        transport.clear(player);
        if (logger.isInfoEnabled()) {
            logger.info(AUTH_MARKER, "Player {} authenticated via dialog ({}, language {})",
                    player.getUsername(), form.name().toLowerCase(Locale.ROOT), session.language);
        }
        session.finish();
        forwarding.watch(player);
    }

    // ------------------------------------------------------------------ termination

    private void onTimeout(DialogSession session) {
        if (session.finished.get()) {
            return;
        }
        if (logger.isInfoEnabled()) {
            logger.info(AUTH_MARKER, "Player {} did not finish dialog authentication within {}s - disconnecting",
                    session.player.getUsername(), settings.getDialogSettings().getTimeoutSeconds());
        }
        disconnect(session, "dialog.timeout", settings.getDialogSettings().getTimeoutSeconds());
    }

    @Override
    public void disconnect(DialogSession session, String key, Object... args) {
        disconnect(session, text(session.language, key, NamedTextColor.RED, args));
    }

    @Override
    public void disconnect(DialogSession session, Component reason) {
        if (session.finished.get()) {
            return;
        }
        try {
            session.player.disconnect(reason);
        } catch (RuntimeException e) {
            logger.debug("Failed to disconnect {} from dialog: {}", session.player.getUsername(), e.toString());
        } finally {
            session.finish();
        }
    }

    @Override
    public boolean runAsync(DialogSession session, Runnable task) {
        try {
            CompletableFuture.runAsync(task, VirtualThreadExecutorProvider.getVirtualExecutor())
                    .exceptionally(throwable -> {
                        logger.error(AUTH_MARKER, "Dialog authentication step failed for {}",
                                session.player.getUsername(), throwable);
                        disconnect(session, "connection.error.generic");
                        return null;
                    });
            return true;
        } catch (RejectedExecutionException shuttingDown) {
            session.finish();
            return false;
        }
    }

    private DialogSession newSession(Player player) {
        DialogSession session = new DialogSession(player, messages.getCurrentLanguage(), this::releaseSession);
        DialogSession previous = sessions.put(player.getUniqueId(), session);
        if (previous != null) {
            previous.finish();
        }
        return session;
    }

    private void releaseSession(DialogSession session) {
        transport.detachClickListener(session.player);
        sessions.remove(session.player.getUniqueId(), session);
    }
}
