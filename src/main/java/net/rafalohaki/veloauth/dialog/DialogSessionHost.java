package net.rafalohaki.veloauth.dialog;

import net.kyori.adventure.text.Component;

/** Operations the dialog sub-flows need from the owning {@link DialogAuthService}. */
interface DialogSessionHost {

    /** Disconnects with the localized message {@code key} and ends the session. */
    void disconnect(DialogSession session, String key, Object... args);

    void disconnect(DialogSession session, Component reason);

    /** A form was answered correctly: VeloAuth considers the player authenticated. */
    void authenticated(DialogSession session, Form form);

    /** Resolves the client language into {@code session.language} and remembers it for the ip/nick. */
    void resolveAndRememberLanguage(DialogSession session);

    /** Waits (briefly) for the client settings, then shows the session's initial screen. */
    void awaitLanguageThenShow(DialogSession session);

    /** Runs {@code task} on a virtual thread; failures end the session with a generic error. */
    boolean runAsync(DialogSession session, Runnable task);
}
