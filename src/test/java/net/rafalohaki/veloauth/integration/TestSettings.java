package net.rafalohaki.veloauth.integration;

import net.rafalohaki.veloauth.config.Settings;

import java.nio.file.Path;

class TestSettings extends Settings {
    private final boolean debug;
    private final String pico;

    TestSettings(Path dataDirectory, boolean debug, String pico) {
        super(dataDirectory);
        this.debug = debug;
        this.pico = pico;
    }

    @Override
    public boolean isDebugEnabled() {
        return debug;
    }

    @Override
    public String getPicoLimboServerName() {
        return pico;
    }
}