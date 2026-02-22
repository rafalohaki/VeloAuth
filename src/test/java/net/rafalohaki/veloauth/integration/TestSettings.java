package net.rafalohaki.veloauth.integration;

import net.rafalohaki.veloauth.config.Settings;

import java.nio.file.Path;

@SuppressWarnings("PMD.TestClassWithoutTestCases") // Test helper/stub, not a test class
class TestSettings extends Settings {
    private final boolean debug;
    private final String authServer;

    TestSettings(Path dataDirectory, boolean debug, String authServer) {
        super(dataDirectory);
        this.debug = debug;
        this.authServer = authServer;
    }

    @Override
    public boolean isDebugEnabled() {
        return debug;
    }

    @Override
    public String getAuthServerName() {
        return authServer;
    }
}