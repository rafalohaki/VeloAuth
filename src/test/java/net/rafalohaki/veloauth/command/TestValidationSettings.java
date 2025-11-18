package net.rafalohaki.veloauth.command;

import net.rafalohaki.veloauth.config.Settings;

import java.nio.file.Path;

class TestValidationSettings extends Settings {
    private final int minLen;
    private final int maxLen;

    TestValidationSettings(Path dataDirectory, int minLen, int maxLen) {
        super(dataDirectory);
        this.minLen = minLen;
        this.maxLen = maxLen;
    }

    @Override
    public int getMinPasswordLength() {
        return minLen;
    }

    @Override
    public int getMaxPasswordLength() {
        return maxLen;
    }
}