package net.rafalohaki.veloauth.command;

import net.rafalohaki.veloauth.config.Settings;

import java.nio.file.Path;

@SuppressWarnings("PMD.TestClassWithoutTestCases") // Test helper/stub, not a test class
class TestValidationSettings extends Settings {
    private final int minLen;
    private final int maxLen;
    private final PasswordPolicy policy;

    TestValidationSettings(Path dataDirectory, int minLen, int maxLen) {
        this(dataDirectory, minLen, maxLen, 0, 0, 0, 0);
    }

    TestValidationSettings(Path dataDirectory, int minLen, int maxLen,
                           int minDigits, int minUpper, int minLower, int minSpecial) {
        super(dataDirectory);
        this.minLen = minLen;
        this.maxLen = maxLen;
        this.policy = PasswordPolicy.forTesting(minDigits, minUpper, minLower, minSpecial);
    }

    @Override
    public int getMinPasswordLength() {
        return minLen;
    }

    @Override
    public int getMaxPasswordLength() {
        return maxLen;
    }

    @Override
    public PasswordPolicy getPasswordPolicy() {
        return policy;
    }
}