package net.rafalohaki.veloauth.command;

import net.rafalohaki.veloauth.config.Settings;

import java.nio.file.Path;

@SuppressWarnings("PMD.TestClassWithoutTestCases") // Test helper/stub, not a test class
class TestValidationSettings extends Settings {
    private final int minLen;
    private final int maxLen;
    private final PasswordPolicy policy;
    private boolean reportEnabled = true;
    private int ipLimitRegistrations = 3;

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

    @Override
    public PasswordSettings getPasswordSettings() {
        return new PasswordSettings(10, ipLimitRegistrations, minLen, maxLen, policy);
    }

    void setIpLimitRegistrationsForTesting(int limit) {
        ipLimitRegistrations = limit;
    }

    @Override
    public OperationSettings captureOperationSettings() {
        OperationSettings base = super.captureOperationSettings();
        return new OperationSettings(
                getPasswordSettings(),
                base.bruteForce(),
                base.premium(),
                base.floodgate(),
                base.twoFactor(),
                base.connection(),
                new ReportSettings(reportEnabled, base.report().includeLogs()),
                base.pendingRestartChanges());
    }

    void setReportEnabledForTesting(boolean enabled) {
        reportEnabled = enabled;
    }
}
