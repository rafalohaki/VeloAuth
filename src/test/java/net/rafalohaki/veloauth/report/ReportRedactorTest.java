package net.rafalohaki.veloauth.report;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link ReportRedactor}.
 * Verifies that secrets in YAML ({@code config.yml}) and TOML ({@code velocity.toml})
 * are redacted before upload, and that non-secret values are preserved.
 */
class ReportRedactorTest {

    @Test
    void redactYaml_quotedPassword_replaced() {
        String input = "database:\n  password: \"mySecret123\"\n  user: veloauth\n";

        String result = ReportRedactor.redact(input);

        assertTrue(result.contains("password: \"<redacted>\""), () -> "Expected redacted password, got: " + result);
        assertFalse(result.contains("mySecret123"), () -> "Secret leaked in: " + result);
        assertTrue(result.contains("user: veloauth"), () -> "Non-secret user was redacted: " + result);
    }

    @Test
    void redactYaml_unquotedPassword_replaced() {
        String input = "  password: mySecret123\n";

        String result = ReportRedactor.redact(input);

        assertTrue(result.contains("password: <redacted>"), () -> "Expected redacted password, got: " + result);
        assertFalse(result.contains("mySecret123"), () -> "Secret leaked in: " + result);
    }

    @Test
    void redactYaml_emptyPassword_replaced() {
        String input = "  password: \"\"\n";

        String result = ReportRedactor.redact(input);

        assertTrue(result.contains("password: \"<redacted>\""), () -> "Expected redacted empty password, got: " + result);
    }

    @Test
    void redactYaml_singleQuotedPassword_replaced() {
        String input = "  password: 'mySecret'\n";

        String result = ReportRedactor.redact(input);

        assertTrue(result.contains("password: '<redacted>'"), () -> "Expected single-quoted redacted, got: " + result);
        assertFalse(result.contains("mySecret"), () -> "Secret leaked in: " + result);
    }

    @Test
    void redactYaml_webhookUrl_replaced() {
        String input = "discord:\n  webhook-url: \"https://discord.com/api/webhooks/123/abc\"\n";

        String result = ReportRedactor.redact(input);

        assertTrue(result.contains("webhook-url: \"<redacted>\""), () -> "Expected redacted webhook, got: " + result);
        assertFalse(result.contains("discord.com/api/webhooks"), () -> "Webhook URL leaked in: " + result);
    }

    @Test
    void redactYaml_sslPassword_replaced() {
        String input = "  ssl-password: \"sslSecret\"\n";

        String result = ReportRedactor.redact(input);

        assertTrue(result.contains("ssl-password: \"<redacted>\""), () -> "Expected redacted ssl-password, got: " + result);
        assertFalse(result.contains("sslSecret"), () -> "SSL password leaked in: " + result);
    }

    @Test
    void redactToml_forwardingSecret_replaced() {
        String input = "forwarding-secret = \"mySecret\"\n";

        String result = ReportRedactor.redact(input);

        assertTrue(result.contains("forwarding-secret = \"<redacted>\""), () -> "Expected redacted forwarding-secret, got: " + result);
        assertFalse(result.contains("mySecret"), () -> "Forwarding secret leaked in: " + result);
    }

    @Test
    void redactToml_secret_replaced() {
        String input = "secret = \"mySecret\"\n";

        String result = ReportRedactor.redact(input);

        assertTrue(result.contains("secret = \"<redacted>\""), () -> "Expected redacted secret, got: " + result);
        assertFalse(result.contains("mySecret"), () -> "Secret leaked in: " + result);
    }

    @Test
    void redact_connectionUrlWithCredentials_credentialsReplaced() {
        String input = "  connection-url: \"postgresql://user:pass@host:5432/db\"\n";

        String result = ReportRedactor.redact(input);

        assertFalse(result.contains("user:pass@"), () -> "URL credentials leaked in: " + result);
        assertTrue(result.contains("postgresql://<redacted>@host:5432/db"), () -> "Expected redacted URL, got: " + result);
    }

    @Test
    void redact_connectionUrlWithoutCredentials_preserved() {
        String input = "  connection-url: \"postgresql://host:5432/db\"\n";

        String result = ReportRedactor.redact(input);

        assertTrue(result.contains("postgresql://host:5432/db"), () -> "URL without creds was modified: " + result);
    }

    @Test
    void redact_nonSecretValues_preserved() {
        String input = "  server-name: limbo\n  port: 3306\n  debug-enabled: true\n";

        String result = ReportRedactor.redact(input);

        assertTrue(result.contains("server-name: limbo"), () -> "Non-secret was modified: " + result);
        assertTrue(result.contains("port: 3306"), () -> "Non-secret was modified: " + result);
        assertTrue(result.contains("debug-enabled: true"), () -> "Non-secret was modified: " + result);
    }

    @Test
    void redact_fullVeloAuthConfig_secretsRedactedNonSecretsPreserved() {
        String input = """
                database:
                  storage-type: "postgresql"
                  host: "localhost"
                  port: 5432
                  database: "veloauth"
                  user: "veloauth_user"
                  password: "superSecretDbPassword"
                  connection-url: "postgresql://veloauth_user:superSecretDbPassword@localhost:5432/veloauth"
                alerts:
                  discord:
                    enabled: true
                    webhook-url: "https://discord.com/api/webhooks/999/tokenXYZ"
                ping-timeout-ms: 5000
                debug-enabled: false
                """;

        String result = ReportRedactor.redact(input);

        // Secrets redacted
        assertFalse(result.contains("superSecretDbPassword"), "DB password leaked");
        assertFalse(result.contains("discord.com/api/webhooks/999/tokenXYZ"), "Webhook URL leaked");
        // Non-secrets preserved
        assertTrue(result.contains("storage-type: \"postgresql\""), "DB type was modified");
        assertTrue(result.contains("host: \"localhost\""), "Host was modified");
        assertTrue(result.contains("port: 5432"), "Port was modified");
        assertTrue(result.contains("user: \"veloauth_user\""), "User was modified");
        assertTrue(result.contains("ping-timeout-ms: 5000"), "Ping timeout was modified");
        assertTrue(result.contains("debug-enabled: false"), "Debug flag was modified");
    }

    @Test
    void redact_nullInput_returnsNull() {
        assertEquals(null, ReportRedactor.redact(null));
    }

    @Test
    void redact_emptyInput_returnsEmpty() {
        assertEquals("", ReportRedactor.redact(""));
    }

    @Test
    void redact_passwordInComment_notRedacted() {
        // Comments starting with # should not be redacted — they are documentation, not values.
        // The regex anchors on ^\s*<key> which won't match a # prefix.
        String input = "# password: example-doc-password\n  password: \"realSecret\"\n";

        String result = ReportRedactor.redact(input);

        // The real password line is redacted
        assertTrue(result.contains("password: \"<redacted>\""), () -> "Real password not redacted: " + result);
        // The comment is preserved as-is (it's documentation, not a live secret)
        assertTrue(result.contains("# password: example-doc-password"), () -> "Comment was modified: " + result);
    }
}
