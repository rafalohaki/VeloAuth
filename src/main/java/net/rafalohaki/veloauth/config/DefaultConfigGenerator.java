package net.rafalohaki.veloauth.config;

import net.rafalohaki.veloauth.i18n.BuiltInLanguages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/** Copies the canonical bundled configuration for a new VeloAuth installation. */
final class DefaultConfigGenerator {

    private static final Logger logger = LoggerFactory.getLogger(DefaultConfigGenerator.class);
    private static final String DEFAULT_CONFIG_RESOURCE = "/default-config.yml";
    private static final String BUILT_IN_LANGUAGE_CODES_PLACEHOLDER =
            "__BUILT_IN_LANGUAGE_CODES__";

    private DefaultConfigGenerator() {}

    /**
     * Creates a new config file from the versioned resource. Existing operator files are never
     * overwritten, even if a caller races the normal existence check in {@link Settings#load()}.
     */
    static void createDefaultConfig(Path configFile) throws IOException {
        String defaultConfig;
        try (InputStream resource = DefaultConfigGenerator.class.getResourceAsStream(
                DEFAULT_CONFIG_RESOURCE)) {
            if (resource == null) {
                throw new IOException("Bundled default configuration resource is missing: "
                        + DEFAULT_CONFIG_RESOURCE);
            }
            defaultConfig = new String(resource.readAllBytes(), StandardCharsets.UTF_8)
                    .replace(BUILT_IN_LANGUAGE_CODES_PLACEHOLDER,
                            BuiltInLanguages.quotedCodeList());
        }

        Files.writeString(configFile, defaultConfig, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        logger.info("Created default configuration file");
    }

    /**
     * Configs written by VeloAuth &lt; 1.6.3 have no top-level {@code dialog:} section. Operator files
     * are never rewritten, so the defaults apply ({@code format: dialog}) and a one-time hint tells
     * the operator how to opt back into the classic chat flow.
     */
    static void warnIfDialogSectionMissing(Path configFile, Logger log) {
        try {
            String current = java.nio.file.Files.readString(configFile, StandardCharsets.UTF_8);
            if (java.util.regex.Pattern.compile("^dialog:\\s*$", java.util.regex.Pattern.MULTILINE)
                    .matcher(current).find()) {
                return;
            }
            log.info("config.yml has no 'dialog' section - using defaults (dialog.format=dialog: GUI login for "
                    + "1.21.6+ clients). To keep the classic /register & /login flow add:\n"
                    + "dialog:\n  format: chat_system\n"
                    + "(see default-config.yml inside the jar for all dialog.* options; /vauth reload applies it)");
        } catch (IOException | RuntimeException e) {
            log.debug("Could not inspect {} for a dialog section: {}", configFile, e.toString());
        }
    }
}
