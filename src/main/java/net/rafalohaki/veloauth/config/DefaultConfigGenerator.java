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
}
