package net.rafalohaki.veloauth.config;

import net.rafalohaki.veloauth.i18n.BuiltInLanguages;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DefaultConfigGeneratorTest {

    private static final String LANGUAGE_CODES_PLACEHOLDER = "__BUILT_IN_LANGUAGE_CODES__";

    @TempDir
    private Path tempDirectory;

    @Test
    void createDefaultConfig_WritesCanonicalBundledResourceByteForByte() throws IOException {
        byte[] resourceBytes;
        try (InputStream resource = getClass().getResourceAsStream("/default-config.yml")) {
            assertNotNull(resource, "Canonical /default-config.yml resource is missing");
            resourceBytes = resource.readAllBytes();
        }
        String expected = new String(resourceBytes, StandardCharsets.UTF_8)
                .replace(LANGUAGE_CODES_PLACEHOLDER, BuiltInLanguages.quotedCodeList());
        Path generated = tempDirectory.resolve("config.yml");

        DefaultConfigGenerator.createDefaultConfig(generated);

        assertEquals(expected, Files.readString(generated, StandardCharsets.UTF_8));
    }

    @Test
    void createDefaultConfig_ExistingOperatorFile_IsNeverOverwritten() throws IOException {
        Path existing = tempDirectory.resolve("config.yml");
        String operatorConfig = "language: pl\ncustom-owner-value: true\n";
        Files.writeString(existing, operatorConfig, StandardCharsets.UTF_8);

        assertThrows(FileAlreadyExistsException.class,
                () -> DefaultConfigGenerator.createDefaultConfig(existing));
        assertEquals(operatorConfig, Files.readString(existing, StandardCharsets.UTF_8));
    }
}
