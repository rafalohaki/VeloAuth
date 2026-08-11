package net.rafalohaki.veloauth;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PluginMetadataTest {

    @Test
    void velocityPluginJson_FloodgateDependency_declaresOptionalLoadOrder() throws IOException {
        try (InputStream input = getClass().getClassLoader().getResourceAsStream("velocity-plugin.json")) {
            assertNotNull(input, "velocity-plugin.json must be packaged");

            JsonObject metadata = JsonParser.parseReader(
                    new InputStreamReader(input, StandardCharsets.UTF_8)).getAsJsonObject();
            assertEquals(BuildConstants.VERSION, metadata.get("version").getAsString(),
                    "Filtered Velocity metadata and generated BuildConstants must share one version");

            boolean optionalFloodgateDependency = false;
            for (JsonElement element : metadata.getAsJsonArray("dependencies")) {
                JsonObject dependency = element.getAsJsonObject();
                if ("floodgate".equals(dependency.get("id").getAsString())
                        && dependency.get("optional").getAsBoolean()) {
                    optionalFloodgateDependency = true;
                    break;
                }
            }

            assertTrue(optionalFloodgateDependency,
                    "Floodgate must be an optional dependency so Velocity loads it before VeloAuth");
        }
    }
}
