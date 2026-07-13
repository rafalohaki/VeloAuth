package net.rafalohaki.veloauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PluginMetadataTest {

    @Test
    void velocityPluginJson_FloodgateDependency_declaresOptionalLoadOrder() throws IOException {
        try (InputStream input = getClass().getClassLoader().getResourceAsStream("velocity-plugin.json")) {
            assertNotNull(input, "velocity-plugin.json must be packaged");

            JsonNode dependencies = new ObjectMapper().readTree(input).path("dependencies");
            boolean optionalFloodgateDependency = false;
            for (JsonNode dependency : dependencies) {
                if ("floodgate".equals(dependency.path("id").asText())
                        && dependency.path("optional").asBoolean()) {
                    optionalFloodgateDependency = true;
                    break;
                }
            }

            assertTrue(optionalFloodgateDependency,
                    "Floodgate must be an optional dependency so Velocity loads it before VeloAuth");
        }
    }
}
