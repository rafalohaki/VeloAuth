package net.rafalohaki.veloauth.report;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class McLogsClientTest {

    @Test
    void serializeBody_ContentAndMetadata_UsesProxyGsonWithoutLosingTypes() {
        byte[] serialized = McLogsClient.serializeBody(
                "line\n\"quoted\"",
                List.of(McLogsClient.MetadataEntry.visible("players", 7, "Players")));

        JsonObject root = JsonParser.parseString(
                new String(serialized, StandardCharsets.UTF_8)).getAsJsonObject();
        assertEquals("line\n\"quoted\"", root.get("content").getAsString());
        assertEquals("VeloAuth", root.get("source").getAsString());
        JsonObject metadata = root.getAsJsonArray("metadata").get(0).getAsJsonObject();
        assertEquals(7, metadata.get("value").getAsInt());
        assertTrue(metadata.get("visible").getAsBoolean());
    }

    @Test
    void parseResponse_SuccessAndFailures_ReturnTypedResult() {
        McLogsClient.UploadResult success = McLogsClient.parseResponse(
                "{\"success\":true,\"url\":\"https://mclo.gs/example\"}");
        assertTrue(success.success());
        assertEquals("https://mclo.gs/example", success.url());

        McLogsClient.UploadResult rejected = McLogsClient.parseResponse(
                "{\"success\":false,\"error\":\"rejected\"}");
        assertFalse(rejected.success());
        assertEquals("rejected", rejected.error());

        assertFalse(McLogsClient.parseResponse("[]").success());
        assertFalse(McLogsClient.parseResponse("not-json").success());
        assertFalse(McLogsClient.parseResponse("{\"success\":true}").success());
    }
}
