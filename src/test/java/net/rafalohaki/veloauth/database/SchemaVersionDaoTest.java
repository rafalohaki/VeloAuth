package net.rafalohaki.veloauth.database;

import net.rafalohaki.veloauth.i18n.Messages;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SchemaVersionDaoTest {

    private DatabaseManager manager;
    private SchemaVersionDao dao;

    @BeforeEach
    void setUp() {
        Messages messages = new Messages();
        messages.setLanguage("en");
        DatabaseConfig config = DatabaseConfig.forLocalDatabase("H2", "schema_ver_test_" + System.nanoTime());
        manager = new DatabaseManager(config, messages);
        assertTrue(manager.initialize().join());
        dao = manager.getSchemaVersionDao();
    }

    @AfterEach
    void tearDown() {
        manager.shutdown();
    }

    @Test
    void baselineRowIsRecordedDuringInitialization() {
        Optional<Integer> current = dao.getCurrentVersion();
        assertTrue(current.isPresent());
        assertEquals(1, current.get());
        assertTrue(dao.hasVersion(1));
        assertFalse(dao.hasVersion(2));
    }

    @Test
    void recordVersion_isIdempotent() {
        assertTrue(dao.recordVersion(2, "2FA TOTP"));
        assertTrue(dao.recordVersion(2, "2FA TOTP"), "second insert with same version should be no-op true");
        assertEquals(2, dao.getCurrentVersion().orElse(-1));
    }
}
