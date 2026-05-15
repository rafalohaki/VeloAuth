package net.rafalohaki.veloauth.audit;

import net.rafalohaki.veloauth.database.AuditLogDao;
import net.rafalohaki.veloauth.database.DatabaseConfig;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditLogServiceTest {

    private DatabaseManager manager;
    private AuditLogDao dao;

    @BeforeEach
    void setUp() {
        Messages messages = new Messages();
        messages.setLanguage("en");
        DatabaseConfig config = DatabaseConfig.forLocalDatabase("H2", "audit_test_" + System.nanoTime());
        manager = new DatabaseManager(config, messages);
        assertTrue(manager.initialize().join(), "DB should initialize");
        dao = manager.getAuditLogDao();
        assertNotNull(dao, "AuditLogDao should be available after init");
    }

    @AfterEach
    void tearDown() {
        manager.shutdown();
    }

    @Test
    void record_persistsEntryAsync() throws Exception {
        AuditLogService service = new AuditLogService(dao, true);

        service.record(AuditEventType.LOGIN_OK, "alice", "127.0.0.1", "smoke");

        waitForCount(1L, dao);
        assertEquals(1L, dao.count());
    }

    @Test
    void record_isNoOpWhenDisabled() throws Exception {
        AuditLogService service = new AuditLogService(dao, false);

        service.record(AuditEventType.LOGIN_FAIL, "bob", "10.0.0.1", "bad pass");

        // give the executor a moment in case something slipped through
        TimeUnit.MILLISECONDS.sleep(100);
        assertEquals(0L, dao.count());
        assertFalse(service.isEnabled());
    }

    @Test
    void prune_removesEntriesOlderThanRetention() {
        AuditLogService service = new AuditLogService(dao, true);
        long now = System.currentTimeMillis();
        long oldTimestamp = now - TimeUnit.DAYS.toMillis(120);

        dao.record(new net.rafalohaki.veloauth.model.AuditLogEntry(
                "LOGIN_OK", "old", "1.1.1.1", oldTimestamp, null));
        dao.record(new net.rafalohaki.veloauth.model.AuditLogEntry(
                "LOGIN_OK", "fresh", "1.1.1.2", now, null));
        assertEquals(2L, dao.count());

        int pruned = service.prune(90);
        assertEquals(1, pruned);
        assertEquals(1L, dao.count());
    }

    private void waitForCount(long expected, AuditLogDao dao) throws InterruptedException {
        AtomicLong observed = new AtomicLong(-1L);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (System.nanoTime() < deadline) {
            observed.set(dao.count());
            if (observed.get() >= expected) {
                return;
            }
            TimeUnit.MILLISECONDS.sleep(25);
        }
        assertEquals(expected, observed.get(), "Audit log did not reach expected count in time");
    }
}
