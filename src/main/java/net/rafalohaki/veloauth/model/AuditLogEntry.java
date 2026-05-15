package net.rafalohaki.veloauth.model;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

import java.util.Objects;

/**
 * Single audit log row in VELOAUTH_AUDIT_LOG.
 * Captures authentication-relevant events for forensics and admin tooling.
 * Async-written via {@code AuditLogService}; rows expire after a configurable
 * retention window.
 */
@DatabaseTable(tableName = "VELOAUTH_AUDIT_LOG")
public class AuditLogEntry {

    @DatabaseField(columnName = "ID", generatedId = true)
    private Long id;

    @DatabaseField(columnName = "EVENT_TYPE", canBeNull = false, width = 32)
    private String eventType;

    @DatabaseField(columnName = "PLAYER_LOWERCASE", width = 16)
    private String playerLowercase;

    @DatabaseField(columnName = "IP", width = 45)
    private String ip;

    @DatabaseField(columnName = "TIMESTAMP", canBeNull = false)
    private long timestamp;

    @DatabaseField(columnName = "DETAILS", width = 512)
    private String details;

    public AuditLogEntry() {
    }

    public AuditLogEntry(String eventType, String playerLowercase, String ip, long timestamp, String details) {
        this.eventType = eventType;
        this.playerLowercase = playerLowercase;
        this.ip = ip;
        this.timestamp = timestamp;
        this.details = details;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getPlayerLowercase() {
        return playerLowercase;
    }

    public void setPlayerLowercase(String playerLowercase) {
        this.playerLowercase = playerLowercase;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuditLogEntry that = (AuditLogEntry) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
