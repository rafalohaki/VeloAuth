package net.rafalohaki.veloauth.model;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

import java.util.Objects;

/**
 * Schema versioning marker stored in VELOAUTH_SCHEMA_VERSION.
 * One row per applied migration. The presence of this table itself
 * is a flag that VeloAuth >=1.3 has touched the schema; rollback to
 * an older binary simply ignores it.
 */
@DatabaseTable(tableName = "VELOAUTH_SCHEMA_VERSION")
public class SchemaVersion {

    @DatabaseField(columnName = "VERSION", id = true, canBeNull = false)
    private int version;

    @DatabaseField(columnName = "APPLIED_AT", canBeNull = false)
    private long appliedAt;

    @DatabaseField(columnName = "DESCRIPTION")
    private String description;

    public SchemaVersion() {
    }

    public SchemaVersion(int version, long appliedAt, String description) {
        this.version = version;
        this.appliedAt = appliedAt;
        this.description = description;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public long getAppliedAt() {
        return appliedAt;
    }

    public void setAppliedAt(long appliedAt) {
        this.appliedAt = appliedAt;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SchemaVersion that = (SchemaVersion) o;
        return version == that.version;
    }

    @Override
    public int hashCode() {
        return Objects.hash(version);
    }

    @Override
    public String toString() {
        return "SchemaVersion{version=" + version + ", appliedAt=" + appliedAt + ", description='" + description + "'}";
    }
}
