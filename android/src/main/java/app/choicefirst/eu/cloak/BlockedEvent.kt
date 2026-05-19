package app.choicefirst.eu.cloak

import android.content.Context
import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase

// ---------------------------------------------------------------------------
// Entity
// ---------------------------------------------------------------------------

/**
 * A single network event — either a tracker domain that was blocked (BLOCK)
 * or a sample of allowed traffic (ALLOW_SAMPLED, 1-in-100 rate).
 *
 * [domain]  — full queried hostname (e.g. "pixel.facebook.com")
 * [matched] — the blocklist suffix that triggered the decision (e.g. "facebook.com")
 * [app]     — originating Android package (e.g. "com.instagram.android") or "unknown"
 * [category]/ [source] — populated when the blocklist carries rich metadata
 * [action]  — "BLOCK" | "ALLOW_SAMPLED"
 *
 * This file is part of the cf-cloak open-source enforcement layer.
 * Licensed under AGPLv3. See the repository root for full terms.
 */
@Entity(tableName = "events")
data class BlockedEvent(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    @ColumnInfo(index = true) val ts: Long,         // epoch millis
    @ColumnInfo(index = true) val domain: String,   // full queried hostname
    val matched: String,                            // matched blocklist suffix
    @ColumnInfo(index = true) val app: String,      // originating package or "unknown"
    val category: String?,                          // e.g. "analytics", "ads"
    val source: String?,                            // blocklist source identifier
    val action: String,                             // "BLOCK" | "ALLOW_SAMPLED"
)

// ---------------------------------------------------------------------------
// DAO
// ---------------------------------------------------------------------------

/** Aggregate blocked count per app, sorted by count descending. */
data class AppStat(val app: String, val count: Int)

@Dao
interface EventDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insert(event: BlockedEvent)

    @Query("SELECT * FROM events WHERE ts >= :since ORDER BY ts DESC LIMIT :limit")
    fun queryAll(since: Long, limit: Int): List<BlockedEvent>

    @Query("SELECT * FROM events WHERE ts >= :since AND app = :app ORDER BY ts DESC LIMIT :limit")
    fun queryByApp(since: Long, app: String, limit: Int): List<BlockedEvent>

    @Query(
        "SELECT app, COUNT(*) as count FROM events " +
        "WHERE ts >= :since GROUP BY app ORDER BY count DESC"
    )
    fun appStats(since: Long): List<AppStat>

    @Query("DELETE FROM events")
    fun clear()

    /**
     * Ring-buffer trim: keep only the [maxRows] most-recent events.
     * Called once at VPN startup to prevent unbounded growth.
     */
    @Query(
        "DELETE FROM events WHERE id NOT IN " +
        "(SELECT id FROM events ORDER BY ts DESC LIMIT :maxRows)"
    )
    fun trimToLimit(maxRows: Int)

    @Query("SELECT COUNT(*) FROM events")
    fun count(): Int
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

@Database(entities = [BlockedEvent::class], version = 1, exportSchema = false)
abstract class EventDatabase : RoomDatabase() {
    abstract fun eventDao(): EventDao

    companion object {
        @Volatile private var INSTANCE: EventDatabase? = null

        fun getDatabase(context: Context): EventDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    EventDatabase::class.java,
                    "cf_events.db",
                ).build().also { INSTANCE = it }
            }
        }
    }
}
