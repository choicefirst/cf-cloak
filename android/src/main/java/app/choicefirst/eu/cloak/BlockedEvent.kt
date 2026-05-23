package app.choicefirst.eu.cloak

import android.content.Context
import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

// ---------------------------------------------------------------------------
// Entity
// ---------------------------------------------------------------------------

/**
 * A single local VPN event — either a matched decision (`blocked`, `observed`,
 * `allowed_override`, `allowed_temp`) or a sampled allowed request
 * (`allow_sampled`, 1-in-100 rate).
 *
 * [domain]  — full queried hostname (e.g. "pixel.facebook.com")
 * [matched] — the blocklist suffix that triggered the decision (e.g. "facebook.com")
 * [registrableDomain] / [matchScope] — canonical rule identity details when available
 * [entityNamesJson] — JSON array of matched tracker/entity owner labels when available
 * [confidenceScore] / [reviewNotesJson] — richer canonical scoring and review context
 * [app]     — originating Android package (e.g. "com.instagram.android") or "unknown"
 * [category]/ [source] — populated when the blocklist carries rich metadata
 * [categoriesCsv] — comma-separated categories for the matched rule
 * [sourcesCsv] — comma-separated upstream source IDs for the matched rule
 * [blocklistVersion]/ [policyVersion] — runtime versions that produced this row
 * [confidenceTier]/ [compatibilityTagsCsv] — projected canonical-rule metadata
 * [action]  — `blocked` | `observed` | `allowed_override` | `allowed_temp` | `allow_sampled`
 * [reason]  — canonical local-event reason when the row came from a policy decision
 * [mode]    — `light` | `extreme` when the row came from a policy decision
 * [wouldBlockLight] / [wouldBlockExtreme] — shadow-mode preview flags for a staged
 * canonical ruleset while legacy enforcement remains active.
 *
 * This file is part of the cf-cloak open-source enforcement layer.
 * Licensed under AGPLv3. See the repository root for full terms.
 */
@Entity(
    tableName = "events",
    indices = [
        Index(value = ["action", "ts"]),
        Index(value = ["matched", "ts"]),
        Index(value = ["app", "ts"]),
    ],
)
data class BlockedEvent(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    @ColumnInfo(index = true) val ts: Long,         // epoch millis
    @ColumnInfo(index = true) val domain: String,   // full queried hostname
    val matched: String,                            // matched blocklist suffix
    @ColumnInfo(name = "registrable_domain") val registrableDomain: String? = null,
    @ColumnInfo(name = "match_scope") val matchScope: String? = null,
    @ColumnInfo(name = "entity_names") val entityNamesJson: String? = null,
    @ColumnInfo(name = "confidence_score") val confidenceScore: Double? = null,
    @ColumnInfo(index = true) val app: String,      // originating package or "unknown"
    val category: String?,                          // e.g. "analytics", "ads"
    @ColumnInfo(name = "categories") val categoriesCsv: String? = null,
    val source: String?,                            // blocklist source identifier
    @ColumnInfo(name = "sources") val sourcesCsv: String? = null,
    @ColumnInfo(name = "blocklist_version") val blocklistVersion: String? = null,
    @ColumnInfo(name = "policy_version") val policyVersion: Int? = null,
    @ColumnInfo(name = "confidence_tier") val confidenceTier: String? = null,
    @ColumnInfo(name = "compatibility_tags") val compatibilityTagsCsv: String? = null,
    @ColumnInfo(name = "review_notes") val reviewNotesJson: String? = null,
    val action: String,
    val reason: String? = null,
    val mode: String? = null,
    @ColumnInfo(name = "would_block_light") val wouldBlockLight: Boolean? = null,
    @ColumnInfo(name = "would_block_extreme") val wouldBlockExtreme: Boolean? = null,
)

// ---------------------------------------------------------------------------
// DAO
// ---------------------------------------------------------------------------

/** Aggregate local event count per app, sorted by count descending. */
data class AppStat(val app: String, val count: Int)

/** Aggregate local event counts per day/action, sorted by day descending. */
data class DailyEventStat(val dayStartTs: Long, val action: String, val count: Int)

@Entity(
    tableName = "daily_event_counts",
    primaryKeys = ["day_start_ts", "action"],
    indices = [
        Index(value = ["action", "day_start_ts"]),
    ],
)
data class DailyEventCount(
    @ColumnInfo(name = "day_start_ts") val dayStartTs: Long,
    val action: String,
    val count: Int = 0,
)

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

    @Query(
        "INSERT OR IGNORE INTO daily_event_counts(day_start_ts, action, count) " +
        "VALUES(:dayStartTs, :action, 0)"
    )
    fun ensureDailyCount(dayStartTs: Long, action: String)

    @Query(
        "UPDATE daily_event_counts SET count = count + 1 " +
        "WHERE day_start_ts = :dayStartTs AND action = :action"
    )
    fun incrementDailyCount(dayStartTs: Long, action: String)

    @Query(
        "SELECT day_start_ts AS dayStartTs, action, count FROM daily_event_counts " +
        "WHERE day_start_ts >= :since ORDER BY day_start_ts DESC, action ASC"
    )
    fun dailyStatsSince(since: Long): List<DailyEventStat>

    @Query(
        "SELECT day_start_ts AS dayStartTs, action, count FROM daily_event_counts " +
        "WHERE day_start_ts >= :since AND action = :action ORDER BY day_start_ts DESC"
    )
    fun dailyStatsSinceByAction(since: Long, action: String): List<DailyEventStat>

    @Query("DELETE FROM events")
    fun clear()

    @Query("DELETE FROM daily_event_counts")
    fun clearDailyStats()

    @Query("DELETE FROM events WHERE ts < :cutoffTs")
    fun deleteOlderThan(cutoffTs: Long)

    @Query("DELETE FROM daily_event_counts WHERE day_start_ts < :cutoffTs")
    fun deleteDailyOlderThan(cutoffTs: Long)

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

@Database(entities = [BlockedEvent::class, DailyEventCount::class], version = 12, exportSchema = false)
abstract class EventDatabase : RoomDatabase() {
    abstract fun eventDao(): EventDao

    companion object {
        @Volatile private var INSTANCE: EventDatabase? = null

        private val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE events ADD COLUMN reason TEXT")
                db.execSQL("ALTER TABLE events ADD COLUMN mode TEXT")
                db.execSQL(
                    "UPDATE events SET action = CASE action " +
                        "WHEN 'BLOCK' THEN 'blocked' " +
                        "WHEN 'ALLOW_SAMPLED' THEN 'allow_sampled' " +
                        "ELSE action END"
                )
            }
        }

        private val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE events ADD COLUMN confidence_tier TEXT")
                db.execSQL("ALTER TABLE events ADD COLUMN compatibility_tags TEXT")
            }
        }

        private val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE events ADD COLUMN sources TEXT")
            }
        }

        private val MIGRATION_4_5 = object : Migration(4, 5) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE events ADD COLUMN blocklist_version TEXT")
                db.execSQL("ALTER TABLE events ADD COLUMN policy_version INTEGER")
            }
        }

        private val MIGRATION_5_6 = object : Migration(5, 6) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE events ADD COLUMN categories TEXT")
            }
        }

        private val MIGRATION_6_7 = object : Migration(6, 7) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE events ADD COLUMN registrable_domain TEXT")
                db.execSQL("ALTER TABLE events ADD COLUMN match_scope TEXT")
            }
        }

        private val MIGRATION_7_8 = object : Migration(7, 8) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE events ADD COLUMN entity_names TEXT")
            }
        }

        private val MIGRATION_8_9 = object : Migration(8, 9) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE events ADD COLUMN confidence_score REAL")
                db.execSQL("ALTER TABLE events ADD COLUMN review_notes TEXT")
            }
        }

        private val MIGRATION_9_10 = object : Migration(9, 10) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("CREATE INDEX IF NOT EXISTS index_events_action_ts ON events(action, ts)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_events_matched_ts ON events(matched, ts)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_events_app_ts ON events(app, ts)")
            }
        }

        private val MIGRATION_10_11 = object : Migration(10, 11) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `daily_event_counts` (" +
                        "`day_start_ts` INTEGER NOT NULL, " +
                        "`action` TEXT NOT NULL, " +
                        "`count` INTEGER NOT NULL, " +
                        "PRIMARY KEY(`day_start_ts`, `action`))"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS index_daily_event_counts_action_day_start_ts " +
                        "ON daily_event_counts(action, day_start_ts)"
                )
            }
        }

        private val MIGRATION_11_12 = object : Migration(11, 12) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE events ADD COLUMN would_block_light INTEGER")
                db.execSQL("ALTER TABLE events ADD COLUMN would_block_extreme INTEGER")
            }
        }

        fun getDatabase(context: Context): EventDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    EventDatabase::class.java,
                    "cf_events.db",
                ).addMigrations(
                    MIGRATION_1_2,
                    MIGRATION_2_3,
                    MIGRATION_3_4,
                    MIGRATION_4_5,
                    MIGRATION_5_6,
                    MIGRATION_6_7,
                    MIGRATION_7_8,
                    MIGRATION_8_9,
                    MIGRATION_9_10,
                    MIGRATION_10_11,
                    MIGRATION_11_12,
                ).build().also { INSTANCE = it }
            }
        }
    }
}
