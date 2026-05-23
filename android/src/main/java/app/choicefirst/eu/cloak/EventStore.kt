package app.choicefirst.eu.cloak

import android.content.Context
import java.util.Calendar
import java.util.concurrent.Executors

/**
 * Abstraction over the local event persistence layer.
 *
 * The interface exists so the real Room-backed implementation can be
 * swapped for an in-memory fake in unit tests without involving Android.
 *
 * [query] and [appStats] may block — callers must ensure they run on a
 * background thread (not the main thread or the VPN packet-processing loop).
 *
 * This file is part of the cf-cloak open-source enforcement layer.
 * Licensed under AGPLv3. See the repository root for full terms.
 */
interface EventStore {
    fun insert(event: BlockedEvent)
    fun query(since: Long, app: String?, limit: Int): List<BlockedEvent>
    fun appStats(since: Long): List<AppStat>
    fun dailyStats(since: Long, action: String? = null): List<DailyEventStat>
    fun clear()
    fun deleteOlderThan(cutoffTs: Long)
    fun deleteDailyOlderThan(cutoffTs: Long)
    fun trim(maxRows: Int)
}

/**
 * Room-backed [EventStore].
 *
 * Writes are dispatched to a single-threaded background executor so they
 * never block the VPN packet loop. Reads are synchronous and must be called
 * from a background thread (the Capacitor bridge executor satisfies this).
 */
class RoomEventStore(context: Context) : EventStore {

    private val db = EventDatabase.getDatabase(context)
    private val dao = db.eventDao()

    // Single writer thread keeps Room inserts off the critical packet path.
    private val writer = Executors.newSingleThreadExecutor { r ->
        Thread(r, "cf-event-writer").apply { isDaemon = true }
    }

    override fun insert(event: BlockedEvent) {
        writer.execute {
            val dayStartTs = if (event.ts <= 0L) 0L else startOfLocalDay(event.ts)
            db.runInTransaction {
                dao.insert(event)
                dao.ensureDailyCount(dayStartTs, event.action)
                dao.incrementDailyCount(dayStartTs, event.action)
            }
        }
    }

    override fun query(since: Long, app: String?, limit: Int): List<BlockedEvent> =
        if (app != null) dao.queryByApp(since, app, limit) else dao.queryAll(since, limit)

    override fun appStats(since: Long): List<AppStat> = dao.appStats(since)

    override fun dailyStats(since: Long, action: String?): List<DailyEventStat> {
        val normalizedSince = if (since <= 0L) 0L else startOfLocalDay(since)
        return if (action != null) {
            dao.dailyStatsSinceByAction(normalizedSince, action)
        } else {
            dao.dailyStatsSince(normalizedSince)
        }
    }

    override fun clear() {
        writer.execute {
            db.runInTransaction {
                dao.clearDailyStats()
                dao.clear()
            }
        }
    }

    override fun deleteOlderThan(cutoffTs: Long) {
        writer.execute { dao.deleteOlderThan(cutoffTs) }
    }

    override fun deleteDailyOlderThan(cutoffTs: Long) {
        writer.execute { dao.deleteDailyOlderThan(cutoffTs) }
    }

    override fun trim(maxRows: Int) {
        writer.execute { dao.trimToLimit(maxRows) }
    }
}

internal fun startOfLocalDay(ts: Long): Long {
    val calendar = Calendar.getInstance()
    calendar.timeInMillis = ts
    calendar.set(Calendar.HOUR_OF_DAY, 0)
    calendar.set(Calendar.MINUTE, 0)
    calendar.set(Calendar.SECOND, 0)
    calendar.set(Calendar.MILLISECOND, 0)
    return calendar.timeInMillis
}

internal fun startOfLocalDayDaysAgo(now: Long, daysAgo: Int): Long {
    val calendar = Calendar.getInstance()
    calendar.timeInMillis = now
    calendar.set(Calendar.HOUR_OF_DAY, 0)
    calendar.set(Calendar.MINUTE, 0)
    calendar.set(Calendar.SECOND, 0)
    calendar.set(Calendar.MILLISECOND, 0)
    calendar.add(Calendar.DAY_OF_YEAR, -daysAgo)
    return calendar.timeInMillis
}
