package app.choicefirst.eu.cloak

import android.content.Context
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
    fun clear()
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

    private val dao = EventDatabase.getDatabase(context).eventDao()

    // Single writer thread keeps Room inserts off the critical packet path.
    private val writer = Executors.newSingleThreadExecutor { r ->
        Thread(r, "cf-event-writer").apply { isDaemon = true }
    }

    override fun insert(event: BlockedEvent) {
        writer.execute { dao.insert(event) }
    }

    override fun query(since: Long, app: String?, limit: Int): List<BlockedEvent> =
        if (app != null) dao.queryByApp(since, app, limit) else dao.queryAll(since, limit)

    override fun appStats(since: Long): List<AppStat> = dao.appStats(since)

    override fun clear() {
        writer.execute { dao.clear() }
    }

    override fun trim(maxRows: Int) {
        writer.execute { dao.trimToLimit(maxRows) }
    }
}
