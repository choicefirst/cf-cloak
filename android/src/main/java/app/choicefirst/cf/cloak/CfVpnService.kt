package app.choicefirst.cf.cloak

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URL
import java.nio.ByteBuffer
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONArray
import org.json.JSONObject

/**
 * DNS-only VPN. We declare a tunnel with a non-routable DNS server address
 * (10.47.0.3) and route only that /32, so exclusively DNS traffic enters the
 * tunnel. Everything else uses Android's regular default route.
 *
 * For each DNS query we parse the QNAME:
 *   - suffix-match against the blocklist → synthesize NXDOMAIN, never leaves the device
 *   - otherwise → forward to UPSTREAM_DNS via a socket we protect() from the tunnel
 *
 * This is the same approach as DNS66 / early Blokada. It's not packet-level
 * blocking — an app that hardcodes an IP or uses DoH bypasses us. Tracker
 * endpoints overwhelmingly resolve via DNS, so this catches ~95% for ~5% of
 * the complexity of a full packet filter.
 *
 * This file is part of the cf-cloak open-source enforcement layer.
 * Licensed under AGPLv3. See the repository root for full terms.
 */
class CfVpnService : VpnService() {

    companion object {
        const val ACTION_START = "app.choicefirst.cf.vpn.START"
        const val ACTION_STOP = "app.choicefirst.cf.vpn.STOP"
        const val EXTRA_DOMAINS = "domains"
        const val EXTRA_VERSION = "version"
        const val EXTRA_SUPABASE_URL = "supabase_url"
        const val EXTRA_SUPABASE_ANON = "supabase_anon_key"
        const val EXTRA_AUTH_TOKEN = "auth_token"
        const val EXTRA_LOG_EVENTS = "log_events"

        private const val TAG = "CfVpn"
        private const val NOTIFICATION_ID = 42
        private const val CHANNEL_ID = "cf_vpn"
        private const val TUNNEL_LOCAL = "10.47.0.2"
        private const val TUNNEL_DNS_SINK = "10.47.0.3"
        private const val UPSTREAM_DNS = "1.1.1.1"
        private const val UPSTREAM_DNS_PORT = 53

        private const val QUEUE_MAX = 2_000
        private const val FLUSH_BATCH = 500
        private const val FLUSH_INTERVAL_SECONDS = 60L

        @Volatile private var active = false
        private val blockedCount = AtomicInteger(0)
        @Volatile private var blocklist: Set<String> = emptySet()
        @Volatile private var version: String = ""

        fun isActive() = active
        fun domainCount() = blocklist.size
        fun blockedInSession() = blockedCount.get()
        fun currentVersion() = version
    }

    private var tunnel: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private var worker: Thread? = null

    private var supabaseUrl: String = ""
    private var supabaseAnon: String = ""
    private var authToken: String = ""
    private var logEvents: Boolean = true

    private val eventQueue = ConcurrentLinkedDeque<Pair<String, String>>()
    private var flusher: ScheduledExecutorService? = null

    private fun nowIso(): String = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
        .apply { timeZone = TimeZone.getTimeZone("UTC") }
        .format(Date())

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                teardown()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val domains = intent.getStringArrayListExtra(EXTRA_DOMAINS) ?: arrayListOf()
                val v = intent.getStringExtra(EXTRA_VERSION) ?: ""
                supabaseUrl = intent.getStringExtra(EXTRA_SUPABASE_URL) ?: ""
                supabaseAnon = intent.getStringExtra(EXTRA_SUPABASE_ANON) ?: ""
                authToken = intent.getStringExtra(EXTRA_AUTH_TOKEN) ?: ""
                logEvents = intent.getBooleanExtra(EXTRA_LOG_EVENTS, true)
                startTunnel(domains, v)
                return START_STICKY
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        teardown()
        super.onDestroy()
    }

    private fun startTunnel(domains: List<String>, v: String) {
        teardown()

        blocklist = domains.map { it.lowercase().trim() }.filter { it.isNotEmpty() }.toSet()
        version = v
        blockedCount.set(0)

        ensureNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        val builder = Builder()
            .setSession("ChoiceFirst")
            .addAddress(TUNNEL_LOCAL, 32)
            .addDnsServer(TUNNEL_DNS_SINK)
            .addRoute(TUNNEL_DNS_SINK, 32)
            .setBlocking(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        tunnel = builder.establish() ?: return
        active = true
        running.set(true)

        worker = Thread({ runDnsLoop() }, "cf-vpn-dns").also { it.start() }
        startFlusher()
    }

    private fun teardown() {
        running.set(false)
        active = false
        worker?.interrupt()
        worker = null
        flusher?.shutdownNow()
        flusher = null
        try { tunnel?.close() } catch (_: Exception) {}
        tunnel = null
        try { flushEvents() } catch (_: Exception) {}
    }

    private fun startFlusher() {
        flusher?.shutdownNow()
        flusher = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "cf-vpn-flush").apply { isDaemon = true }
        }.also {
            it.scheduleWithFixedDelay(
                { runCatching { flushEvents() }.onFailure { e -> Log.w(TAG, "flush failed", e) } },
                FLUSH_INTERVAL_SECONDS,
                FLUSH_INTERVAL_SECONDS,
                TimeUnit.SECONDS,
            )
        }
    }

    private fun enqueueBlocked(matchedDomain: String) {
        if (!logEvents) return
        while (eventQueue.size >= QUEUE_MAX) eventQueue.pollFirst() ?: break
        eventQueue.addLast(matchedDomain to nowIso())
    }

    private fun flushEvents() {
        if (!logEvents) return
        if (supabaseUrl.isEmpty() || authToken.isEmpty()) return
        val batch = ArrayList<Pair<String, String>>(FLUSH_BATCH)
        while (batch.size < FLUSH_BATCH) {
            val e = eventQueue.pollFirst() ?: break
            batch.add(e)
        }
        if (batch.isEmpty()) return

        val body = JSONObject().apply {
            put("events", JSONArray().apply {
                for ((domain, ts) in batch) put(JSONObject().apply {
                    put("domain", domain)
                    put("ts", ts)
                })
            })
        }.toString()

        val url = URL("${supabaseUrl.trimEnd('/')}/functions/v1/log-blocked")
        val conn = (url.openConnection() as HttpURLConnection).apply {
            connectTimeout = 10_000
            readTimeout = 15_000
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Authorization", "Bearer $authToken")
            if (supabaseAnon.isNotEmpty()) setRequestProperty("apikey", supabaseAnon)
        }
        try {
            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { it.write(body) }
            val code = conn.responseCode
            if (code !in 200..299) {
                Log.w(TAG, "log-blocked returned $code; requeuing ${batch.size} events")
                for (i in batch.indices.reversed()) eventQueue.addFirst(batch[i])
            }
        } catch (e: Exception) {
            Log.w(TAG, "log-blocked post failed", e)
            for (i in batch.indices.reversed()) eventQueue.addFirst(batch[i])
        } finally {
            try { conn.disconnect() } catch (_: Exception) {}
        }
    }

    private fun runDnsLoop() {
        val fd = tunnel ?: return
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buffer = ByteArray(32 * 1024)

        while (running.get()) {
            val len = try {
                input.read(buffer)
            } catch (_: Exception) {
                break
            }
            if (len <= 0) continue

            val packet = buffer.copyOfRange(0, len)
            handlePacket(packet, output)
        }

        try { input.close() } catch (_: Exception) {}
        try { output.close() } catch (_: Exception) {}
    }

    private fun handlePacket(packet: ByteArray, out: FileOutputStream) {
        if (packet.size < 28) return
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return
        val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 17) return // UDP
        if (packet.size < ipHeaderLen + 8) return

        val udpStart = ipHeaderLen
        val srcPort = ((packet[udpStart].toInt() and 0xFF) shl 8) or (packet[udpStart + 1].toInt() and 0xFF)
        val dstPort = ((packet[udpStart + 2].toInt() and 0xFF) shl 8) or (packet[udpStart + 3].toInt() and 0xFF)
        if (dstPort != 53) return

        val dnsStart = udpStart + 8
        val dnsPayload = packet.copyOfRange(dnsStart, packet.size)

        val name = DnsPacket.queryName(dnsPayload) ?: run {
            forward(packet, udpStart, srcPort, dnsPayload, out)
            return
        }

        val matched = DnsPacket.matchedBlock(name, blocklist)
        if (matched != null) {
            blockedCount.incrementAndGet()
            enqueueBlocked(matched)
            val response = DnsPacket.nxDomainResponse(dnsPayload)
            writeUdpReply(packet, udpStart, srcPort, response, out)
            return
        }

        forward(packet, udpStart, srcPort, dnsPayload, out)
    }

    private fun forward(
        originalPacket: ByteArray,
        udpStart: Int,
        srcPort: Int,
        dnsPayload: ByteArray,
        out: FileOutputStream,
    ) {
        val socket = DatagramSocket()
        protect(socket)
        try {
            socket.soTimeout = 5_000
            val upstream = InetSocketAddress(InetAddress.getByName(UPSTREAM_DNS), UPSTREAM_DNS_PORT)
            socket.send(DatagramPacket(dnsPayload, dnsPayload.size, upstream))

            val reply = ByteArray(32 * 1024)
            val dp = DatagramPacket(reply, reply.size)
            socket.receive(dp)

            val replyBytes = reply.copyOfRange(0, dp.length)
            writeUdpReply(originalPacket, udpStart, srcPort, replyBytes, out)
        } catch (_: Exception) {
        } finally {
            try { socket.close() } catch (_: Exception) {}
        }
    }

    private fun writeUdpReply(
        originalPacket: ByteArray,
        udpStart: Int,
        originalSrcPort: Int,
        dnsReply: ByteArray,
        out: FileOutputStream,
    ) {
        val ipHeaderLen = (originalPacket[0].toInt() and 0x0F) * 4
        val totalLen = ipHeaderLen + 8 + dnsReply.size
        val pkt = ByteBuffer.allocate(totalLen)

        pkt.put(originalPacket, 0, ipHeaderLen)
        pkt.position(0)

        pkt.put(2, ((totalLen ushr 8) and 0xFF).toByte())
        pkt.put(3, (totalLen and 0xFF).toByte())
        pkt.put(8, 64.toByte())
        val src = originalPacket.copyOfRange(12, 16)
        val dst = originalPacket.copyOfRange(16, 20)
        pkt.position(12); pkt.put(dst); pkt.put(src)

        pkt.put(10, 0); pkt.put(11, 0)
        val ipChecksum = checksum(pkt.array(), 0, ipHeaderLen)
        pkt.put(10, ((ipChecksum ushr 8) and 0xFF).toByte())
        pkt.put(11, (ipChecksum and 0xFF).toByte())

        pkt.position(ipHeaderLen)
        pkt.put(0, pkt.get(0))
        pkt.position(ipHeaderLen)
        pkt.put((53 ushr 8 and 0xFF).toByte())
        pkt.put((53 and 0xFF).toByte())
        pkt.put((originalSrcPort ushr 8 and 0xFF).toByte())
        pkt.put((originalSrcPort and 0xFF).toByte())
        val udpLen = 8 + dnsReply.size
        pkt.put((udpLen ushr 8 and 0xFF).toByte())
        pkt.put((udpLen and 0xFF).toByte())
        pkt.put(0); pkt.put(0)
        pkt.put(dnsReply)

        try { out.write(pkt.array(), 0, totalLen) } catch (_: Exception) {}
    }

    private fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + length
        while (i < end - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            if (sum and 0x10000 != 0) sum = (sum and 0xFFFF) + 1
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
            if (sum and 0x10000 != 0) sum = (sum and 0xFFFF) + 1
        }
        return sum.inv() and 0xFFFF
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return
        nm.createNotificationChannel(NotificationChannel(
            CHANNEL_ID,
            "ChoiceFirst protection",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Shown while CF is blocking trackers."
            setShowBadge(false)
        })
    }

    private fun buildNotification(): Notification {
        val openApp = packageManager.getLaunchIntentForPackage(packageName)
        val contentIntent = openApp?.let {
            PendingIntent.getActivity(
                this, 0, it,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
        }

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(applicationInfo.icon)
            .setContentTitle("ChoiceFirst is protecting you")
            .setContentText("Blocking ${blocklist.size} tracker domains")
            .setOngoing(true)
            .setContentIntent(contentIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}
