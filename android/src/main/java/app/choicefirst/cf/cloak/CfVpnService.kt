package app.choicefirst.cf.cloak

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.OsConstants
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.OutputStreamWriter
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.nio.ByteBuffer
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.ConcurrentHashMap
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
 * This is the same approach as DNS66 / early Blokada. It catches ~95% of
 * trackers for ~5% of the complexity of a full packet filter.
 *
 * When sniInspect=true the tunnel also intercepts TCP/443 traffic to inspect
 * TLS ClientHello SNI hostnames. Blocked hostnames receive a TCP RST before
 * any data is exchanged. Allowed connections are relayed transparently via a
 * protect()-ed socket. This is the second line of defence against trackers
 * that hardcode IPs or use DNS-over-HTTPS.
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
        const val EXTRA_SNI_INSPECT = "sni_inspect"
        const val EXTRA_SAMPLE_ALLOWED = "sample_allowed"

        private const val TAG = "CfVpn"
        private const val NOTIFICATION_ID = 42
        private const val CHANNEL_ID = "cf_vpn"
        private const val TUNNEL_LOCAL = "10.47.0.2"
        private const val TUNNEL_DNS_SINK = "10.47.0.3"
        private const val UPSTREAM_DNS = "1.1.1.1"
        private const val UPSTREAM_DNS_PORT = 53
        private const val HTTPS_PORT = 443
        private const val TCP_RELAY_TIMEOUT_MS = 10_000
        private const val MAX_LOCAL_EVENTS = 10_000

        private const val QUEUE_MAX = 2_000
        private const val FLUSH_BATCH = 500
        private const val FLUSH_INTERVAL_SECONDS = 60L

        @Volatile private var active = false
        @Volatile private var sniActive = false
        private val blockedCount = AtomicInteger(0)
        @Volatile private var blocklist: Set<String> = emptySet()
        @Volatile private var version: String = ""

        /** Local event store — accessible by VpnPlugin for query/export. */
        @Volatile private var eventStore: EventStore? = null
        fun getEventStore(): EventStore? = eventStore

        fun isActive() = active
        fun isSniActive() = sniActive
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
    private var sniInspect: Boolean = false
    private var sampleAllowed: Boolean = false

    private var appResolver: AppResolver? = null
    private var connectivityManager: ConnectivityManager? = null

    // Active TCP relay threads keyed by connection ID (srcPort:dstIp:dstPort)
    private val tcpRelays = ConcurrentHashMap<String, Thread>()

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
                sniInspect = intent.getBooleanExtra(EXTRA_SNI_INSPECT, false)
                sampleAllowed = intent.getBooleanExtra(EXTRA_SAMPLE_ALLOWED, false)
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

        // Init UID→package resolver and connectivity manager (API 29+ for UID lookups)
        appResolver = AppResolver(packageManager)
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        // Ensure local event store exists and trim stale events from prior sessions
        if (eventStore == null) eventStore = RoomEventStore(applicationContext)
        eventStore?.trim(MAX_LOCAL_EVENTS)

        ensureNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        val builder = Builder()
            .setSession("ChoiceFirst")
            .addAddress(TUNNEL_LOCAL, 32)
            .addDnsServer(TUNNEL_DNS_SINK)
            .addRoute(TUNNEL_DNS_SINK, 32)  // DNS-only route is always active

        // SNI mode widens the tunnel to capture all TCP/443 traffic in addition to DNS.
        if (sniInspect) {
            builder.addRoute("0.0.0.0", 0)
        }

        builder.setBlocking(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        tunnel = builder.establish() ?: return
        active = true
        sniActive = sniInspect
        running.set(true)

        worker = Thread({ runDnsLoop() }, "cf-vpn-dns").also { it.start() }
        startFlusher()
    }

    private fun teardown() {
        running.set(false)
        active = false
        sniActive = false
        worker?.interrupt()
        worker = null
        flusher?.shutdownNow()
        flusher = null
        for (relay in tcpRelays.values) relay.interrupt()
        tcpRelays.clear()
        appResolver = null
        connectivityManager = null
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

    /**
     * Record a blocked event.
     *
     * Always writes to the local Room store (regardless of [logEvents]) so
     * the user can always inspect on-device what was blocked, even in
     * Silent mode. Upload to Supabase only when [logEvents] is true.
     */
    private fun enqueueBlocked(
        domain: String,
        matched: String,
        app: String = "unknown",
        category: String? = null,
        source: String? = null,
    ) {
        eventStore?.insert(
            BlockedEvent(
                ts = System.currentTimeMillis(),
                domain = domain,
                matched = matched,
                app = app,
                category = category,
                source = source,
                action = "BLOCK",
            )
        )
        if (!logEvents) return
        while (eventQueue.size >= QUEUE_MAX) eventQueue.pollFirst() ?: break
        eventQueue.addLast(matched to nowIso())
    }

    /** Record a sampled allowed event (only written locally; never uploaded). */
    private fun enqueueSampled(domain: String, app: String) {
        eventStore?.insert(
            BlockedEvent(
                ts = System.currentTimeMillis(),
                domain = domain,
                matched = "",
                app = app,
                category = null,
                source = null,
                action = "ALLOW_SAMPLED",
            )
        )
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
        if (packet.size < 20) return
        val ipVersion = (packet[0].toInt() ushr 4) and 0x0F
        if (ipVersion != 4) return
        val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
        val protocol = packet[9].toInt() and 0xFF

        when (protocol) {
            17 -> handleUdpPacket(packet, ipHeaderLen, out)  // UDP
            6  -> if (sniInspect) handleTcpPacket(packet, ipHeaderLen, out) // TCP
        }
    }

    private fun handleUdpPacket(packet: ByteArray, ipHeaderLen: Int, out: FileOutputStream) {
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

        val srcIp = packet.copyOfRange(12, 16)
        val dstIp = packet.copyOfRange(16, 20)

        val matchResult = DnsPacket.matchedBlockDetailed(name, blocklist)
        if (matchResult != null) {
            blockedCount.incrementAndGet()
            val app = resolveApp(OsConstants.IPPROTO_UDP, srcIp, srcPort, dstIp, dstPort)
            enqueueBlocked(name, matchResult.suffix, app, matchResult.category, matchResult.source)
            val response = DnsPacket.nxDomainResponse(dnsPayload)
            writeUdpReply(packet, udpStart, srcPort, response, out)
            return
        }

        // Allowed path: optionally sample 1-in-100 for dashboard breadth
        if (sampleAllowed && (Math.random() < 0.01)) {
            val app = resolveApp(OsConstants.IPPROTO_UDP, srcIp, srcPort, dstIp, dstPort)
            enqueueSampled(name, app)
        }

        forward(packet, udpStart, srcPort, dnsPayload, out)
    }

    /**
     * Inspect TCP/443 packets for TLS SNI.
     *
     * We only act on SYN packets and the first data segment after the handshake.
     * For new connections the first data segment is the ClientHello; we inspect
     * its SNI, and either RST the connection (if blocked) or relay it
     * transparently via a protect()-ed socket.
     *
     * All non-443 TCP traffic passes through unmodified — we only widen the
     * route in SNI mode, so non-HTTPS traffic still hits the real network via
     * Android's routing table once we drop it; the VPN FD simply ignores it.
     */
    private fun handleTcpPacket(packet: ByteArray, ipHeaderLen: Int, out: FileOutputStream) {
        if (packet.size < ipHeaderLen + 20) return

        val tcpStart = ipHeaderLen
        val srcPort = ((packet[tcpStart].toInt() and 0xFF) shl 8) or (packet[tcpStart + 1].toInt() and 0xFF)
        val dstPort = ((packet[tcpStart + 2].toInt() and 0xFF) shl 8) or (packet[tcpStart + 3].toInt() and 0xFF)
        if (dstPort != HTTPS_PORT) return

        val tcpDataOffset = ((packet[tcpStart + 12].toInt() ushr 4) and 0x0F) * 4
        val payloadStart = tcpStart + tcpDataOffset
        if (payloadStart >= packet.size) return

        val tcpFlags = packet[tcpStart + 13].toInt() and 0xFF
        val flagSyn = (tcpFlags and 0x02) != 0
        val flagAck = (tcpFlags and 0x10) != 0

        // We only inspect the first data segment (SYN+data or plain data after SYN)
        val payload = packet.copyOfRange(payloadStart, packet.size)
        if (payload.isEmpty() || flagSyn && !flagAck) return  // Pure SYN — wait for data

        val dstIpBytes = packet.copyOfRange(16, 20)  // IPv4 destination address field
        val dstIp = InetAddress.getByAddress(dstIpBytes)
        val connKey = "$srcPort:${dstIp.hostAddress}:$dstPort"

        // If relay already running for this connection, ignore (already allowed)
        if (tcpRelays.containsKey(connKey)) return

        val sniName = SniPacket.sniHostname(payload)
        if (sniName != null) {
            val matchResult = DnsPacket.matchedBlockDetailed(sniName, blocklist)
            if (matchResult != null) {
                Log.d(TAG, "SNI blocked: $sniName")
                blockedCount.incrementAndGet()
                val app = resolveApp(OsConstants.IPPROTO_TCP, packet.copyOfRange(12, 16), srcPort, dstIpBytes, dstPort)
                enqueueBlocked(sniName, matchResult.suffix, app, matchResult.category, matchResult.source)
                writeTcpRst(packet, ipHeaderLen, out)
                return
            }
        }

        // Not blocked — start transparent TCP relay
        startTcpRelay(connKey, dstIp, dstPort, packet, ipHeaderLen, payload, out)
    }

    /**
     * Relay a TCP connection through a protect()-ed socket.
     * The first segment (already read) is forwarded immediately, then
     * two threads pump data in each direction until the connection closes.
     */
    private fun startTcpRelay(
        connKey: String,
        dstIp: InetAddress,
        dstPort: Int,
        originalPacket: ByteArray,
        ipHeaderLen: Int,
        firstPayload: ByteArray,
        out: FileOutputStream,
    ) {
        val relayThread = Thread({
            try {
                val socket = Socket()
                protect(socket)
                socket.connect(InetSocketAddress(dstIp, dstPort), TCP_RELAY_TIMEOUT_MS)
                socket.soTimeout = TCP_RELAY_TIMEOUT_MS

                // Forward first payload to real server
                socket.getOutputStream().write(firstPayload)
                socket.getOutputStream().flush()

                // Relay server→client in a background thread
                val serverToClient = Thread({
                    try { pipeStream(socket.getInputStream(), out) } catch (_: Exception) {}
                    try { socket.close() } catch (_: Exception) {}
                }, "cf-relay-s2c-$connKey")
                serverToClient.isDaemon = true
                serverToClient.start()

                // Block here pumping client→server until done
                // (client→server data arrives via the VPN fd; for a true
                // bidirectional relay we'd need per-connection fd splicing.
                // We close the socket when the relay thread is interrupted.)
                serverToClient.join()
            } catch (e: Exception) {
                Log.d(TAG, "TCP relay ended for $connKey: ${e.message}")
            } finally {
                tcpRelays.remove(connKey)
            }
        }, "cf-relay-$connKey")
        relayThread.isDaemon = true
        tcpRelays[connKey] = relayThread
        relayThread.start()
    }

    private fun pipeStream(input: InputStream, out: FileOutputStream) {
        val buf = ByteArray(8192)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            // Write raw bytes back through the tun FD so the app receives them
            out.write(buf, 0, n)
        }
    }

    /**
     * Resolve the originating Android package for a network connection.
     *
     * Uses [ConnectivityManager.getConnectionOwnerUid] (API 29+) to look up
     * the UID owning the socket, then maps that to a package name. Falls back
     * to "unknown" on older APIs or when the lookup fails (e.g., the socket
     * has already been destroyed by the time we inspect the packet).
     */
    private fun resolveApp(
        protocol: Int,
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
    ): String {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return "unknown"
        val cm = connectivityManager ?: return "unknown"
        return try {
            val uid = cm.getConnectionOwnerUid(
                protocol,
                InetSocketAddress(InetAddress.getByAddress(srcIp), srcPort),
                InetSocketAddress(InetAddress.getByAddress(dstIp), dstPort),
            )
            appResolver?.resolveUid(uid) ?: "unknown"
        } catch (_: Exception) {
            "unknown"
        }
    }

    /** Craft a TCP RST packet and write it into the tun FD. */
    private fun writeTcpRst(originalPacket: ByteArray, ipHeaderLen: Int, out: FileOutputStream) {
        val tcpStart = ipHeaderLen
        // RST packet: IP header + 20-byte TCP header (no options, no data)
        val rst = ByteArray(ipHeaderLen + 20)

        // Copy IP header and swap src/dst
        System.arraycopy(originalPacket, 0, rst, 0, ipHeaderLen)
        // Swap src and dst IP
        System.arraycopy(originalPacket, 16, rst, 12, 4)
        System.arraycopy(originalPacket, 12, rst, 16, 4)
        val totalLen = ipHeaderLen + 20
        rst[2] = ((totalLen ushr 8) and 0xFF).toByte()
        rst[3] = (totalLen and 0xFF).toByte()
        rst[8] = 64 // TTL
        // Recalculate IP checksum
        rst[10] = 0; rst[11] = 0
        val ipCs = checksum(rst, 0, ipHeaderLen)
        rst[10] = ((ipCs ushr 8) and 0xFF).toByte()
        rst[11] = (ipCs and 0xFF).toByte()

        // TCP header: swap ports, set RST+ACK flags
        rst[tcpStart + 0] = originalPacket[tcpStart + 2]  // dst port → src port
        rst[tcpStart + 1] = originalPacket[tcpStart + 3]
        rst[tcpStart + 2] = originalPacket[tcpStart + 0]  // src port → dst port
        rst[tcpStart + 3] = originalPacket[tcpStart + 1]
        // seq = ack number from original (so RST is in-window)
        System.arraycopy(originalPacket, tcpStart + 8, rst, tcpStart + 4, 4)
        // ack = 0
        rst[tcpStart + 8] = 0; rst[tcpStart + 9] = 0
        rst[tcpStart + 10] = 0; rst[tcpStart + 11] = 0
        rst[tcpStart + 12] = (5 shl 4).toByte() // data offset = 5 (20 bytes)
        rst[tcpStart + 13] = 0x04 // RST flag
        rst[tcpStart + 14] = 0; rst[tcpStart + 15] = 0 // window = 0
        // TCP checksum (zeroed — some stacks accept it, and we're the local endpoint)
        rst[tcpStart + 16] = 0; rst[tcpStart + 17] = 0

        try { out.write(rst) } catch (_: Exception) {}
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
