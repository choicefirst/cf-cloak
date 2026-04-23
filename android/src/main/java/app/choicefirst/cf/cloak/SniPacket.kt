package app.choicefirst.cf.cloak

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal TLS ClientHello parser that extracts the Server Name Indication
 * (SNI) hostname from a raw TCP payload.
 *
 * This is the second line of defence after DNS blocking. Trackers that
 * hardcode server IPs or use DNS-over-HTTPS bypass the DNS sinkhole; their
 * TLS handshakes still carry a plaintext SNI extension that we can inspect
 * and, if blocked, RST before any data is exchanged.
 *
 * We only ever read the first TCP segment of a new connection — specifically
 * the TLS record containing the ClientHello. No subsequent payload is
 * inspected, and nothing from the payload is stored beyond the hostname
 * string. Allowed connections are relayed byte-for-byte with no further
 * inspection.
 *
 * Protocol reference: RFC 6066 §3 (SNI), RFC 8446 §4.1.2 (ClientHello).
 *
 * This file is part of the cf-cloak open-source enforcement layer.
 * Licensed under AGPLv3. See the repository root for full terms.
 */
object SniPacket {

    // TLS content type for Handshake records
    private const val CONTENT_TYPE_HANDSHAKE: Byte = 0x16

    // TLS Handshake message type for ClientHello
    private const val HANDSHAKE_CLIENT_HELLO: Byte = 0x01

    // TLS extension type for SNI
    private const val EXT_SERVER_NAME: Short = 0x0000.toShort()

    // SNI name type for host_name
    private const val NAME_TYPE_HOST_NAME: Byte = 0x00

    /**
     * Extract the SNI hostname from a raw TCP segment payload.
     *
     * [payload] must be the TCP *data* only — no IP or TCP headers.
     * Returns null if the payload is not a TLS ClientHello, is malformed,
     * or contains no SNI extension.
     */
    fun sniHostname(payload: ByteArray): String? {
        if (payload.size < 5) return null

        val buf = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN)

        // --- TLS record header (5 bytes) ---
        val contentType = buf.get()
        if (contentType != CONTENT_TYPE_HANDSHAKE) return null

        val legacyVersion = buf.getShort()
        // Accept TLS 1.0 (0x0301) through 1.3 compat (0x0303/0x0304).
        // Reject anything below 0x0300 to avoid matching random binary traffic.
        if ((legacyVersion.toInt() and 0xFF00) != 0x0300) return null

        val recordLength = buf.getShort().toInt() and 0xFFFF
        if (recordLength < 4 || buf.remaining() < recordLength) return null

        // --- Handshake header (4 bytes) ---
        val handshakeType = buf.get()
        if (handshakeType != HANDSHAKE_CLIENT_HELLO) return null

        // 3-byte handshake body length
        val hLength = readUint24(buf)
        if (hLength < 34 || buf.remaining() < hLength) return null

        // --- ClientHello body ---
        // client_version (2)
        buf.getShort()

        // random (32)
        if (buf.remaining() < 32) return null
        buf.position(buf.position() + 32)

        // session_id: 1-byte length + data
        if (buf.remaining() < 1) return null
        val sessionIdLen = buf.get().toInt() and 0xFF
        if (buf.remaining() < sessionIdLen) return null
        buf.position(buf.position() + sessionIdLen)

        // cipher_suites: 2-byte length + data
        if (buf.remaining() < 2) return null
        val cipherSuitesLen = buf.getShort().toInt() and 0xFFFF
        if (buf.remaining() < cipherSuitesLen) return null
        buf.position(buf.position() + cipherSuitesLen)

        // compression_methods: 1-byte length + data
        if (buf.remaining() < 1) return null
        val compressionLen = buf.get().toInt() and 0xFF
        if (buf.remaining() < compressionLen) return null
        buf.position(buf.position() + compressionLen)

        // extensions: 2-byte total length (optional — TLS 1.3 always has them)
        if (buf.remaining() < 2) return null
        val extensionsLen = buf.getShort().toInt() and 0xFFFF
        if (buf.remaining() < extensionsLen) return null

        // Walk extension list
        val extEnd = buf.position() + extensionsLen
        while (buf.position() + 4 <= extEnd) {
            val extType = buf.getShort()
            val extLen = buf.getShort().toInt() and 0xFFFF
            if (buf.remaining() < extLen) return null

            if (extType == EXT_SERVER_NAME) {
                return parseSniExtension(buf, extLen)
            }

            buf.position(buf.position() + extLen)
        }

        return null
    }

    private fun parseSniExtension(buf: ByteBuffer, extLen: Int): String? {
        if (extLen < 2) return null
        // server_name_list length (2 bytes)
        val listLen = buf.getShort().toInt() and 0xFFFF
        if (listLen < 3 || buf.remaining() < listLen) return null

        val listEnd = buf.position() + listLen
        while (buf.position() + 3 <= listEnd) {
            val nameType = buf.get()
            val nameLen = buf.getShort().toInt() and 0xFFFF
            if (buf.remaining() < nameLen) return null

            if (nameType == NAME_TYPE_HOST_NAME && nameLen > 0) {
                val nameBytes = ByteArray(nameLen)
                buf.get(nameBytes)
                return String(nameBytes, Charsets.US_ASCII).lowercase()
            }
            buf.position(buf.position() + nameLen)
        }
        return null
    }

    /** Read a 3-byte big-endian unsigned integer. */
    private fun readUint24(buf: ByteBuffer): Int {
        if (buf.remaining() < 3) return -1
        val b0 = buf.get().toInt() and 0xFF
        val b1 = buf.get().toInt() and 0xFF
        val b2 = buf.get().toInt() and 0xFF
        return (b0 shl 16) or (b1 shl 8) or b2
    }
}
