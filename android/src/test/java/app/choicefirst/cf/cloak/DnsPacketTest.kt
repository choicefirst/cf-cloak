package app.choicefirst.cf.cloak

import org.junit.Assert.*
import org.junit.Test

/**
 * JVM unit tests for [DnsPacket] and [PolicyEngine].
 *
 * These tests run on the local JVM without an Android emulator (testImplementation only).
 * They are the canonical regression guard for the open-source blocking core.
 */
class DnsPacketTest {

    // ── queryName ─────────────────────────────────────────────────────────────

    @Test
    fun `queryName returns null for empty payload`() {
        assertNull(DnsPacket.queryName(ByteArray(0)))
    }

    @Test
    fun `queryName returns null for short payload`() {
        assertNull(DnsPacket.queryName(ByteArray(11)))
    }

    @Test
    fun `queryName parses simple A query`() {
        // Manually crafted DNS query for "example.com" (QTYPE=A, QCLASS=IN)
        // Header: id=0x1234, flags=0x0100, qdcount=1, others=0
        // QNAME: 7|example|3|com|0
        // QTYPE: 0x0001, QCLASS: 0x0001
        val bytes = byteArrayOf(
            0x12, 0x34,             // ID
            0x01, 0x00,             // QR=0, Opcode=0, RD=1
            0x00, 0x01,             // QDCOUNT=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR = 0
            7, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(),
            'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            3, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0,                      // end of QNAME
            0x00, 0x01,             // QTYPE=A
            0x00, 0x01,             // QCLASS=IN
        )
        assertEquals("example.com", DnsPacket.queryName(bytes))
    }

    @Test
    fun `queryName lowercases the result`() {
        val bytes = byteArrayOf(
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            3, 'F'.code.toByte(), 'O'.code.toByte(), 'O'.code.toByte(),
            3, 'C'.code.toByte(), 'O'.code.toByte(), 'M'.code.toByte(),
            0,
            0x00, 0x01, 0x00, 0x01,
        )
        assertEquals("foo.com", DnsPacket.queryName(bytes))
    }

    @Test
    fun `queryName returns null on pointer compression`() {
        val bytes = byteArrayOf(
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0.toByte(), 0x00, // pointer at offset 12 — bail
        )
        assertNull(DnsPacket.queryName(bytes))
    }

    // ── matchedBlock ──────────────────────────────────────────────────────────

    @Test
    fun `matchedBlock returns null when blocklist empty`() {
        assertNull(DnsPacket.matchedBlock("tracker.evil.com", emptySet()))
    }

    @Test
    fun `matchedBlock exact match`() {
        val bl = setOf("evil.com")
        assertEquals("evil.com", DnsPacket.matchedBlock("evil.com", bl))
    }

    @Test
    fun `matchedBlock suffix match one level`() {
        val bl = setOf("evil.com")
        assertEquals("evil.com", DnsPacket.matchedBlock("tracker.evil.com", bl))
    }

    @Test
    fun `matchedBlock suffix match two levels`() {
        val bl = setOf("evil.com")
        assertEquals("evil.com", DnsPacket.matchedBlock("a.b.evil.com", bl))
    }

    @Test
    fun `matchedBlock does not match sibling`() {
        val bl = setOf("evil.com")
        assertNull(DnsPacket.matchedBlock("notevil.com", bl))
    }

    @Test
    fun `matchedBlock does not partial-match label`() {
        val bl = setOf("vil.com")
        assertNull(DnsPacket.matchedBlock("evil.com", bl))
    }

    // ── matchedBlockDetailed ──────────────────────────────────────────────────

    @Test
    fun `matchedBlockDetailed returns null on no match`() {
        assertNull(DnsPacket.matchedBlockDetailed("safe.com", setOf("evil.com")))
    }

    @Test
    fun `matchedBlockDetailed returns null category when metadata absent`() {
        val result = DnsPacket.matchedBlockDetailed("tracker.evil.com", setOf("evil.com"))
        assertNotNull(result)
        assertEquals("evil.com", result!!.suffix)
        assertNull(result.category)
        assertNull(result.source)
    }

    @Test
    fun `matchedBlockDetailed returns category from metadata`() {
        val meta = mapOf("evil.com" to ("ads" to "easylist"))
        val result = DnsPacket.matchedBlockDetailed("tracker.evil.com", setOf("evil.com"), meta)
        assertNotNull(result)
        assertEquals("ads", result!!.category)
        assertEquals("easylist", result.source)
    }

    // ── nxDomainResponse ─────────────────────────────────────────────────────

    @Test
    fun `nxDomainResponse sets QR and NXDOMAIN rcode`() {
        val req = ByteArray(12) // minimal header, 12 bytes
        req[0] = 0xAB.toByte(); req[1] = 0xCD.toByte() // ID
        req[2] = 0x01 // RD=1
        req[4] = 0x00; req[5] = 0x01 // QDCOUNT=1
        val resp = DnsPacket.nxDomainResponse(req)
        assertEquals(0xAB.toByte(), resp[0])       // ID preserved
        assertEquals(0xCD.toByte(), resp[1])
        assertTrue((resp[2].toInt() and 0x80) != 0) // QR=1
        assertEquals(0x83.toByte(), resp[3])        // RA=1, RCODE=3
        assertEquals(0, resp[6].toInt())            // ANCOUNT=0
    }
}
