/**
 * Tests for sniHostname() — TLS ClientHello SNI extraction.
 * Uses Node.js built-in test runner — zero external dependencies.
 */
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { sniHostname } from './sni.js'

// ---------------------------------------------------------------------------
// Helpers to build minimal valid TLS ClientHello payloads
// ---------------------------------------------------------------------------

function buildClientHello(hostname: string): Uint8Array {
  const sniValue = Buffer.from(hostname, 'ascii')
  // SNI extension body: list_len(2) + name_type(1) + name_len(2) + name
  const sniBody = Buffer.alloc(2 + 1 + 2 + sniValue.length)
  let o = 0
  sniBody.writeUInt16BE(1 + 2 + sniValue.length, o); o += 2 // server_name_list length
  sniBody[o++] = 0x00                                         // name_type = host_name
  sniBody.writeUInt16BE(sniValue.length, o); o += 2
  sniValue.copy(sniBody, o)

  // Extension: type(2) + len(2) + body
  const ext = Buffer.alloc(4 + sniBody.length)
  ext.writeUInt16BE(0x0000, 0)          // ext type = server_name
  ext.writeUInt16BE(sniBody.length, 2)
  sniBody.copy(ext, 4)

  // Extensions block: total_len(2) + ext
  const extensions = Buffer.alloc(2 + ext.length)
  extensions.writeUInt16BE(ext.length, 0)
  ext.copy(extensions, 2)

  // ClientHello body (minimal valid structure):
  //   client_version(2) + random(32) + session_id_len(1) +
  //   cipher_suites_len(2) + cipher_suite(2) + compression_len(1) + 0x00 +
  //   extensions
  const chBody = Buffer.alloc(2 + 32 + 1 + 2 + 2 + 1 + 1 + extensions.length)
  let p = 0
  chBody.writeUInt16BE(0x0303, p); p += 2   // TLS 1.2 client_version
  p += 32                                    // random (zeroed)
  chBody[p++] = 0x00                         // session_id_len = 0
  chBody.writeUInt16BE(2, p); p += 2         // cipher_suites_len = 2
  chBody.writeUInt16BE(0x002F, p); p += 2    // TLS_RSA_WITH_AES_128_CBC_SHA
  chBody[p++] = 0x01                         // compression_methods_len = 1
  chBody[p++] = 0x00                         // null compression
  extensions.copy(chBody, p)

  // Handshake header: type(1) + length(3)
  const handshake = Buffer.alloc(4 + chBody.length)
  handshake[0] = 0x01                              // ClientHello
  handshake[1] = (chBody.length >> 16) & 0xFF
  handshake[2] = (chBody.length >> 8) & 0xFF
  handshake[3] = chBody.length & 0xFF
  chBody.copy(handshake, 4)

  // TLS record: content_type(1) + version(2) + length(2) + handshake
  const record = Buffer.alloc(5 + handshake.length)
  record[0] = 0x16                                  // content_type = Handshake
  record.writeUInt16BE(0x0301, 1)                   // legacy_version = TLS 1.0
  record.writeUInt16BE(handshake.length, 3)
  handshake.copy(record, 5)

  return new Uint8Array(record)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('sniHostname', () => {
  it('extracts SNI from a well-formed ClientHello', () => {
    const payload = buildClientHello('example.com')
    assert.equal(sniHostname(payload), 'example.com')
  })

  it('lowercases the extracted hostname', () => {
    const payload = buildClientHello('EXAMPLE.COM')
    assert.equal(sniHostname(payload), 'example.com')
  })

  it('handles subdomains correctly', () => {
    const payload = buildClientHello('tracker.doubleclick.net')
    assert.equal(sniHostname(payload), 'tracker.doubleclick.net')
  })

  it('returns null for empty payload', () => {
    assert.equal(sniHostname(new Uint8Array(0)), null)
  })

  it('returns null for payload shorter than TLS record header', () => {
    assert.equal(sniHostname(new Uint8Array([0x16, 0x03, 0x01])), null)
  })

  it('returns null when content type is not Handshake (0x16)', () => {
    const payload = buildClientHello('example.com')
    payload[0] = 0x17 // Application Data
    assert.equal(sniHostname(payload), null)
  })

  it('returns null when handshake type is not ClientHello (0x01)', () => {
    const payload = buildClientHello('example.com')
    payload[5] = 0x02 // ServerHello
    assert.equal(sniHostname(payload), null)
  })

  it('returns null for random binary data', () => {
    const noise = new Uint8Array(200)
    for (let i = 0; i < noise.length; i++) noise[i] = i & 0xFF
    assert.equal(sniHostname(noise), null)
  })

  it('returns null for all-zero payload', () => {
    assert.equal(sniHostname(new Uint8Array(200)), null)
  })

  it('handles a long hostname without crashing', () => {
    const hostname = 'a'.repeat(200) + '.example.com'
    const payload = buildClientHello(hostname)
    assert.equal(sniHostname(payload), hostname.toLowerCase())
  })
})
