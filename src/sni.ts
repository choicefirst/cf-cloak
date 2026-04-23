/**
 * cf-cloak — TLS SNI extraction (TypeScript mirror of SniPacket.kt)
 *
 * Extracts the Server Name Indication hostname from a raw TCP payload
 * containing a TLS ClientHello record. Used in the web/React layer for
 * rule-preview and domain classification without duplicating logic.
 *
 * Licensed under AGPLv3. Commercial use requires a separate license.
 */

const CONTENT_TYPE_HANDSHAKE = 0x16
const HANDSHAKE_CLIENT_HELLO = 0x01
const EXT_SERVER_NAME = 0x0000
const NAME_TYPE_HOST_NAME = 0x00

/**
 * Extract the SNI hostname from a raw TCP segment payload (no IP/TCP headers).
 * Returns null if the payload is not a TLS ClientHello, is malformed,
 * or contains no SNI extension.
 */
export function sniHostname(payload: Uint8Array): string | null {
  if (payload.length < 5) return null

  let pos = 0

  // --- TLS record header (5 bytes) ---
  const contentType = payload[pos++]
  if (contentType !== CONTENT_TYPE_HANDSHAKE) return null

  // Legacy version (2 bytes big-endian)
  const legacyVersionHigh = payload[pos++]
  pos++ // low byte unused for the check
  if (legacyVersionHigh !== 0x03) return null

  // Record length (2 bytes)
  const recordLength = (payload[pos] << 8) | payload[pos + 1]
  pos += 2
  if (recordLength < 4 || pos + recordLength > payload.length) return null

  // --- Handshake header (4 bytes) ---
  const handshakeType = payload[pos++]
  if (handshakeType !== HANDSHAKE_CLIENT_HELLO) return null

  // 3-byte handshake body length
  const hLength = (payload[pos] << 16) | (payload[pos + 1] << 8) | payload[pos + 2]
  pos += 3
  if (hLength < 34 || pos + hLength > payload.length) return null

  // --- ClientHello body ---
  // client_version (2)
  pos += 2

  // random (32)
  if (pos + 32 > payload.length) return null
  pos += 32

  // session_id: 1-byte length + data
  if (pos >= payload.length) return null
  const sessionIdLen = payload[pos++]
  if (pos + sessionIdLen > payload.length) return null
  pos += sessionIdLen

  // cipher_suites: 2-byte length + data
  if (pos + 2 > payload.length) return null
  const cipherSuitesLen = (payload[pos] << 8) | payload[pos + 1]
  pos += 2
  if (pos + cipherSuitesLen > payload.length) return null
  pos += cipherSuitesLen

  // compression_methods: 1-byte length + data
  if (pos >= payload.length) return null
  const compressionLen = payload[pos++]
  if (pos + compressionLen > payload.length) return null
  pos += compressionLen

  // extensions: 2-byte total length
  if (pos + 2 > payload.length) return null
  const extensionsLen = (payload[pos] << 8) | payload[pos + 1]
  pos += 2
  if (pos + extensionsLen > payload.length) return null

  const extEnd = pos + extensionsLen
  while (pos + 4 <= extEnd) {
    const extType = (payload[pos] << 8) | payload[pos + 1]
    pos += 2
    const extLen = (payload[pos] << 8) | payload[pos + 1]
    pos += 2
    if (pos + extLen > payload.length) return null

    if (extType === EXT_SERVER_NAME) {
      return parseSniExtension(payload, pos, extLen)
    }
    pos += extLen
  }

  return null
}

function parseSniExtension(payload: Uint8Array, pos: number, extLen: number): string | null {
  if (extLen < 2) return null
  const listLen = (payload[pos] << 8) | payload[pos + 1]
  pos += 2
  if (listLen < 3 || pos + listLen > payload.length) return null

  const listEnd = pos + listLen
  while (pos + 3 <= listEnd) {
    const nameType = payload[pos++]
    const nameLen = (payload[pos] << 8) | payload[pos + 1]
    pos += 2
    if (pos + nameLen > payload.length) return null

    if (nameType === NAME_TYPE_HOST_NAME && nameLen > 0) {
      // ASCII decode — SNI hostnames are always ASCII
      let name = ''
      for (let i = 0; i < nameLen; i++) name += String.fromCharCode(payload[pos + i])
      return name.toLowerCase()
    }
    pos += nameLen
  }
  return null
}
