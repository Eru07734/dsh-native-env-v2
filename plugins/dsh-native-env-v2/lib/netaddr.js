/**
 * dsh-net-bridge / netaddr — the small amount of address arithmetic the listener
 * needs: normalize a socket's peer address, recognize loopback, and match an
 * IPv4 CIDR allowlist.
 *
 * IPv4 CIDR allowlists are supported. IPv6 literals are supported by exact match,
 * and an IPv4-mapped IPv6 peer (`::ffff:192.0.2.1`) is normalized to its IPv4 form.
 *
 * @module dsh-net-bridge/netaddr
 */

/**
 * Normalize a `socket.remoteAddress` value.
 * @param address - the raw address as reported by Node.
 * @returns the IPv4 form when the value is IPv4 or IPv4-mapped IPv6, else the
 *   input unchanged.
 */
export function normalizeAddress(address) {
  if (typeof address !== 'string') return ''
  if (address.startsWith('::ffff:')) return address.slice('::ffff:'.length)
  return address
}

/**
 * Whether one address is loopback.
 * @param address - raw or normalized address.
 * @returns true for 127.0.0.0/8 and `::1`.
 */
export function isLoopback(address) {
  const value = normalizeAddress(address)
  return value === '::1' || value === 'localhost' || /^127\./.test(value)
}

/**
 * Parse one allowlist entry.
 * @param entry - `192.0.2.0/24`, `192.0.2.1`, or a host name.
 * @returns an object with the base address (as a 32-bit integer when IPv4), the
 *   prefix length, and the original text.
 */
export function parseEntry(entry) {
  const text = String(entry).trim()
  const slash = text.indexOf('/')
  const address = slash < 0 ? text : text.slice(0, slash)
  const rawPrefix = slash < 0 ? 32 : Number(text.slice(slash + 1))
  const prefix = Number.isInteger(rawPrefix) && rawPrefix >= 0 && rawPrefix <= 32 ? rawPrefix : 32
  const value = ipv4ToInt(address)
  return { text, address, prefix, value }
}

/**
 * Convert a dotted IPv4 literal to a 32-bit unsigned integer.
 * @param address - e.g. `192.0.2.1`.
 * @returns the integer, or `undefined` when the input is not IPv4.
 */
export function ipv4ToInt(address) {
  const parts = String(address).split('.')
  if (parts.length !== 4) return undefined
  let value = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return undefined
    const octet = Number(part)
    if (octet > 255) return undefined
    value = (value * 256) + octet
  }
  return value >>> 0
}

/**
 * Whether one address matches one allowlist entry.
 * @param address - the peer address (raw or normalized).
 * @param entry - one parsed entry from {@link parseEntry}.
 * @returns true on an exact string match or an in-range IPv4 match.
 */
export function matchesEntry(address, entry) {
  const value = normalizeAddress(address)
  if (entry.value === undefined) return value === entry.address
  const candidate = ipv4ToInt(value)
  if (candidate === undefined) return false
  const mask = entry.prefix === 0 ? 0 : (0xffffffff << (32 - entry.prefix)) >>> 0
  return (candidate & mask) === (entry.value & mask)
}

/**
 * Whether one peer address passes an allowlist.
 *
 * An empty list means "loopback only": the plugin's default configuration must
 * never accept a remote connection just because nobody configured an allowlist.
 *
 * @param address - the peer address.
 * @param entries - raw allowlist entries.
 * @returns true when the address is accepted.
 */
export function isAllowedPeer(address, entries) {
  if (!Array.isArray(entries) || entries.length === 0) return isLoopback(address)
  return entries.map(parseEntry).some((entry) => matchesEntry(address, entry))
}
