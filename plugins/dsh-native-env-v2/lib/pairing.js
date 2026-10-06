/**
 * dsh-native-env / pairing — the invite payload, and nothing else.
 *
 * An invite is the ONLY thing a human has to move between two machines: one
 * short string that fits in a QR code, in a chat message, or on a clipboard.
 * Everything the old deployment asked an operator to write by hand —
 * `peers`, `listen`, `allowPeers`, `port`, `tokenFile`, an ssh command line —
 * is derived from it at runtime, which is the entire point of this revision.
 *
 * Layout:
 *
 *   dsh+env://pair?v=2&relay=<wss url>&inviteId=<32 hex>&exp=<epoch ms>&fp=<16 hex>#<pairSecret>
 *
 * Two decisions carry weight:
 *
 *   1. **The secret lives in the FRAGMENT.** A URI fragment is never sent in an
 *      HTTP request line, so it cannot land in a reverse proxy's access log, a
 *      `Referer` header, or a browser history entry that syncs to a cloud
 *      account. Putting the secret in the query — the obvious implementation —
 *      leaks it to every intermediary the QR code's URL might ever be pasted
 *      into. The rest of the payload is deliberately non-secret: the invite ID
 *      is what the relay is told anyway, and the fingerprint is public.
 *   2. **Parsing never throws.** A scanned QR code is untrusted input from a
 *      camera. `parseInviteUri` returns a discriminated result so the caller can
 *      show "this invite expired" or "this relay address is not a WebSocket URL"
 *      instead of a stack trace, and so no code path can be tempted to treat a
 *      partially-parsed invite as usable.
 *
 * What an invite does NOT contain: any file path, any host name of either
 * machine, any long-lived key, or anything derived from the harness. Leaking the
 * relay is unavoidable — it is where the guest must connect — so the invite is
 * treated as sensitive but not as a long-term credential, and it expires.
 *
 * @module dsh-native-env/pairing
 */

import { INVITE_ID_BYTES, PAIR_SECRET_BYTES, PAIRING_VERSION, newInviteId, newPairSecret } from './e2ee.js'
import { normalizeDeviceCode, normalizePassword, looksLikePassword } from './device-code.js'

/** The URI scheme+specific-part that identifies a pairing invite. */
export const INVITE_SCHEME = 'dsh+env'
export const INVITE_HOST = 'pair'

/** The protocol version this build writes and accepts. */
export const SUPPORTED_VERSION = PAIRING_VERSION

/**
 * How a pairing is offered, and the difference is a security property rather than a
 * presentation choice.
 *
 *   - `qr` — a URI that carries the host's IDENTITY FINGERPRINT. The guest proves the
 *     host is the pinned machine, so a malicious relay cannot insert itself.
 *   - `code` — a device code and a temporary password, typed by a human. There is
 *     nothing to pin a fingerprint to, so this mode trusts the relay for identity and
 *     relies on the displayed short authentication string for the human check that
 *     replaces it. See `pairing-session.js`.
 */
export const JOIN_MODE = Object.freeze({ qr: 'qr', code: 'code' })

/** The longest invite this module will parse. A QR code this size is already absurd. */
export const MAX_URI_LENGTH = 1024

/** The longest relay URL accepted. A URL that will not fit is a misconfiguration. */
export const MAX_RELAY_LENGTH = 512

/** Every query key an invite may carry. Anything else is refused, not ignored. */
const ALLOWED_QUERY_KEYS = Object.freeze(['v', 'relay', 'inviteId', 'exp', 'fp'])

/**
 * A slot id, as the RELAY sees it: opaque, lower-case, and short enough to type.
 *
 * One pattern for both modes, deliberately: a 32-hex invite id and a nine-digit device
 * code are both just slot keys to the relay, and giving the relay a second pattern to
 * recognise would mean two places to keep in step. The client is the side that knows
 * which shape it minted.
 */
const SLOT_ID_PATTERN = /^[0-9a-z]{4,64}$/

/** Fingerprints are the first 64 bits of a SHA-256, hex. */
const FINGERPRINT_PATTERN = /^[0-9a-f]{16}$/

/** 32 random bytes, base64url, unpadded: exactly 43 characters. */
const PAIR_SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/

/** The longest an invite may live, as a guard against a replayed ancient one. */
export const MAX_INVITE_TTL_MS = 24 * 60 * 60 * 1000

/** The default lifetime: long enough to walk to another machine, short enough to be safe. */
export const DEFAULT_INVITE_TTL_MS = 10 * 60 * 1000

/**
 * A parse or validation failure with a stable code.
 *
 * The code is what a UI switches on (`expired` gets a "create a new invite"
 * button, `bad-relay` points at the relay field); the message is what a human
 * reads. Neither ever contains the secret.
 */
export class InviteError extends Error {
  /**
   * @param code - stable machine-readable code.
   * @param message - human-readable explanation.
   */
  constructor(code, message) {
    super(message)
    this.name = 'InviteError'
    this.code = code
  }
}

/**
 * Build one invite.
 *
 * @param options.relay - the `ws:`/`wss:` relay endpoint.
 * @param options.inviteId - 32 hex characters; generated when omitted.
 * @param options.expiresAt - epoch ms; defaults to now + {@link DEFAULT_INVITE_TTL_MS}.
 * @param options.fingerprint - the host identity fingerprint, 16 hex characters.
 * @param options.pairSecret - base64url secret; generated when omitted.
 * @returns `{ uri, invite }`, where `invite` is the normalized form.
 * @throws {InviteError} when a supplied field is malformed.
 */
export function createInvite(options) {
  const relay = normalizeRelay(options?.relay)
  const inviteId = options?.inviteId ?? newInviteId()
  if (!SLOT_ID_PATTERN.test(String(inviteId))) {
    throw new InviteError('bad-invite-id', 'an invite id must be 4 to 64 lower-case letters or digits')
  }
  const expiresAt = options?.expiresAt ?? Date.now() + DEFAULT_INVITE_TTL_MS
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0) {
    throw new InviteError('bad-expiry', 'an invite expiry must be a positive epoch-millisecond integer')
  }
  const fingerprint = String(options?.fingerprint ?? '')
  if (!FINGERPRINT_PATTERN.test(fingerprint)) {
    throw new InviteError('bad-fingerprint', 'a host fingerprint must be 16 lowercase hex characters')
  }
  const pairSecret = options?.pairSecret ?? newPairSecret()
  if (!PAIR_SECRET_PATTERN.test(pairSecret)) {
    throw new InviteError('bad-secret', `a pairing secret must be ${String(PAIR_SECRET_BYTES)} base64url bytes`)
  }

  const invite = {
    version: SUPPORTED_VERSION,
    mode: JOIN_MODE.qr,
    relay,
    inviteId,
    expiresAt,
    fingerprint,
    pairSecret,
    secure: relay.startsWith('wss:'),
  }
  const query = new URLSearchParams({
    v: String(SUPPORTED_VERSION),
    relay,
    inviteId,
    exp: String(expiresAt),
    fp: fingerprint,
  })
  // The secret is appended after `#`, never as a query parameter. See the module
  // header: this is the difference between a secret and a logged secret.
  const uri = `${INVITE_SCHEME}://${INVITE_HOST}?${query.toString()}#${pairSecret}`
  if (uri.length > MAX_URI_LENGTH) {
    throw new InviteError('invite-too-long', `the invite is ${String(uri.length)} characters, over the ${String(MAX_URI_LENGTH)} limit`)
  }
  return { uri, invite }
}

/**
 * Build the join descriptor for a TYPED pairing — a device code and a password.
 *
 * There is no URI and no QR code, because the two values travel by being read off one
 * screen and typed into another. That is also why this mode cannot carry a pinned
 * fingerprint: a nine-digit code has nowhere to put one, and a human will not type 16
 * hex characters correctly. The consequence is a real one and it is not hidden —
 * `pairing-session.js` refuses to pretend, and the short authentication string exists
 * precisely because of it.
 *
 * @param options.relay - the relay both machines share. The guest must be configured
 *   with it, since a typed code cannot name one.
 * @param options.deviceCode - the nine digits shown on the host.
 * @param options.password - the temporary password shown on the host.
 * @param options.expiresAt - when the password stops being accepted.
 * @returns the join descriptor, shaped like an invite so one handshake serves both.
 * @throws {InviteError} on a malformed field.
 */
export function createDeviceJoin(options) {
  const relay = normalizeRelay(options?.relay)
  // Nine digits exactly, via the same normalizer the typed form uses — so a code with
  // separators works, and a five-digit value is refused HERE rather than silently
  // becoming a slot key that no host will ever register.
  const deviceCode = normalizeDeviceCode(options?.deviceCode)
  if (deviceCode === undefined) {
    throw new InviteError('bad-device-code', 'a device code is nine digits, for example 123 456 789')
  }
  const password = normalizePassword(options?.password)
  if (password === undefined) {
    throw new InviteError('bad-password', 'a pairing password is twelve characters, as shown on the host')
  }
  const expiresAt = options?.expiresAt ?? Date.now() + DEFAULT_INVITE_TTL_MS
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0) {
    throw new InviteError('bad-expiry', 'a pairing expiry must be a positive epoch-millisecond integer')
  }
  return {
    version: SUPPORTED_VERSION,
    mode: JOIN_MODE.code,
    relay,
    inviteId: deviceCode,
    expiresAt,
    pairSecret: password,
    secure: relay.startsWith('wss:'),
  }
}

/**
 * Which join mode a descriptor is, with an EXPLICIT `mode` always winning.
 *
 * Inferring from the presence of a fingerprint is a convenience for a descriptor built
 * by hand, but it must not be able to overrule a stated mode: `mode: 'qr'` with no
 * fingerprint is a defect, not a typed join, and inferring would turn a missing pin
 * into a silently unpinned pairing — the exact failure the mode field exists to make
 * impossible.
 *
 * @param invite - the descriptor.
 * @returns `qr` or `code`.
 */
export function joinModeOf(invite) {
  if (invite?.mode === JOIN_MODE.code) return JOIN_MODE.code
  if (invite?.mode === JOIN_MODE.qr) return JOIN_MODE.qr
  return invite?.fingerprint === undefined ? JOIN_MODE.code : JOIN_MODE.qr
}

/**
 * Parse one invite string.
 *
 * Never throws and never partially succeeds: a caller that gets `ok: true` has an
 * invite with every field validated, and a caller that gets `ok: false` has a
 * code it can act on.
 *
 * @param text - the scanned or pasted invite.
 * @returns `{ ok: true, invite, uri }` or `{ ok: false, code, error }`.
 */
export function parseInviteUri(text) {
  try {
    return { ok: true, ...parseInviteOrThrow(text) }
  } catch (error) {
    if (error instanceof InviteError) return { ok: false, code: error.code, error: error.message }
    return { ok: false, code: 'unparseable', error: `this is not a pairing invite: ${String(error?.message ?? error)}` }
  }
}

/**
 * Parse one invite, throwing on any defect.
 *
 * Kept separate from {@link parseInviteUri} so an internal caller that has
 * already validated (or is re-parsing its own output) can use the strict form
 * without unwrapping a result object.
 *
 * @param text - the invite string.
 * @returns `{ invite, uri }`.
 * @throws {InviteError} on every defect.
 */
export function parseInviteOrThrow(text) {
  if (typeof text !== 'string') throw new InviteError('not-text', 'a pairing invite must be a string')
  const trimmed = text.trim()
  if (trimmed.length === 0) throw new InviteError('empty', 'the pairing invite is empty')
  if (trimmed.length > MAX_URI_LENGTH) {
    throw new InviteError('invite-too-long', `the invite is ${String(trimmed.length)} characters, over the ${String(MAX_URI_LENGTH)} limit`)
  }

  let url
  try {
    url = new URL(trimmed)
  } catch {
    throw new InviteError('unparseable', 'the pairing invite is not a valid URI')
  }
  // `URL` lowercases the scheme and keeps the host; both are fixed for this
  // scheme, so a mismatch means this is a different link entirely.
  if (url.protocol !== `${INVITE_SCHEME}:`) {
    throw new InviteError('wrong-scheme', `a pairing invite must start with ${INVITE_SCHEME}://`)
  }
  if (url.hostname !== INVITE_HOST) {
    throw new InviteError('wrong-target', `a pairing invite must be addressed to ${INVITE_HOST}`)
  }
  if (url.pathname !== '' && url.pathname !== '/') {
    throw new InviteError('bad-path', 'a pairing invite must not carry a path')
  }

  // A secret in the query string is the mistake this format exists to prevent,
  // so it is refused BY NAME before the unknown-field sweep below, which would
  // otherwise hide the specific, actionable diagnosis behind a generic one.
  if (url.searchParams.has('pairSecret') || url.searchParams.has('secret')) {
    throw new InviteError('secret-in-query', 'the pairing secret must be in the URI fragment, never in the query string')
  }

  const seen = new Set()
  for (const key of url.searchParams.keys()) {
    if (!ALLOWED_QUERY_KEYS.includes(key)) throw new InviteError('unknown-field', `the invite carries an unknown field ${JSON.stringify(key)}`)
    if (seen.has(key)) throw new InviteError('duplicate-field', `the invite repeats the field ${JSON.stringify(key)}`)
    seen.add(key)
  }

  const version = Number(url.searchParams.get('v'))
  if (!Number.isInteger(version)) throw new InviteError('missing-version', 'the invite is missing its protocol version')
  if (version !== SUPPORTED_VERSION) {
    throw new InviteError('version-mismatch', `this invite speaks pairing v${String(version)}; this build speaks v${String(SUPPORTED_VERSION)}`)
  }

  const relay = normalizeRelay(url.searchParams.get('relay'))
  const inviteId = url.searchParams.get('inviteId') ?? ''
  if (!SLOT_ID_PATTERN.test(inviteId)) throw new InviteError('bad-invite-id', 'the invite id is not 4 to 64 lower-case letters or digits')
  const expiresAt = Number(url.searchParams.get('exp'))
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0) throw new InviteError('bad-expiry', 'the invite expiry is not an epoch-millisecond integer')
  const fingerprint = url.searchParams.get('fp') ?? ''
  if (!FINGERPRINT_PATTERN.test(fingerprint)) throw new InviteError('bad-fingerprint', 'the host fingerprint is not 16 lowercase hex characters')

  const hash = url.hash.startsWith('#') ? url.hash.slice(1) : url.hash
  if (hash.length === 0) throw new InviteError('missing-secret', 'the invite has no pairing secret (the part after "#")')
  if (!PAIR_SECRET_PATTERN.test(hash)) {
    throw new InviteError('bad-secret', `the pairing secret must be ${String(PAIR_SECRET_BYTES)} base64url bytes, that is 43 characters`)
  }

  const invite = {
    version,
    mode: JOIN_MODE.qr,
    relay,
    inviteId,
    expiresAt,
    fingerprint,
    pairSecret: hash,
    secure: relay.startsWith('wss:'),
  }
  return { invite, uri: trimmed }
}

/**
 * Validate one parsed invite against the clock and against its own shape.
 *
 * `parseInviteUri` already checks all of this, but this function is the gate that
 * `pairing-session.js` calls, and an invite can reach it WITHOUT having been parsed
 * — constructed in code, restored from storage, or handed over by a caller that
 * bypassed the parser. Re-checking here is what makes "an invite that reaches the
 * handshake has been validated" a property of the code rather than a convention.
 *
 * @param invite - a parsed invite.
 * @param now - the current epoch ms; injectable so the check is testable.
 * @returns `{ ok: true }` or `{ ok: false, code, error }`.
 */
export function validateInvite(invite, now = Date.now()) {
  if (invite === null || typeof invite !== 'object') return { ok: false, code: 'missing', error: 'there is no invite to validate' }
  if (invite.version !== SUPPORTED_VERSION) {
    return {
      ok: false,
      code: 'version-mismatch',
      error: `this invite speaks pairing v${String(invite.version)}; this build speaks v${String(SUPPORTED_VERSION)}`,
    }
  }
  const mode = joinModeOf(invite)
  try {
    normalizeRelay(invite.relay)
  } catch (error) {
    if (error instanceof InviteError) return { ok: false, code: error.code, error: error.message }
    return { ok: false, code: 'bad-relay', error: String(error?.message ?? error) }
  }
  if (!SLOT_ID_PATTERN.test(String(invite.inviteId))) {
    return { ok: false, code: 'bad-invite-id', error: 'the slot id is not 4 to 64 lower-case letters or digits' }
  }
  // A QR join is REQUIRED to pin a fingerprint; a typed join must not pretend to.
  // Accepting a fingerprint-less QR descriptor, or a code descriptor that carries one
  // it never showed the user, would be the kind of half-authenticated state this check
  // exists to make impossible.
  if (mode === JOIN_MODE.qr && !FINGERPRINT_PATTERN.test(String(invite.fingerprint))) {
    return { ok: false, code: 'bad-fingerprint', error: 'the host fingerprint is not 16 lowercase hex characters' }
  }
  if (!looksLikePassword(String(invite.pairSecret ?? ''))) {
    return {
      ok: false,
      code: 'bad-secret',
      error: 'the pairing secret must be 8 to 64 characters from A-Z, a-z, 0-9, "_" or "-"',
    }
  }
  if (!Number.isSafeInteger(invite.expiresAt) || invite.expiresAt <= 0) {
    return { ok: false, code: 'bad-expiry', error: 'the invite expiry is not an epoch-millisecond integer' }
  }
  if (now > invite.expiresAt) {
    const seconds = Math.max(1, Math.round((now - invite.expiresAt) / 1000))
    return { ok: false, code: 'expired', error: `this invite expired ${String(seconds)}s ago; ask the host for a new one` }
  }
  if (invite.expiresAt - now > MAX_INVITE_TTL_MS) {
    return { ok: false, code: 'implausible-expiry', error: 'this invite claims to be valid far into the future; refusing it' }
  }
  return { ok: true, mode }
}

/**
 * A redacted description of one invite, safe to log and to render in a UI.
 *
 * The secret never appears, and the invite id is truncated to a prefix: enough
 * to correlate two log lines about the same invite, not enough to be a credential.
 *
 * @param invite - a parsed invite.
 * @returns the loggable description.
 */
export function describeInvite(invite) {
  const mode = joinModeOf(invite)
  return {
    version: invite.version,
    mode,
    // For a typed pairing the device code is an ADDRESS, not a credential — it is
    // meant to be read aloud — so it is described in full. A QR invite id is
    // truncated: enough to correlate two log lines, not enough to be a slot key.
    ...(mode === JOIN_MODE.code
      ? { deviceCode: String(invite.inviteId) }
      : { inviteIdPrefix: String(invite.inviteId).slice(0, 8) }),
    relay: relayLabel(invite.relay),
    expiresAt: invite.expiresAt,
    ...(mode === JOIN_MODE.qr ? { fingerprint: invite.fingerprint } : {}),
    secure: invite.secure === true,
  }
}

/**
 * A short label for one relay endpoint, for status documents and logs.
 * @param relay - the relay URL.
 * @returns `host:port` when parseable, else a fixed placeholder.
 */
export function relayLabel(relay) {
  try {
    const url = new URL(String(relay))
    return url.port === '' ? url.hostname : `${url.hostname}:${url.port}`
  } catch {
    return '(unparseable relay)'
  }
}

/**
 * Normalize and validate one relay endpoint.
 *
 * Only `ws:`/`wss:` are accepted. `https:` is a common paste mistake and is
 * refused with a message that says so, because silently rewriting the scheme
 * would hide a genuine misconfiguration — and a plain `http:` relay is not a
 * relay at all.
 *
 * @param relay - the raw endpoint.
 * @returns the normalized endpoint.
 * @throws {InviteError} when it is missing, too long, or not a WebSocket URL.
 */
export function normalizeRelay(relay) {
  const text = typeof relay === 'string' ? relay.trim() : ''
  if (text.length === 0) throw new InviteError('missing-relay', 'the invite names no relay')
  if (text.length > MAX_RELAY_LENGTH) throw new InviteError('relay-too-long', 'the relay URL is implausibly long')
  let url
  try {
    url = new URL(text)
  } catch {
    throw new InviteError('bad-relay', 'the relay is not a valid URL')
  }
  if (url.protocol !== 'wss:' && url.protocol !== 'ws:') {
    const hint = url.protocol === 'https:' ? ' (use wss://, not https://)' : ''
    throw new InviteError('bad-relay', `a relay must be a ws:// or wss:// URL${hint}`)
  }
  return url.toString()
}
