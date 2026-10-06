/**
 * dsh-native-env / relay-protocol — the message contract between a DSH half and
 * the relay, and the endpoint arithmetic around it.
 *
 * Both the plugin and the relay import this file, so a message name or an error
 * code can never drift between the two sides. That matters more here than
 * elsewhere in the plugin: the relay is a SEPARATE DEPLOYMENT, possibly running
 * an older build, and a protocol mismatch has to produce "this relay speaks v1,
 * this build speaks v2" rather than a frame the other side silently ignores.
 *
 * The relay's whole job is to bring two ends together, so the contract is small
 * on purpose:
 *
 *   client → relay   join       who is asking, for which invite, in which role
 *   relay  → client  challenge  a fresh nonce to prove the invite secret against
 *   client → relay   auth       that proof
 *   relay  → client  ready      both roles are present; forward from now on
 *   either way       peer       one OPAQUE payload for the other end
 *   relay  → client  presence   the other end arrived or left
 *   relay  → client  error      the invite is unknown, expired, used, or full
 *
 * `peer` payloads are opaque to the relay: after the pairing handshake they are
 * AES-256-GCM ciphertext. The relay frames them without parsing, and is written
 * so that it could not parse them if it wanted to — there is no env method name,
 * no tool name, and no file path anywhere in the relay's code path.
 *
 * @module dsh-native-env/relay-protocol
 */

import { createHmac } from 'node:crypto'

/** Wire version of the relay protocol. */
export const RELAY_VERSION = 2

/** The two roles an invite admits. Exactly one of each may occupy an invite. */
export const ROLE_HOST = 'host'
export const ROLE_GUEST = 'guest'

/** Every message type on the relay wire. */
export const RELAY_MESSAGE = Object.freeze({
  /** client → relay: open a slot. */
  join: 'join',
  /** relay → client: prove the invite secret against this nonce. */
  challenge: 'challenge',
  /** client → relay: the invite-secret proof. */
  auth: 'auth',
  /** relay → client: the slot is open and the peer is present. */
  ready: 'ready',
  /** relay → client: the slot is open, the peer is not here yet. */
  waiting: 'waiting',
  /** either way: one opaque payload for the other end. */
  peer: 'peer',
  /** relay → client: the peer arrived or left. */
  presence: 'presence',
  /** relay → client: something is wrong with this slot. */
  error: 'error',
})

/**
 * Error codes the relay may send.
 *
 * Each one maps to a distinct operator action, which is why they are separate
 * codes rather than one "refused": `invite-unknown` means the host never
 * registered it (or it expired), `invite-used` means someone already paired on
 * it, and `role-taken` means a second guest is trying to join.
 */
export const RELAY_ERROR = Object.freeze({
  inviteUnknown: 'invite-unknown',
  inviteExpired: 'invite-expired',
  inviteUsed: 'invite-used',
  roleTaken: 'role-taken',
  badRole: 'bad-role',
  badMessage: 'bad-message',
  authFailed: 'auth-failed',
  versionMismatch: 'version-mismatch',
  rateLimited: 'rate-limited',
  shuttingDown: 'shutting-down',
})

/** Presence states a client may be told about. */
export const PRESENCE = Object.freeze({
  peerJoined: 'peer-joined',
  peerLeft: 'peer-left',
})

/** Default relay paths, appended to the relay ORIGIN the invite carries. */
export const RELAY_INVITE_PATH = '/v2/invites'
export const RELAY_CHANNEL_PATH = '/v2/relay'
export const RELAY_HEALTH_PATH = '/healthz'

/**
 * A relay protocol violation on this side.
 *
 * Carries the relay's code when the relay supplied one, so a caller can branch
 * on `error.code` without string-matching a message.
 */
export class RelayError extends Error {
  /**
   * @param code - a {@link RELAY_ERROR} value, or a local code.
   * @param message - the human-readable explanation.
   */
  constructor(code, message) {
    super(message)
    this.name = 'RelayError'
    this.code = code
  }
}

/**
 * Build the WebSocket endpoint for one invite from the relay base in the invite.
 *
 * The invite carries the CHANNEL base (`wss://relay.example.test/v2/relay`), and
 * the invite id is appended as the last path segment. Appending rather than
 * putting it in a query string keeps it out of `Referer`-style logging by proxies
 * that log path-only, and matches how the relay routes.
 *
 * @param relayBase - the `ws:`/`wss:` base from the invite.
 * @param inviteId - the 32-hex invite id.
 * @returns the endpoint URL.
 */
export function relayEndpoint(relayBase, inviteId) {
  const base = String(relayBase)
  const trimmed = base.endsWith('/') ? base.slice(0, -1) : base
  return `${trimmed}/${encodeURIComponent(inviteId)}`
}

/**
 * Build the HTTPS URL for registering an invite, from the same base.
 *
 * The scheme is rewritten `ws→http` / `wss→https`: registration is an ordinary
 * request, and the relay serves both on one origin.
 *
 * @param relayBase - the `ws:`/`wss:` base from the invite.
 * @returns the registration URL.
 */
export function relayRegisterUrl(relayBase) {
  const url = new URL(String(relayBase))
  url.protocol = url.protocol === 'wss:' ? 'https:' : 'http:'
  // The channel base ends in `/v2/relay`; registration lives beside it.
  url.pathname = url.pathname.replace(/\/v2\/relay\/?$/, RELAY_INVITE_PATH)
  return url.toString()
}

/**
 * Build the health URL from the same base.
 * @param relayBase - the `ws:`/`wss:` base.
 * @returns the health endpoint URL.
 */
export function relayHealthUrl(relayBase) {
  const url = new URL(relayRegisterUrl(relayBase))
  url.pathname = RELAY_HEALTH_PATH
  return url.toString()
}

/** @returns true when `role` is one of the two defined roles. */
export function isRole(role) {
  return role === ROLE_HOST || role === ROLE_GUEST
}

/**
 * Validate one inbound relay message.
 *
 * Returns a discriminated result rather than throwing so a hostile or merely
 * older relay produces a diagnosable state instead of an exception inside a
 * WebSocket event handler, where an unhandled throw takes the process down.
 *
 * @param raw - the parsed message.
 * @returns `{ ok: true, message }` or `{ ok: false, code, error }`.
 */
export function parseRelayMessage(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, code: RELAY_ERROR.badMessage, error: 'a relay message must be a JSON object' }
  }
  const type = raw.t
  if (typeof type !== 'string') return { ok: false, code: RELAY_ERROR.badMessage, error: 'a relay message must carry a "t" field' }
  if (!Object.values(RELAY_MESSAGE).includes(type)) {
    return { ok: false, code: RELAY_ERROR.badMessage, error: `unknown relay message type ${JSON.stringify(type)}` }
  }
  if (type === RELAY_MESSAGE.error) {
    return {
      ok: true,
      message: { type, code: typeof raw.code === 'string' ? raw.code : RELAY_ERROR.badMessage, message: typeof raw.message === 'string' ? raw.message : 'the relay refused' },
    }
  }
  if (type === RELAY_MESSAGE.peer) {
    if (typeof raw.d !== 'string') return { ok: false, code: RELAY_ERROR.badMessage, error: 'a peer payload must be a string' }
    return { ok: true, message: { type, payload: raw.d } }
  }
  if (type === RELAY_MESSAGE.challenge) {
    if (typeof raw.nonce !== 'string' || !/^[0-9a-f]{16,64}$/.test(raw.nonce)) {
      return { ok: false, code: RELAY_ERROR.badMessage, error: 'the challenge nonce is malformed' }
    }
    if (Number.isInteger(raw.v) && raw.v !== RELAY_VERSION) {
      return {
        ok: false,
        code: RELAY_ERROR.versionMismatch,
        error: `the relay speaks protocol v${String(raw.v)}; this build speaks v${String(RELAY_VERSION)}`,
      }
    }
    return { ok: true, message: { type, nonce: raw.nonce, expiresAt: Number.isSafeInteger(raw.expiresAt) ? raw.expiresAt : undefined } }
  }
  if (type === RELAY_MESSAGE.presence) {
    const state = raw.state
    if (state !== PRESENCE.peerJoined && state !== PRESENCE.peerLeft) {
      return { ok: false, code: RELAY_ERROR.badMessage, error: `unknown presence state ${JSON.stringify(state)}` }
    }
    return { ok: true, message: { type, state } }
  }
  return { ok: true, message: { type } }
}

/**
 * The frame a client sends to open a slot.
 *
 * @param options.inviteId - the invite id.
 * @param options.role - `host` or `guest`.
 * @param options.nonce - a fresh client nonce.
 * @returns the join message.
 */
export function joinMessage(options) {
  return { t: RELAY_MESSAGE.join, v: RELAY_VERSION, inviteId: options.inviteId, role: options.role, nonce: options.nonce }
}

/**
 * The frame a client sends to prove the invite secret.
 *
 * The transcript order is fixed here and mirrored in the relay, because an HMAC
 * over a different field order is a different HMAC — the one class of bug this
 * shared module exists to prevent.
 *
 * @param options.secret - the invite secret.
 * @param options.inviteId - the invite id.
 * @param options.role - the role being claimed.
 * @param options.clientNonce - the nonce from the join.
 * @param options.serverNonce - the nonce from the challenge.
 * @returns the auth message.
 */
export function authMessage(options) {
  return {
    t: RELAY_MESSAGE.auth,
    proof: relayJoinProof(options.secret, options.inviteId, options.role, options.clientNonce, options.serverNonce),
  }
}

/**
 * Compute the invite-secret proof the relay verifies.
 *
 * HMAC rather than a signature because the verifier must be able to recompute it
 * from the secret it stored. This proof authorizes the RENDEZVOUS only: it is not
 * what authenticates the two machines to each other, and it is deliberately not
 * reused for that (see `pairing-session.js`, where the machines authenticate with
 * Ed25519 signatures that survive a compromised relay).
 *
 * @param secret - the invite secret.
 * @param inviteId - the invite id.
 * @param role - the role being claimed.
 * @param clientNonce - the client's nonce.
 * @param serverNonce - the relay's nonce.
 * @returns lowercase hex digest.
 */
export function relayJoinProof(secret, inviteId, role, clientNonce, serverNonce) {
  return createHmac('sha256', String(secret))
    .update(['relay', inviteId, role, clientNonce, serverNonce].join('|'))
    .digest('hex')
}

/** One JSON string, parsed. Used by both ends to keep decode errors uniform. */
export function parseJson(text) {
  try {
    return { ok: true, value: JSON.parse(String(text)) }
  } catch (error) {
    return { ok: false, error: `the message is not JSON: ${String(error?.message ?? error)}` }
  }
}
