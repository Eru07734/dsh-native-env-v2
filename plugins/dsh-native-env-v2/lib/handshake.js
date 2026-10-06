/**
 * dsh-native-env / handshake — mutual authentication for one env connection,
 * plus the CHANNEL tag that keeps this wire separate from the net-bridge's.
 *
 * Copied from `dsh-net-bridge/lib/handshake.js`, which already solves the problem
 * this half has: the connection carries filesystem reads and shell commands, so
 * it must prove the shared secret in BOTH directions before a single business
 * frame is accepted. A bearer token sent on connect would be replayable off the
 * wire; an HMAC challenge/response over fresh nonces never puts the secret on
 * the wire, and it additionally lets the dialing side detect that it reached the
 * real host rather than an unrelated service that owns the port.
 *
 * Exchange (both frames are ordinary JSON-RPC requests, so the same
 * {@link LineWire} carries them):
 *
 *   peer → host   bridge/hello { version, peer, nonce, channel }
 *   host → peer   { ok, version, nonce, hmac: HMAC(token, host|clientNonce|serverNonce) }
 *   peer → host   bridge/auth  { hmac: HMAC(token, peer|clientNonce|serverNonce) }
 *   host → peer   { ok, peer }
 *
 * The ONE addition over the net-bridge copy is `channel`. The net-bridge's host
 * side keys its registry by peer name and holds exactly ONE socket per peer
 * (`Hub.#adopt` → `peer.attach({socket, …})`), so an env connection that reused
 * the net-bridge's port under the same peer name would displace the live keeper
 * connection. This plugin therefore listens on its own port, and the channel tag
 * makes the two wires self-identifying: a frame meant for the other listener is
 * refused instead of half-understood.
 *
 * Digests are compared in constant time. Nothing here encrypts the session
 * stream: v1 is authenticated, not confidential.
 *
 * @module dsh-native-env/handshake
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

/** Wire version of the env extension namespace. */
export const BRIDGE_VERSION = 1

/** Method names owned by this plugin; they never reach a DSH runtime. */
export const HELLO_METHOD = 'bridge/hello'
export const AUTH_METHOD = 'bridge/auth'

/**
 * The two wires this handshake serves. `runtime` is the net-bridge's (the
 * default when a frame omits the field, so an older guest keeper still parses),
 * `env` is ours.
 */
export const CHANNEL_RUNTIME = 'runtime'
export const CHANNEL_ENV = 'env'

/** A peer name is a stable, filesystem-safe, log-safe label. */
export const PEER_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/

/** @returns a fresh 128-bit nonce as lowercase hex. */
export function newNonce() {
  return randomBytes(16).toString('hex')
}

/**
 * Compute one handshake digest.
 * @param token - the shared secret.
 * @param parts - domain separator and nonces, joined with `|`.
 * @returns lowercase hex HMAC-SHA256.
 */
export function proof(token, ...parts) {
  return createHmac('sha256', token).update(parts.join('|')).digest('hex')
}

/** The digest the host must return to prove it knows the token. */
export function hostProof(token, clientNonce, serverNonce) {
  return proof(token, 'host', clientNonce, serverNonce)
}

/** The digest the dialing peer must return to prove it knows the token. */
export function peerProof(token, clientNonce, serverNonce) {
  return proof(token, 'peer', clientNonce, serverNonce)
}

/**
 * Constant-time comparison of two hex digests.
 * @param a - first digest.
 * @param b - second digest.
 * @returns true only when both are non-empty, equal-length, and equal.
 */
export function sameProof(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  if (a.length === 0 || a.length !== b.length) return false
  const left = Buffer.from(a, 'utf8')
  const right = Buffer.from(b, 'utf8')
  return left.length === right.length && timingSafeEqual(left, right)
}

/**
 * Validate the peer-supplied hello parameters.
 *
 * `channel` is optional and defaults to `runtime`, so a net-bridge guest that
 * predates this file still parses. A caller that owns a specific wire passes
 * `expectedChannel` and gets a refusal for anything else — which is what stops
 * an env listener from accepting a runtime dial-in and then answering frames it
 * does not implement.
 *
 * @param params - raw `bridge/hello` params.
 * @param expectedChannel - the channel this listener serves, when it has one.
 * @returns the normalized `{ version, peer, nonce, channel }`.
 * @throws when a field is missing or malformed, so the connection is refused
 *   before any state is created.
 */
export function parseHello(params, expectedChannel) {
  const version = params.version
  if (version !== BRIDGE_VERSION) {
    throw new Error(`env-bridge: unsupported protocol version ${JSON.stringify(version)} (this side speaks ${BRIDGE_VERSION})`)
  }
  const peer = params.peer
  if (typeof peer !== 'string' || !PEER_NAME_PATTERN.test(peer)) {
    throw new Error('env-bridge: hello.peer must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}')
  }
  const nonce = params.nonce
  if (typeof nonce !== 'string' || !/^[0-9a-f]{16,64}$/.test(nonce)) {
    throw new Error('env-bridge: hello.nonce must be 16-64 lowercase hex characters')
  }
  const channel = params.channel === undefined ? CHANNEL_RUNTIME : params.channel
  if (channel !== CHANNEL_RUNTIME && channel !== CHANNEL_ENV) {
    throw new Error(`env-bridge: hello.channel must be ${JSON.stringify(CHANNEL_RUNTIME)} or ${JSON.stringify(CHANNEL_ENV)}`)
  }
  if (expectedChannel !== undefined && channel !== expectedChannel) {
    throw new Error(
      `env-bridge: this listener serves channel ${JSON.stringify(expectedChannel)} but the peer asked for ${JSON.stringify(channel)}`,
    )
  }
  return { version, peer, nonce, channel }
}

/**
 * Dialing-side handshake: prove the token to the host and verify the host.
 *
 * @param wire - a started {@link LineWire} over the socket.
 * @param options.token - shared secret; never sent on the wire.
 * @param options.peer - this peer's stable name.
 * @param options.channel - the wire being dialed; defaults to {@link CHANNEL_ENV}.
 * @param options.timeoutMs - deadline for each exchange.
 * @returns the authenticated peer name, the host's reported version, and the channel.
 * @throws when the host rejects the hello/auth frames or proves the wrong token.
 */
export async function authenticateAsPeer(wire, options) {
  const { token, peer, channel = CHANNEL_ENV, timeoutMs = 5000 } = options
  if (typeof token !== 'string' || token.length === 0) throw new Error('env-bridge: a token is required to dial out')
  const clientNonce = newNonce()

  const hello = await wire.request(
    HELLO_METHOD,
    { version: BRIDGE_VERSION, peer, nonce: clientNonce, channel },
    AbortSignal.timeout(timeoutMs),
  )
  if (hello === null || typeof hello !== 'object' || hello.ok !== true) {
    throw new Error('env-bridge: host refused the hello frame')
  }
  const serverNonce = hello.nonce
  if (typeof serverNonce !== 'string' || !sameProof(hello.hmac, hostProof(token, clientNonce, serverNonce))) {
    throw new Error('env-bridge: host failed to prove the shared token (wrong token, or the listener is not a DSH env bridge)')
  }

  const ack = await wire.request(AUTH_METHOD, { hmac: peerProof(token, clientNonce, serverNonce) }, AbortSignal.timeout(timeoutMs))
  if (ack === null || typeof ack !== 'object' || ack.ok !== true) {
    throw new Error('env-bridge: host rejected the auth frame')
  }
  return {
    peer: typeof ack.peer === 'string' ? ack.peer : peer,
    version: hello.version ?? BRIDGE_VERSION,
    channel: typeof hello.channel === 'string' ? hello.channel : channel,
  }
}
