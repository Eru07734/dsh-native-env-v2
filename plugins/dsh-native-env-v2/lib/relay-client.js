/**
 * dsh-native-env / relay-client — one client connection to a relay slot.
 *
 * This file is deliberately only about the RENDEZVOUS: connecting, proving the
 * invite secret to the relay, and moving opaque payloads to and from the other
 * end. It contains no cryptography of its own and no knowledge of the env
 * protocol, which is what keeps the two auditable separately:
 *
 *   - `relay-protocol.js` is the contract (and is shared with the relay),
 *   - this file is the transport (and is the only place that touches a socket),
 *   - `pairing-session.js` is the authentication (and is the only place that
 *     holds key material).
 *
 * The connection is `ws://` or `wss://`, and ONLY the `wss://` form is safe on the
 * public internet — but the relay never learns the env payloads either way,
 * because everything after the handshake is sealed by `e2ee.js`. TLS protects the
 * rendezvous (the join, the proof, the ephemeral public keys); E2EE protects the
 * session. Either one alone would be insufficient: TLS without E2EE trusts the
 * relay with the environment, and E2EE without TLS exposes the ephemeral key
 * exchange to trivial active tampering.
 *
 * @module dsh-native-env/relay-client
 */

import { EventEmitter } from 'node:events'

import { newNonce } from './e2ee.js'
import {
  RELAY_ERROR,
  RELAY_MESSAGE,
  RELAY_VERSION,
  PRESENCE,
  RelayError,
  authMessage,
  joinMessage,
  parseJson,
  parseRelayMessage,
} from './relay-protocol.js'
import { connectWebSocket } from './ws.js'

/** Default deadline for one relay exchange (join→challenge→auth→ready). */
export const DEFAULT_RELAY_TIMEOUT_MS = 15000

/**
 * One open relay slot.
 *
 * Emits `payload` (a string for the other end), `presence`, `close` and `error`.
 */
export class RelaySession extends EventEmitter {
  /**
   * @param options.ws - the open WebSocket.
   * @param options.role - `host` or `guest`.
   * @param options.inviteId - the invite id.
   * @param options.label - a diagnostic label.
   */
  constructor(options) {
    super()
    this.ws = options.ws
    this.role = options.role
    this.inviteId = options.inviteId
    this.label = options.label ?? `relay:${options.inviteId.slice(0, 8)}`
    this.peerPresent = false
    this.waiters = []
    this.closed = false

    this.onMessage = (text) => this.dispatch(text)
    this.onClose = (event) => this.handleClose(event)
    this.onError = (error) => this.handleError(error)
    this.ws.on('message', this.onMessage)
    this.ws.on('close', this.onClose)
    this.ws.on('error', this.onError)
  }

  /**
   * Route one inbound relay message.
   * @param text - the raw message.
   */
  dispatch(text) {
    const decoded = parseJson(text)
    if (!decoded.ok) {
      this.handleError(new RelayError(RELAY_ERROR.badMessage, decoded.error))
      return
    }
    const parsed = parseRelayMessage(decoded.value)
    if (!parsed.ok) {
      this.handleError(new RelayError(parsed.code, parsed.error))
      return
    }
    const message = parsed.message
    // Re-emitted so a caller can observe the rendezvous without this class
    // knowing what the caller is waiting for. Emitted BEFORE the type is handled,
    // so a listener that reacts to `ready` is not racing this method's own work.
    this.emit('message', message)
    switch (message.type) {
      case RELAY_MESSAGE.challenge:
        this.ws.send(JSON.stringify(authMessage({
          secret: this.secret,
          inviteId: this.inviteId,
          role: this.role,
          clientNonce: this.clientNonce,
          serverNonce: message.nonce,
        })))
        return
      case RELAY_MESSAGE.ready:
        this.markPeerPresent()
        return
      case RELAY_MESSAGE.waiting:
        return
      case RELAY_MESSAGE.presence:
        if (message.state === PRESENCE.peerJoined) this.markPeerPresent()
        else {
          this.peerPresent = false
          this.emit('presence', { state: message.state })
        }
        return
      case RELAY_MESSAGE.peer:
        this.emit('payload', message.payload)
        return
      case RELAY_MESSAGE.error:
        this.handleError(new RelayError(message.code, message.message))
        return
      default:
        this.handleError(new RelayError(RELAY_ERROR.badMessage, `unhandled relay message ${JSON.stringify(message.type)}`))
    }
  }

  /** Record that the other end has arrived and wake everyone waiting. */
  markPeerPresent() {
    if (this.peerPresent) return
    this.peerPresent = true
    for (const waiter of this.waiters.splice(0)) waiter.resolve()
    this.emit('presence', { state: PRESENCE.peerJoined })
  }

  /**
   * Wait until the other end occupies the slot.
   * @param timeoutMs - the deadline.
   * @returns a promise resolving once the peer is present.
   * @throws {RelayError} on timeout, or the relay's own error.
   */
  waitForPeer(timeoutMs = DEFAULT_RELAY_TIMEOUT_MS) {
    if (this.peerPresent) return Promise.resolve()
    if (this.closed) return Promise.reject(new RelayError('closed', 'the relay connection closed before the peer arrived'))
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject, timer: undefined }
      if (Number.isSafeInteger(timeoutMs) && timeoutMs > 0) {
        waiter.timer = setTimeout(() => {
          const index = this.waiters.indexOf(waiter)
          if (index >= 0) this.waiters.splice(index, 1)
          reject(
            new RelayError(
              'peer-timeout',
              `no peer joined this invite within ${String(Math.round(timeoutMs / 1000))}s; the invite may have expired, or the other machine may be offline`,
            ),
          )
        }, timeoutMs)
        waiter.timer.unref?.()
      }
      this.waiters.push(waiter)
    })
  }

  /**
   * Send one opaque payload to the other end.
   * @param payload - the payload string.
   * @throws {RelayError} when the slot is closed.
   */
  sendPayload(payload) {
    if (this.closed) throw new RelayError('closed', 'cannot send: the relay connection is closed')
    this.ws.send(JSON.stringify({ t: RELAY_MESSAGE.peer, d: String(payload) }))
  }

  /**
   * Record a fatal condition: reject waiters, emit once, close.
   * @param error - the cause.
   */
  handleError(error) {
    if (this.closed) return
    for (const waiter of this.waiters.splice(0)) waiter.reject(error)
    if (this.listenerCount('error') > 0) this.emit('error', error)
    else this.emit('relay-error', error)
    this.close()
  }

  /**
   * Handle the socket closing.
   * @param event - `{ code, reason }`.
   */
  handleClose(event) {
    if (this.closed) return
    this.closed = true
    for (const waiter of this.waiters.splice(0)) {
      waiter.reject(new RelayError('closed', `the relay connection closed (${String(event?.code ?? '?')})`))
    }
    this.detach()
    this.emit('close', event)
  }

  /** Detach listeners. */
  detach() {
    this.ws.off('message', this.onMessage)
    this.ws.off('close', this.onClose)
    this.ws.off('error', this.onError)
  }

  /** Close the slot. Idempotent. */
  close() {
    if (this.closed) return
    this.closed = true
    this.detach()
    try {
      this.ws.close(1000, 'done')
    } catch {
      /* already gone */
    }
    this.emit('close', { code: 1000, reason: 'closed locally' })
  }
}

/**
 * Open one relay slot and complete the rendezvous.
 *
 * The join/challenge/auth exchange happens here and nowhere else, so the client
 * nonce that the proof binds to is generated, used and discarded in one place.
 *
 * @param options.endpoint - the full `ws:`/`wss:` URL including the invite id.
 * @param options.inviteId - the invite id.
 * @param options.role - `host` or `guest`.
 * @param options.secret - the invite secret.
 * @param options.timeoutMs - the rendezvous deadline.
 * @param options.maxPayload - frame ceiling.
 * @param options.tls - extra `tls.connect` options.
 * @param options.logger - optional `{ info, warn }`.
 * @returns the open session.
 * @throws {RelayError} when the relay refuses the join or the proof.
 */
export async function openRelaySession(options) {
  const timeoutMs = Number.isSafeInteger(options.timeoutMs) ? options.timeoutMs : DEFAULT_RELAY_TIMEOUT_MS
  const ws = await connectWebSocket(options.endpoint, {
    timeoutMs,
    maxPayload: options.maxPayload,
    tls: options.tls,
    label: options.label,
  })

  const session = new RelaySession({ ws, role: options.role, inviteId: options.inviteId, label: options.label })
  session.secret = options.secret
  session.clientNonce = newNonce()

  // The rendezvous is one small state machine, and it is written as one promise so
  // that every way it can end — a challenge, a refusal, a close, a deadline —
  // settles exactly once and leaves no listener behind. An earlier revision raced
  // three separate promises here, which left a rejected promise nobody awaited and
  // turned a refused invite into an unhandled rejection in the host's log.
  await new Promise((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timer)
      session.off('message', onMessage)
      session.off('close', onClose)
      session.off('relay-error', onError)
    }
    const done = () => {
      cleanup()
      resolve()
    }
    const fail = (error) => {
      cleanup()
      reject(error)
    }
    const timer = setTimeout(() => {
      fail(new RelayError('timeout', `the relay did not answer within ${String(timeoutMs)} ms`))
    }, timeoutMs)
    timer.unref?.()
    const onMessage = (message) => {
      if (message.type === RELAY_MESSAGE.error) {
        fail(new RelayError(message.code, message.message))
        return
      }
      if (
        message.type === RELAY_MESSAGE.challenge ||
        message.type === RELAY_MESSAGE.ready ||
        message.type === RELAY_MESSAGE.waiting
      ) {
        done()
      }
    }
    const onClose = () => fail(new RelayError('closed', 'the relay connection closed during the rendezvous'))
    const onError = (error) => fail(error instanceof Error ? error : new RelayError('relay-error', String(error)))
    session.on('message', onMessage)
    session.on('close', onClose)
    session.on('relay-error', onError)
    ws.send(JSON.stringify(joinMessage({ inviteId: options.inviteId, role: options.role, nonce: session.clientNonce })))
  })

  return session
}

/**
 * Ask a relay to register one invite.
 *
 * Plain HTTPS rather than a WebSocket: this is a one-shot request, and the relay
 * serves registration on the same origin as the channel.
 *
 * @param options.url - the registration URL.
 * @param options.inviteId - the invite id.
 * @param options.secret - the invite secret, which the relay must hold to
 *   authorize the rendezvous.
 * @param options.expiresAt - the invite expiry.
 * @param options.previousSecret - the secret this slot was last registered with, when
 *   the caller is ROTATING it. Required to replace a live slot whose secret differs:
 *   without it, refreshing a device card's password could not reuse the same stable
 *   device code until the old slot expired, which would defeat the point of a stable
 *   code.
 * @param options.timeoutMs - the request deadline.
 * @returns the registration receipt.
 * @throws {RelayError} when the relay refuses.
 */
export async function registerInvite(options) {
  const timeoutMs = Number.isSafeInteger(options.timeoutMs) ? options.timeoutMs : DEFAULT_RELAY_TIMEOUT_MS
  let response
  try {
    response = await fetch(options.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        v: RELAY_VERSION,
        inviteId: options.inviteId,
        secret: options.secret,
        expiresAt: options.expiresAt,
        ...(options.previousSecret === undefined ? {} : { previousSecret: options.previousSecret }),
      }),
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (error) {
    throw new RelayError('unreachable', `the relay at ${options.url} is unreachable: ${String(error?.message ?? error)}`)
  }
  const text = await response.text()
  if (!response.ok) {
    let body
    try {
      body = JSON.parse(text)
    } catch {
      body = undefined
    }
    throw new RelayError(
      typeof body?.code === 'string' ? body.code : `http-${String(response.status)}`,
      typeof body?.message === 'string' ? body.message : `the relay answered ${String(response.status)}: ${text.slice(0, 200)}`,
    )
  }
  let receipt = {}
  try {
    receipt = JSON.parse(text)
  } catch {
    receipt = {}
  }
  return { ok: true, reRegistered: receipt.reRegistered === true, rotated: receipt.rotated === true }
}
