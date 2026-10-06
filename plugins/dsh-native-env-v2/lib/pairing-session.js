/**
 * dsh-native-env / pairing-session — authenticating two machines THROUGH a relay
 * neither of them trusts.
 *
 * The relay authorizes the rendezvous: it holds the invite secret for the
 * invite's lifetime, and without that proof nothing gets paired. But a party that
 * holds the invite secret is exactly the party able to sit in the middle of the
 * connection, so the rendezvous proof cannot also be what authenticates the two
 * machines to each other. If it were, a malicious relay would simply claim to be
 * the host.
 *
 * The handshake below therefore authenticates with Ed25519 signatures over a
 * transcript that includes both ephemeral keys, and the guest checks the host's
 * identity against the FINGERPRINT PINNED IN THE INVITE. That pin is what a
 * compromised relay cannot forge.
 *
 * The order is chosen so that no sensitive value reaches the relay, and no env
 * frame moves before both sides are authenticated:
 *
 *   1. guest → host   hello   ephemeral X25519 public key, nonce, IV prefix
 *   2. host  → guest  ack     the same, plus the host's own
 *      (both derive the session keys; everything after this is encrypted)
 *   3. guest → host   ident   guest identity key + signature, SEALED
 *   4. host  → guest  ident   host identity key + signature, SEALED
 *   5. guest → host   meta    label and platform, only AFTER the host verified
 *   6. host  → guest  meta    the same for the host
 *   7. guest → host   ready   the guest is authenticated and listening
 *
 * A relay therefore observes: an invite id, two role names, two ephemeral public
 * keys, and ciphertext. It does not observe a hostname, a fingerprint, a tool
 * name, an argument, a path, or a result. Step 5 is deliberately last-but-one for
 * exactly that reason: the guest's hostname is more identifying than its public
 * key, so it is only disclosed once the host has proven it is the pinned host.
 *
 * A relay that substitutes its own ephemeral keys succeeds only as far as step 4:
 * the guest verifies the host's signature against a transcript containing the
 * RELAY's key, and the real host's signature does not verify against it. The
 * failure is fatal by design — there is no "continue anyway" path.
 *
 * @module dsh-native-env/pairing-session
 */

import { EventEmitter } from 'node:events'

import {
  PAIRING_VERSION,
  CryptoFailure,
  deriveSessionKeys,
  exportPublicKey,
  fingerprint,
  generateEphemeral,
  importPublicKey,
  newIvPrefix,
  newNonce,
  sharedSecret,
  shortAuthString,
  signTranscript,
  verifyTranscript,
} from './e2ee.js'
import { LineReader, createE2eeStream } from './e2ee-channel.js'
import { validateInvite } from './pairing.js'
import { ROLE_GUEST, ROLE_HOST, RELAY_ERROR, RelayError, relayEndpoint } from './relay-protocol.js'
import { openRelaySession } from './relay-client.js'

/** The default deadline for the whole handshake. */
export const DEFAULT_PAIR_TIMEOUT_MS = 20000

/** Handshake message types. Distinct from the relay's own `RELAY_MESSAGE` set. */
const PAIR_MESSAGE = Object.freeze({
  hello: 'hello',
  ack: 'ack',
  ident: 'ident',
  meta: 'meta',
  ready: 'ready',
})

/**
 * A pairing failure with a code the UI can branch on.
 *
 * `fingerprint-mismatch` in particular must be distinguishable from every other
 * failure: it is the one outcome that means "stop, something is wrong", as opposed
 * to "try again".
 */
export class PairingError extends Error {
  /**
   * @param code - a stable machine-readable code.
   * @param message - the human-readable explanation.
   */
  constructor(code, message) {
    super(message)
    this.name = 'PairingError'
    this.code = code
  }
}

/**
 * The exact bytes both sides sign, so a signature can never be replayed onto a
 * different session, invite, role or peer.
 *
 * @param options.side - `host` or `guest`, the side whose signature this is.
 * @param options.inviteId - the invite id.
 * @param options.guestEphemeral - the guest's ephemeral public key, base64.
 * @param options.hostEphemeral - the host's ephemeral public key, base64.
 * @param options.guestNonce - the guest's nonce.
 * @param options.hostNonce - the host's nonce.
 * @returns the transcript string.
 */
export function pairingTranscript(options) {
  return [
    'dsh-native-env/pair',
    String(PAIRING_VERSION),
    options.side,
    options.inviteId,
    options.guestEphemeral,
    options.hostEphemeral,
    options.guestNonce,
    options.hostNonce,
  ].join('|')
}

/**
 * A queue of plaintext payloads from the other end, used before the handshake has
 * produced an encrypted stream.
 *
 * Messages arrive as whole JSON objects rather than as newline-delimited text, so
 * this is a queue and not a line reader; conflating the two would put a framing
 * assumption on the encrypted channel that does not hold for the plaintext phase.
 */
class PayloadQueue extends EventEmitter {
  /**
   * @param session - the relay session.
   * @param timeoutMs - the default per-message deadline.
   */
  constructor(session, timeoutMs) {
    super()
    this.session = session
    this.timeoutMs = timeoutMs
    this.queue = []
    this.waiters = []
    this.closed = false
    this.onPayload = (payload) => this.push(payload)
    this.onClose = () => this.failAll(new PairingError('relay-closed', 'the relay connection closed during the pairing handshake'))
    session.on('payload', this.onPayload)
    session.on('close', this.onClose)
  }

  /**
   * Queue one raw payload.
   * @param payload - the payload string.
   */
  push(payload) {
    if (this.closed) return
    const waiter = this.waiters.shift()
    if (waiter !== undefined) {
      waiter.resolve(payload)
      return
    }
    this.queue.push(payload)
  }

  /**
   * Await the next payload.
   * @param timeoutMs - overrides the default deadline.
   * @returns the payload string.
   */
  next(timeoutMs = this.timeoutMs) {
    const queued = this.queue.shift()
    if (queued !== undefined) return Promise.resolve(queued)
    if (this.closed) return Promise.reject(new PairingError('closed', 'the pairing channel is closed'))
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject, timer: undefined }
      waiter.timer = setTimeout(() => {
        const index = this.waiters.indexOf(waiter)
        if (index >= 0) this.waiters.splice(index, 1)
        reject(new PairingError('timeout', `the peer did not answer within ${String(Math.round(timeoutMs / 1000))}s`))
      }, timeoutMs)
      waiter.timer.unref?.()
      this.waiters.push(waiter)
    })
  }

  /**
   * Await the next payload and parse it as one handshake message.
   *
   * A peer that sends malformed JSON here is refused by name rather than being
   * allowed to throw inside an event handler.
   *
   * @param expected - the message type expected.
   * @param timeoutMs - the deadline.
   * @returns the parsed message.
   */
  async nextMessage(expected, timeoutMs) {
    const raw = await this.next(timeoutMs)
    let parsed
    try {
      parsed = JSON.parse(raw)
    } catch (error) {
      throw new PairingError('malformed', `the peer sent a pairing message that is not JSON: ${String(error?.message ?? error)}`)
    }
    if (parsed === null || typeof parsed !== 'object' || parsed.t !== expected) {
      throw new PairingError('unexpected-message', `expected a ${JSON.stringify(expected)} message, got ${JSON.stringify(parsed?.t ?? parsed)}`)
    }
    return parsed
  }

  /**
   * Reject every waiter.
   * @param error - the cause.
   */
  failAll(error) {
    if (this.closed) return
    this.closed = true
    for (const waiter of this.waiters.splice(0)) waiter.reject(error)
  }

  /**
   * Stop consuming payloads, handing any that were already queued to `forward`.
   *
   * This is the switchover from the plaintext phase to the encrypted one, and the
   * forwarding is what makes it lossless: a payload that arrived while the queue
   * was still the listener would otherwise sit in this queue forever and be
   * decrypted never, which presents as a handshake that hangs on one side while
   * the other waits for a reply.
   *
   * @param forward - `(payload: string) => void`, called for each queued payload.
   * @returns the number of payloads forwarded.
   */
  detach(forward) {
    this.session.off('payload', this.onPayload)
    const queued = this.queue.splice(0)
    this.closed = true
    for (const payload of queued) forward(payload)
    return queued.length
  }

  /**
   * Detach from the relay session and reject anyone still waiting.
   *
   * Unlike {@link failAll} this always rejects, even after {@link detach} has
   * already marked the queue closed: a waiter left over from the plaintext phase
   * would otherwise hang forever on a channel nobody is reading any more.
   */
  dispose() {
    this.session.off('payload', this.onPayload)
    this.session.off('close', this.onClose)
    const error = new PairingError('disposed', 'the pairing channel was disposed')
    for (const waiter of this.waiters.splice(0)) waiter.reject(error)
    this.closed = true
  }
}

/**
 * Build one `hello`/`ack` message from this side's ephemeral material.
 * @param options.ephemeral - this side's X25519 keypair.
 * @param options.nonce - this side's nonce.
 * @param options.iv - this side's IV prefix, hex.
 * @returns the message.
 */
function ephemeralMessage(type, options) {
  return { t: type, v: PAIRING_VERSION, eph: exportPublicKey(options.ephemeral.publicKey), nonce: options.nonce, iv: options.iv }
}

/**
 * Validate one `hello`/`ack` message.
 * @param message - the parsed message.
 * @param label - which message this is, for the error text.
 * @returns `{ ephemeral, nonce, iv }`.
 * @throws {PairingError} on any defect.
 */
function readEphemeralMessage(message, label) {
  if (Number(message.v) !== PAIRING_VERSION) {
    throw new PairingError(
      'version-mismatch',
      `the peer speaks pairing v${String(message.v)}; this build speaks v${String(PAIRING_VERSION)}`,
    )
  }
  if (typeof message.eph !== 'string' || message.eph.length === 0) {
    throw new PairingError('malformed', `the peer's ${label} carries no ephemeral key`)
  }
  if (typeof message.nonce !== 'string' || !/^[0-9a-f]{16,64}$/.test(message.nonce)) {
    throw new PairingError('malformed', `the peer's ${label} carries a malformed nonce`)
  }
  if (typeof message.iv !== 'string' || !/^[0-9a-f]{8}$/.test(message.iv)) {
    throw new PairingError('malformed', `the peer's ${label} carries a malformed IV prefix`)
  }
  return { ephemeral: message.eph, nonce: message.nonce, iv: Buffer.from(message.iv, 'hex') }
}

/**
 * Establish one authenticated, encrypted session over a relay.
 *
 * @param options.invite - the parsed invite.
 * @param options.role - `host` or `guest`.
 * @param options.identity - `{ publicKey, privateKey }`, this machine's Ed25519 identity.
 * @param options.label - this machine's display label, disclosed only after mutual
 *   authentication.
 * @param options.platform - this machine's platform string.
 * @param options.timeoutMs - the handshake deadline.
 * @param options.signal - an optional abort signal. Aborting closes the relay
 *   session, which is what makes every wait below fail rather than hang — a
 *   cancelled attempt that left its socket open would leak a relay slot and, on a
 *   relay with a per-address limit, eventually stop pairing altogether.
 * @param options.maxPayload - the relay frame ceiling.
 * @param options.tls - extra `tls.connect` options.
 * @param options.logger - optional `{ info, warn }`.
 * @returns `{ stream, session, peer, close }`.
 * @throws {PairingError} on every authentication or protocol failure.
 */
export async function establishPairedStream(options) {
  const invite = options.invite
  if (invite === null || typeof invite !== 'object') throw new PairingError('no-invite', 'there is no invite to pair with')
  const verdict = validateInvite(invite)
  if (!verdict.ok) throw new PairingError(verdict.code, verdict.error)
  const role = options.role === ROLE_HOST ? ROLE_HOST : options.role === ROLE_GUEST ? ROLE_GUEST : undefined
  if (role === undefined) throw new PairingError('bad-role', `role must be ${JSON.stringify(ROLE_HOST)} or ${JSON.stringify(ROLE_GUEST)}`)
  const identity = options.identity
  if (identity === undefined) throw new PairingError('no-identity', 'this machine has no pairing identity')
  if (options.signal?.aborted) throw new PairingError('aborted', 'the pairing attempt was cancelled before it started')

  const timeoutMs = Number.isSafeInteger(options.timeoutMs) ? options.timeoutMs : DEFAULT_PAIR_TIMEOUT_MS
  const logger = options.logger

  let session
  try {
    session = await openRelaySession({
      // A host with an embedded public relay dials its own loopback listener.
      // The advertised invite and its identity/authentication transcript stay intact.
      endpoint: relayEndpoint(options.relayBase ?? invite.relay, invite.inviteId),
      inviteId: invite.inviteId,
      role,
      secret: invite.pairSecret,
      timeoutMs: Math.min(timeoutMs, 15000),
      maxPayload: options.maxPayload,
      tls: options.tls,
      label: `relay:${role}`,
      logger,
    })
  } catch (error) {
    if (error instanceof RelayError) throw new PairingError(error.code, error.message)
    throw new PairingError('relay-unreachable', String(error?.message ?? error))
  }

  // Every wait below is settled by closing the session, so one abort listener
  // registered here is enough to unwind the whole handshake.
  const onAbort = () => session.close()
  options.signal?.addEventListener('abort', onAbort, { once: true })
  if (options.signal?.aborted) {
    session.close()
    throw new PairingError('aborted', 'the pairing attempt was cancelled')
  }

  // The queue is attached BEFORE waiting for the peer, and that order is
  // load-bearing: the other end may send its `hello` in the same tick the relay
  // reports it joined, and a listener attached afterwards would never see it —
  // which presents as a handshake timeout on a connection that is working fine.
  const queue = new PayloadQueue(session, timeoutMs)

  try {
    await session.waitForPeer(timeoutMs)
  } catch (error) {
    queue.dispose()
    session.close()
    // `waitForPeer` rejects for a deadline AND for a relay refusal that arrives
    // while waiting (a wrong secret, a taken role). Collapsing both into
    // "peer-timeout" would tell an operator to wait, when the truth is that the
    // invite was rejected and waiting cannot help.
    if (error instanceof RelayError) throw new PairingError(error.code, error.message)
    throw new PairingError('peer-timeout', String(error?.message ?? error))
  }

  let stream
  /** The listener that routes post-handshake payloads into the encrypted stream. */
  let feedPayload

  /** Abandon the handshake, closing everything this function opened. */
  const abandon = () => {
    if (feedPayload !== undefined) session.off('payload', feedPayload)
    queue.dispose()
    stream?.end()
    session.close()
  }

  try {
    const ephemeral = generateEphemeral()
    const nonce = newNonce()
    const iv = newIvPrefix()

    let guestSide
    let hostSide
    if (role === ROLE_GUEST) {
      session.sendPayload(JSON.stringify(ephemeralMessage(PAIR_MESSAGE.hello, { ephemeral, nonce, iv: iv.toString('hex') })))
      const ack = readEphemeralMessage(await queue.nextMessage(PAIR_MESSAGE.ack, timeoutMs), 'ack')
      guestSide = { ephemeral: exportPublicKey(ephemeral.publicKey), nonce, iv }
      hostSide = ack
    } else {
      const hello = readEphemeralMessage(await queue.nextMessage(PAIR_MESSAGE.hello, timeoutMs), 'hello')
      guestSide = hello
      hostSide = { ephemeral: exportPublicKey(ephemeral.publicKey), nonce, iv }
      session.sendPayload(JSON.stringify(ephemeralMessage(PAIR_MESSAGE.ack, { ephemeral, nonce, iv: iv.toString('hex') })))
    }

    const secret = sharedSecret(ephemeral.privateKey, otherEphemeral(role, guestSide, hostSide))
    const keys = deriveSessionKeys(secret, `${guestSide.nonce}${hostSide.nonce}`, invite.inviteId)
    // The short authentication string is derived from the SESSION SECRET, so a relay
    // that terminates the encryption on both sides ends up with two different values
    // and the two screens disagree. In a typed pairing that comparison is the only
    // thing standing between the user and an active relay, which is why it is
    // computed unconditionally rather than only when a fingerprint is missing.
    const sas = shortAuthString(secret, guestSide.ephemeral, hostSide.ephemeral, invite.inviteId)
    // A QR invite pins the host's identity; a TYPED one cannot, because there is
    // nothing to carry a fingerprint. `pinned` travels with the peer description so
    // every surface that shows a pairing can say which kind it was instead of
    // implying a guarantee the mode does not provide.
    const pinned = typeof invite.fingerprint === 'string' && invite.fingerprint.length > 0
    stream = createE2eeStream({
      role,
      keys,
      inviteId: invite.inviteId,
      send: (payload) => session.sendPayload(payload),
      sendIv: iv,
      receiveIv: role === ROLE_GUEST ? hostSide.iv : guestSide.iv,
      label: `e2ee:${role}`,
    })
    const reader = new LineReader(stream)

    // The switchover from the plaintext phase to the encrypted one. The reader is
    // attached FIRST, then anything still queued is fed into the stream, then the
    // live listener takes over — in that order, because a payload decrypted before
    // a reader exists would be emitted into nothing and lost.
    queue.detach((payload) => stream.feed(payload))
    feedPayload = (payload) => stream.feed(payload)
    session.on('payload', feedPayload)

    const transcripts = {
      guest: pairingTranscript({
        side: 'guest',
        inviteId: invite.inviteId,
        guestEphemeral: guestSide.ephemeral,
        hostEphemeral: hostSide.ephemeral,
        guestNonce: guestSide.nonce,
        hostNonce: hostSide.nonce,
      }),
      host: pairingTranscript({
        side: 'host',
        inviteId: invite.inviteId,
        guestEphemeral: guestSide.ephemeral,
        hostEphemeral: hostSide.ephemeral,
        guestNonce: guestSide.nonce,
        hostNonce: hostSide.nonce,
      }),
    }

    const send = (message) => stream.sendFrame(JSON.stringify(message))
    const receive = async (expected) => {
      const raw = await reader.next(timeoutMs)
      let message
      try {
        message = JSON.parse(raw)
      } catch (error) {
        throw new PairingError('malformed', `the peer sent a sealed frame that is not JSON: ${String(error?.message ?? error)}`)
      }
      if (message === null || typeof message !== 'object' || message.t !== expected) {
        throw new PairingError('unexpected-message', `expected ${JSON.stringify(expected)}, got ${JSON.stringify(message?.t ?? message)}`)
      }
      return message
    }

    const selfIdent = {
      t: PAIR_MESSAGE.ident,
      side: role,
      id: exportPublicKey(identity.publicKey),
      sig: signTranscript(identity.privateKey, transcripts[role]),
    }

    let peerFingerprint
    if (role === ROLE_GUEST) {
      send(selfIdent)
      const hostIdent = await receive(PAIR_MESSAGE.ident)
      if (hostIdent.side !== ROLE_HOST) throw new PairingError('wrong-side', 'the peer claimed the guest role while this side is the guest')
      const actual = fingerprint(hostIdent.id)
      if (pinned && actual !== invite.fingerprint) {
        // The one failure an operator must not retry blindly.
        throw new PairingError(
          'fingerprint-mismatch',
          `the host proved a different identity (${actual}) than the invite pins (${invite.fingerprint}); this is either the wrong host or an intercepted invite`,
        )
      }
      if (!verifyTranscript(restoreIdentityPublic(hostIdent.id), transcripts.host, hostIdent.sig)) {
        throw new PairingError('bad-signature', 'the host\'s identity signature did not verify; the relay may be intercepting this invite')
      }
      if (!pinned) {
        // Said out loud, every time. The signature above proves the peer HOLDS the
        // identity it claims and binds it to these ephemeral keys — it does not prove
        // it is the machine the user meant, because nothing in a typed pairing says
        // which machine that is. Compare the short authentication string.
        logger?.warn?.(
          `paired by device code: the host identifies as ${actual}. This mode cannot pin the host, so a malicious relay could be in the middle — ` +
            `compare the short code ${sas} shown on both machines before trusting this pairing.`,
        )
      }
      peerFingerprint = actual
      send({ t: PAIR_MESSAGE.meta, label: options.label ?? '', platform: options.platform ?? '' })
    } else {
      const guestIdent = await receive(PAIR_MESSAGE.ident)
      if (guestIdent.side !== ROLE_GUEST) throw new PairingError('wrong-side', 'the peer claimed the host role while this side is the host')
      if (!verifyTranscript(restoreIdentityPublic(guestIdent.id), transcripts.guest, guestIdent.sig)) {
        throw new PairingError('bad-signature', 'the guest\'s identity signature did not verify')
      }
      peerFingerprint = fingerprint(guestIdent.id)
      send(selfIdent)
    }

    if (role === ROLE_GUEST) {
      const hostMeta = await receive(PAIR_MESSAGE.meta)
      send({ t: PAIR_MESSAGE.ready })
      return finish({ peer: { fingerprint: peerFingerprint, role: ROLE_HOST, label: String(hostMeta.label ?? ''), platform: String(hostMeta.platform ?? ''), sas, pinned } })
    }

    const guestMeta = await receive(PAIR_MESSAGE.meta)
    send({ t: PAIR_MESSAGE.meta, label: options.label ?? '', platform: options.platform ?? '' })
    await receive(PAIR_MESSAGE.ready)
    return finish({ peer: { fingerprint: peerFingerprint, role: ROLE_GUEST, label: String(guestMeta.label ?? ''), platform: String(guestMeta.platform ?? ''), sas, pinned } })

    /**
     * Hand the established session to the caller.
     *
     * The handshake's own reader is disposed: from here on the stream is driven by
     * the env wire's reader, and two readers on one stream would each consume the
     * other's lines. Nothing is lost by that, because the guest sends nothing after
     * its `ready` and the host sends nothing at all — the next byte on this stream
     * is the first env frame.
     *
     * @param result.peer - the authenticated peer description.
     * @returns the session handle.
     */
    function finish(result) {
      reader.dispose()
      queue.dispose()
      logger?.info?.(`paired with ${result.peer.role} ${result.peer.fingerprint}`)
      return {
        stream,
        session,
        peer: result.peer,
        close: () => {
          try {
            stream.end()
          } catch {
            /* already closed */
          }
          session.close()
        },
      }
    }
  } catch (error) {
    abandon()
    if (error instanceof PairingError) throw error
    if (error instanceof CryptoFailure) throw new PairingError(error.code, error.message)
    throw new PairingError('handshake-failed', String(error?.message ?? error))
  } finally {
    options.signal?.removeEventListener('abort', onAbort)
  }
}

/**
 * The peer's ephemeral key, whichever side this is.
 *
 * The shared secret is computed against the OTHER side's ephemeral key, and which
 * variable holds it depends on the role — a place where a copy-paste mistake would
 * silently derive two different keys and present as "the first frame fails to
 * decrypt".
 *
 * @param role - this side's role.
 * @param guestSide - the guest's ephemeral material.
 * @param hostSide - the host's ephemeral material.
 * @returns the peer's ephemeral public key.
 */
function otherEphemeral(role, guestSide, hostSide) {
  return role === ROLE_GUEST ? hostSide.ephemeral : guestSide.ephemeral
}

/**
 * Import one identity public key for verification.
 *
 * A named helper so the failure is a `PairingError` the caller can branch on,
 * rather than a raw `CryptoFailure` escaping from the import.
 *
 * @param base64 - the SPKI public key.
 * @returns the public KeyObject.
 * @throws {PairingError} when it does not parse.
 */
function restoreIdentityPublic(base64) {
  try {
    return importPublicKey(base64)
  } catch (error) {
    throw new PairingError('bad-identity-key', `the peer's identity key could not be read: ${String(error?.message ?? error)}`)
  }
}
