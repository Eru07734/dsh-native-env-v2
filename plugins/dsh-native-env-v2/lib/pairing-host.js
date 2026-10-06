/**
 * dsh-native-env / pairing-host — the LOCAL half of the pairing transport.
 *
 * This is what replaces the hand-written `peers:` block. Instead of an operator
 * declaring a machine, an address, a port and a token file, the host:
 *
 *   1. mints an identity once and keeps its public fingerprint (that fingerprint
 *      is the ONLY thing the other machine needs to trust, and it is what a QR code
 *      carries);
 *   2. creates a short-lived invite, registers it with a relay, and shows the URI;
 *   3. sits on that invite, waiting for the other machine to arrive;
 *   4. when one does, authenticates it and hands the resulting encrypted stream to
 *      the existing `EnvClient` — which is the same object the `tcp` and `ssh`
 *      transports use, so nothing above this file changes;
 *   5. goes back to waiting on the SAME invite, so a dropped connection is a
 *      reconnect rather than a new QR code.
 *
 * Two decisions are worth stating because they are the ones a future change would
 * most plausibly get wrong:
 *
 *   - **The accept loop is strictly sequential per invite.** The relay admits one
 *     host connection per invite, so a second concurrent `establishPairedStream`
 *     for the same invite would be refused by the relay and logged as a failure
 *     that looks like a network problem. One loop, one connection.
 *   - **A failed handshake does not kill the invite.** A wrong-identity guest, a
 *     half-open connection or a relay hiccup all leave the invite usable, so the
 *     loop logs and re-waits. Only revocation or expiry ends it. A pairing flow
 *     that dies on the first malformed attempt is unusable on a flaky network.
 *
 * @module dsh-native-env/pairing-host
 */

import { EventEmitter } from 'node:events'

import process from 'node:process'

import { exportIdentity, exportPublicKey, fingerprint, generateIdentity, restoreIdentity } from './e2ee.js'
import { createInvite, createDeviceJoin, describeInvite, relayLabel } from './pairing.js'
import { createDeviceCard, formatDeviceCode } from './device-code.js'
import { establishPairedStream } from './pairing-session.js'
import { encodeQrSvg } from './qr.js'
import { registerInvite } from './relay-client.js'
import { relayRegisterUrl } from './relay-protocol.js'
import { DEFAULT_INVITE_TTL_MS } from './pairing.js'
import { acceptanceRecord, acceptanceStatus } from './terms.js'

/** The credential record name that holds this machine's pairing identity. */
export const IDENTITY_SECRET = 'host-identity'

/** How long the accept loop waits between attempts after an unexpected failure. */
const RETRY_DELAY_MS = 1000

/**
 * One live invite and its accept loop.
 *
 * Owned by {@link PairingHost}; kept as its own class because the loop's state
 * (running, current peer, retry budget) is meaningful on its own and `status()`
 * reports it.
 */
class InviteSlot {
  /**
   * @param options.host - the owning `PairingHost`.
   * @param options.invite - the parsed invite.
   * @param options.uri - the invite URI as shown to the user.
   */
  constructor(options) {
    this.host = options.host
    this.invite = options.invite
    /** The QR URI, or `undefined` for a typed device card (which has no URI). */
    this.uri = options.uri
    /** The device card, when this slot was created as a typed pairing. */
    this.card = options.card
    this.createdAt = Date.now()
    this.running = false
    this.currentPeer = undefined
    this.lastError = undefined
    this.connections = 0
    /** Wall-clock ms until which this slot keeps accepting. */
    this.expiresAt = options.invite.expiresAt
  }

  /** @returns the QR code for this invite, or `undefined` for a typed card. */
  svg() {
    if (this.uri === undefined) return undefined
    const options = { size: 320, label: `Pairing invite ${describeInvite(this.invite).inviteIdPrefix}` }
    try {
      return encodeQrSvg(this.uri, { ...options, level: 'M' })
    } catch (error) {
      if (!String(error?.message).includes('does not fit')) throw error
      // Quick Tunnel hostnames are longer than a LAN relay. Level L fits the
      // ordinary public invite without changing its credential or fingerprint.
      try { return encodeQrSvg(this.uri, { ...options, level: 'L' }) } catch (fallback) {
        if (!String(fallback?.message).includes('does not fit')) throw fallback
        // A copyable invite must remain usable even if no QR version can fit it.
        return undefined
      }
    }
  }

  /** @returns a redacted status document. */
  status() {
    return {
      ...describeInvite(this.invite),
      // The full id IS included here, unlike in a log line: the Web UI needs a
      // stable key to fetch this invite's QR image, and the id is not a secret —
      // it travels in the relay's request path and the relay sees it anyway. What
      // must never appear is the SECRET, which `describeInvite` already omits.
      inviteId: this.invite.inviteId,
      ...(this.uri === undefined ? {} : { uri: this.uri }),
      state: this.running ? 'waiting-for-peer' : 'stopped',
      connections: this.connections,
      currentPeer: this.currentPeer,
      lastError: this.lastError,
      revoked: this.revoked === true,
    }
  }

  /**
   * The card as it may be shown to the OWNER, with the password.
   *
   * Only ever called on a path that has already passed the harness's browser
   * authentication, or a command typed by the human at the machine. Everything else
   * gets {@link InviteSlot.status}.
   *
   * @returns the displayable card, or `undefined` for a QR invite.
   */
  cardDisplay() {
    return this.card?.toDisplay()
  }

  /**
   * Stop the loop and release anything it is holding.
   *
   * Two cancellations, both required: the abort cancels an attempt still waiting
   * for a guest, and closing the active handle tears down a connection that already
   * succeeded — its abort listener was removed when the handshake completed, so
   * without this the stop would leave the socket open and the relay slot taken.
   */
  stop() {
    this.running = false
    this.stopped = true
    this.controller?.abort()
    try {
      this.active?.close()
    } catch {
      /* already closed */
    }
    this.active = undefined
  }

  /**
   * Run the accept loop until stopped or expired.
   *
   * @returns a promise that settles when the loop ends.
   */
  async run() {
    this.running = true
    while (!this.stopped && Date.now() < this.expiresAt) {
      try {
        this.controller = new AbortController()
        await this.acceptOne(this.controller.signal)
      } catch (error) {
        this.lastError = String(error?.message ?? error)
        if (this.stopped || error?.code === 'aborted') break
        // Retry: an invite is a scarce thing to hand to another machine, and
        // burning it because one attempt failed would be the wrong trade.
        this.host.logger?.warn?.(`native-env: invite ${describeInvite(this.invite).inviteIdPrefix} attempt failed: ${this.lastError}`)
        await delay(RETRY_DELAY_MS)
      }
    }
    this.running = false
    if (!this.stopped) {
      this.lastError ??= 'the invite expired'
      this.host.logger?.info?.(`native-env: invite ${describeInvite(this.invite).inviteIdPrefix} expired`)
      this.host.emit('invite-expired', this.status())
    }
  }

  /**
   * Wait for one guest, authenticate it, and hand the stream to the host.
   * @param signal - aborts the attempt.
   */
  async acceptOne(signal) {
    const paired = await establishPairedStream({
      invite: this.invite,
      relayBase: this.host.connectionRelayFor(this.invite.relay),
      role: 'host',
      identity: this.host.identity,
      label: this.host.label,
      platform: process.platform,
      timeoutMs: this.host.acceptTimeoutMs,
      logger: this.host.logger,
      signal,
    })
    this.connections += 1
    const peerName = this.host.peerNameFor(paired.peer)
    this.currentPeer = peerName
    this.active = paired
    this.host.logger?.info?.(
      `native-env: guest ${paired.peer.fingerprint} paired on invite ${describeInvite(this.invite).inviteIdPrefix} as peer "${peerName}"`,
    )
    // The stream outlives this call: the owner attaches a wire and a client to it,
    // and the loop below waits for it to end before accepting the next guest.
    await this.host.adopt(peerName, paired, this.invite)
    this.active = undefined
    this.currentPeer = undefined
  }
}

/** Resolve after `ms`. */
function delay(ms) {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms)
    timer.unref?.()
  })
}

/**
 * The host's pairing service.
 *
 * Emits `peer-adopted` (`{ peerName, peer, invite, stream, session }`),
 * `peer-lost` (`{ peerName }`) and `invite-expired` (`status`).
 */
export class PairingHost extends EventEmitter {
  /**
   * @param options.config - `{ relayUrls, inviteTtlMs, maxPeers, acceptTimeoutMs, label, requireTerms }`.
   * @param options.logger - optional `{ info, warn }`.
   * @param options.identity - this machine's Ed25519 identity.
   * @param options.secrets - the `SecretStore`.
   * @param options.state - the `StateStore`.
   */
  constructor(options) {
    super()
    this.config = options.config
    this.logger = options.logger
    this.identity = options.identity
    this.secrets = options.secrets
    this.state = options.state
    this.label = options.label ?? 'dsh host'
    this.acceptTimeoutMs = options.config.acceptTimeoutMs ?? 5 * 60 * 1000
    /** @type {Map<string, InviteSlot>} */
    this.slots = new Map()
    /** @type {Map<string, { inviteId: string }>} */
    this.peerInvites = new Map()
    /** Pairs a peer name with the 8 characters of its identity fingerprint. */
    this.peerNames = new Map()
    /**
     * The live typed device card, when one exists.
     *
     * Kept so a password refresh can reuse the STABLE code and, crucially, prove the
     * previous secret to the relay — which is what lets it replace its own slot
     * without waiting for the old one to expire.
     *
     * @type {{ card: object, slot: InviteSlot, codeSalt: number } | undefined}
     */
    this.deviceCard = undefined
  }

  /**
   * Load this machine's identity, minting one on first use.
   *
   * The private half is stored through the credential service and NOWHERE else. If
   * that service is unavailable, a fresh identity is minted for this process only
   * and the caller is told, because a private key in a plain file is a worse
   * outcome than a pairing that needs redoing after a restart.
   *
   * @param options.config - the resolved plugin config.
   * @param options.logger - optional logger.
   * @param options.secrets - the secret store.
   * @param options.state - the state store.
   * @returns the pairing host.
   */
  static async load(options) {
    const stored = await options.secrets.read(IDENTITY_SECRET)
    if (stored !== undefined) {
      try {
        const identity = restoreIdentity(JSON.parse(stored))
        return new PairingHost({ ...options, identity })
      } catch (error) {
        // A stored identity that will not parse is worse than none: every existing
        // invite pins its fingerprint, so silently minting a new one would make
        // every previously issued invite fail with `fingerprint-mismatch`. Say so.
        options.logger?.warn?.(
          `native-env: the stored pairing identity is unreadable (${String(error?.message ?? error)}); minting a NEW identity. ` +
            'Previously issued invites will no longer match this host.',
        )
      }
    }
    const identity = generateIdentity()
    const persisted = await options.secrets.write(IDENTITY_SECRET, JSON.stringify(exportIdentity(identity)))
    if (!persisted) {
      options.logger?.warn?.(
        'native-env: this pairing identity is held in memory only, so every invite issued by this process becomes unusable after a restart.',
      )
    }
    return new PairingHost({ ...options, identity })
  }

  /** @returns the host identity's short fingerprint, what an invite pins. */
  get fingerprint() {
    return fingerprint(this.identity.publicKey)
  }

  /** @returns the host identity's public key, base64 SPKI. */
  get publicKey() {
    return exportPublicKey(this.identity.publicKey)
  }

  /** @returns the configured relay base, or `undefined`. */
  get relayBase() {
    return Array.isArray(this.config.relayUrls) ? this.config.relayUrls[0] : undefined
  }

  /** The local half of an embedded relay need not wait on public DNS. */
  connectionRelayFor(relay) {
    return this.config.publicRelay?.advertised === relay ? this.config.publicRelay.local : relay
  }

  /**
   * The peer name for one authenticated guest.
   *
   * Derived from the guest's IDENTITY fingerprint, not from the invite, so the same
   * machine reconnects under the same peer name — which is what lets it keep its
   * place in a UI and lets a session stay entered across a reconnect.
   *
   * @param peer - the pairing peer description.
   * @returns the peer name.
   */
  peerNameFor(peer) {
    const existing = this.peerNames.get(peer.fingerprint)
    if (existing !== undefined) return existing
    const name = `guest-${String(peer.fingerprint).slice(0, 8)}`
    this.peerNames.set(peer.fingerprint, name)
    return name
  }

  /**
   * Whether the terms have been accepted on this machine.
   * @returns the acceptance status.
   */
  termsStatus() {
    return acceptanceStatus(this.state.get('terms'))
  }

  /**
   * Record that the user accepted the notice.
   * @param role - `host` or `guest`.
   * @returns the stored record.
   */
  acceptTerms(role = 'host') {
    const record = acceptanceRecord({ role })
    this.state.write({ terms: record })
    this.logger?.info?.(`native-env: the disclaimer (version ${String(record.termsVersion)}) was accepted`)
    return record
  }

  /**
   * Create, register and start waiting on one invite.
   *
   * Registration happens BEFORE the URI is returned, so a URI a user can already
   * see is always a URI the relay knows about. Returning it first and registering
   * after would produce exactly one class of report that is impossible to debug:
   * "the QR code says the invite is unknown".
   *
   * @param options.ttlMs - overrides the configured invite lifetime.
   * @returns `{ uri, svg, invite, status }`.
   * @throws {Error} when the terms have not been accepted, or the relay refuses.
   */
  async createInvite(options = {}) {
    if (this.config.requireTerms !== false) {
      const status = this.termsStatus()
      if (!status.accepted) {
        throw new Error(
          `native-env: the disclaimer must be accepted before an invite can be created (${status.reason}). ` +
            'Read it with /env terms and accept it with /env terms accept.',
        )
      }
    }
    const relay = this.relayBase
    if (typeof relay !== 'string' || relay.length === 0) {
      throw new Error('native-env: no relay is configured, so a pairing invite cannot be created (set relayUrls in the plugin config)')
    }
    const ttlMs = Number.isSafeInteger(options.ttlMs) ? options.ttlMs : (this.config.inviteTtlMs ?? DEFAULT_INVITE_TTL_MS)
    const { uri, invite } = createInvite({ relay, fingerprint: this.fingerprint, expiresAt: Date.now() + ttlMs })

    await registerInvite({
      url: relayRegisterUrl(this.connectionRelayFor(relay)),
      inviteId: invite.inviteId,
      secret: invite.pairSecret,
      expiresAt: invite.expiresAt,
      timeoutMs: this.config.relayTimeoutMs,
    })

    const slot = new InviteSlot({ host: this, invite, uri })
    this.slots.set(invite.inviteId, slot)
    // Fire and forget: the loop reports its own failures through `lastError` and the
    // log, so the caller does not have to hold a promise for the invite's lifetime.
    void slot.run()
    this.logger?.info(
      `native-env: invite ${describeInvite(invite).inviteIdPrefix} created on ${relayLabel(relay)}; it expires in ${String(Math.round(ttlMs / 1000))}s`,
    )
    return { uri, svg: slot.svg(), invite, status: slot.status() }
  }

  /**
   * Create, register and start waiting on a TYPED device card.
   *
   * This is the remote-desktop shape: a device code the operator reads off this
   * screen and a temporary password they type on the other machine. No URI, no QR,
   * and — stated plainly because it is a real difference — **no pinned host
   * fingerprint**, since a nine-digit code has nowhere to carry one.
   *
   * The code is derived from this machine's identity, so it is STABLE: the same
   * computer shows the same code every time. Rotating the password (`refreshPassword`)
   * keeps the code and replaces the credential, which is what makes the card safe to
   * leave on screen.
   *
   * @param options.ttlMs - overrides the configured card lifetime.
   * @param options.refresh - `true` to keep the existing code and mint a new password.
   * @returns `{ card, status }` where `card` carries the password for the owner's eyes.
   * @throws {Error} when the terms have not been accepted, no relay is configured, or
   *   the relay refuses every candidate code.
   */
  async createDeviceCard(options = {}) {
    if (this.config.requireTerms !== false) {
      const status = this.termsStatus()
      if (!status.accepted) {
        throw new Error(
          `native-env: the disclaimer must be accepted before a device card can be created (${status.reason}). ` +
            'Read it with /env terms and accept it with /env terms accept.',
        )
      }
    }
    const relay = this.relayBase
    if (typeof relay !== 'string' || relay.length === 0) {
      throw new Error('native-env: no relay is configured, so a device card cannot be created (set relayUrls in the plugin config)')
    }
    const ttlMs = Number.isSafeInteger(options.ttlMs) ? options.ttlMs : (this.config.inviteTtlMs ?? DEFAULT_INVITE_TTL_MS)

    // A refresh keeps the code AND the accept loop: the peer already waiting on the
    // other machine should not have to be told a new code because the password aged.
    const previous = options.refresh === true ? this.deviceCard : undefined
    const codeSalt = previous?.codeSalt ?? this.state.get('deviceCodeSalt', 0)

    // At most a few attempts: a collision means another machine on THIS relay drew the
    // same nine digits, which is a 1-in-10^9 event the operator may still hit once.
    let chosen
    let lastError
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const candidate = createDeviceCard({
        publicKey: this.identity.publicKey,
        codeSalt: codeSalt + attempt,
        ttlMs,
        hostFingerprint: this.fingerprint,
        label: this.label,
      })
      const join = createDeviceJoin({ relay, deviceCode: candidate.deviceCode, password: candidate.password, expiresAt: candidate.expiresAt })
      try {
        await registerInvite({
          url: relayRegisterUrl(this.connectionRelayFor(relay)),
          inviteId: join.inviteId,
          secret: join.pairSecret,
          expiresAt: join.expiresAt,
          // Lets a rotation replace our OWN live slot while the code stays stable.
          previousSecret: previous?.card.password,
          timeoutMs: this.config.relayTimeoutMs,
        })
        // The DEVICE CARD INSTANCE is kept whole. Spreading it into a plain object —
        // the obvious way to attach two more fields — drops its prototype methods, and
        // `toDisplay()` then disappears at the first call.
        chosen = { card: candidate, codeSalt: codeSalt + attempt, join }
        break
      } catch (error) {
        lastError = error
        // `invite-used` is the only outcome worth retrying with a different salt; a
        // dead relay will fail the same way five times and should surface once.
        if (error?.code !== 'invite-used') break
      }
    }
    if (chosen === undefined) {
      throw new Error(`native-env: the relay would not register a device code (${String(lastError?.message ?? 'unknown reason')})`)
    }

    if (chosen.codeSalt !== this.state.get('deviceCodeSalt', 0)) this.state.write({ deviceCodeSalt: chosen.codeSalt })
    // The previous loop is stopped but its SLOT at the relay is replaced by the
    // registration above, so nothing is left dangling: a guest already connected stays
    // connected, and a new guest uses the new password.
    previous?.slot.stop()
    if (previous !== undefined) this.slots.delete(previous.slot.invite.inviteId)

    const slot = new InviteSlot({ host: this, invite: chosen.join, uri: undefined, card: chosen.card })
    this.slots.set(chosen.join.inviteId, slot)
    void slot.run()
    this.deviceCard = { card: chosen.card, slot, codeSalt: chosen.codeSalt }
    this.logger?.info(
      `native-env: device card ${formatDeviceCode(chosen.card.deviceCode)} is live on ${relayLabel(relay)}; it expires in ${String(Math.round(ttlMs / 1000))}s`,
    )
    return { card: chosen.card.toDisplay(), status: slot.status() }
  }

  /**
   * Adopt one authenticated guest.
   *
   * Resolves when the guest's connection has ENDED, which is what makes the
   * caller's accept loop naturally sequential: the next guest is only accepted
   * after this one is gone.
   *
   * @param peerName - the peer name.
   * @param paired - the paired session.
   * @param invite - the invite it arrived on.
   * @returns a promise for the end of that connection.
   */
  async adopt(peerName, paired, invite) {
    const finished = new Promise((resolve) => {
      paired.stream.once('end', resolve)
      paired.session.once('close', resolve)
    })
    this.emit('peer-adopted', { peerName, peer: paired.peer, invite, stream: paired.stream, session: paired.session })
    await finished
    // A guest that is gone is detached, but the peer name is REMEMBERED: the same
    // machine reconnecting must land on the same peer, or a session that entered it
    // would silently point at a peer that no longer exists.
    this.peerInvites.set(peerName, { inviteId: invite.inviteId })
    this.emit('peer-lost', { peerName })
  }

  /** @returns every invite's redacted status. */
  invites() {
    return [...this.slots.values()].map((slot) => slot.status())
  }

  /**
   * Find one live invite by its full id or its 8-character prefix.
   * @param idOrPrefix - the invite id, or enough of its prefix to be unambiguous.
   * @returns the slot, or `undefined`.
   */
  slotFor(idOrPrefix) {
    const wanted = String(idOrPrefix ?? '')
    if (wanted.length === 0) return undefined
    const exact = this.slots.get(wanted)
    if (exact !== undefined) return exact
    const matches = [...this.slots.values()].filter((slot) => slot.invite.inviteId.startsWith(wanted))
    // An ambiguous prefix resolves to nothing rather than to whichever came first:
    // showing the wrong machine's QR code is worse than showing none.
    return matches.length === 1 ? matches[0] : undefined
  }

  /**
   * The QR code for one live invite.
   * @param idOrPrefix - the invite id or prefix.
   * @returns the SVG, or `undefined` when there is no unique match.
   */
  svgFor(idOrPrefix) {
    return this.slotFor(idOrPrefix)?.svg()
  }

  /**
   * Stop waiting on one invite, or on every invite when no id is given.
   *
   * This stops ACCEPTING; it does not tell the relay to forget the invite, because
   * the relay has no such call — the invite dies with its TTL. That is why the
   * status document says `revoked` rather than implying the URI is dead everywhere.
   *
   * @param inviteId - the invite id or its 8-character prefix; omit for all.
   * @returns the number of invites stopped.
   */
  revoke(inviteId) {
    let stopped = 0
    for (const [id, slot] of [...this.slots.entries()]) {
      if (inviteId !== undefined && !id.startsWith(String(inviteId))) continue
      slot.revoked = true
      slot.stop()
      this.slots.delete(id)
      stopped += 1
    }
    return stopped
  }

  /** Stop every accept loop. */
  async stop() {
    for (const slot of this.slots.values()) slot.stop()
    this.slots.clear()
  }
}
