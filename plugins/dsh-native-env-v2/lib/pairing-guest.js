/**
 * dsh-native-env / pairing-guest — the REMOTE half of the pairing transport.
 *
 * The guest is the machine that scans or pastes an invite. It has no address book,
 * no configured host, no token file, and — critically for a Windows machine behind
 * NAT — no inbound port: it DIALS OUT to the relay the invite names, proves the
 * invite secret, and authenticates the host by the fingerprint the invite pins.
 *
 * It keeps the invite it was given, so a dropped connection reconnects on the same
 * invite instead of requiring the operator to carry a new QR code across the room.
 * The invite is a credential, so it is stored through the credential service and
 * never in the plain state file (see `state-store.js`), and it stops being usable
 * when it expires.
 *
 * One behaviour deliberately mirrors the legacy transports: a failure NEVER falls
 * back to anything. There is no "connect to the last known address" and no default
 * relay. With no valid invite the guest does nothing at all, which is exactly what
 * a machine that has not been paired should do.
 *
 * @module dsh-native-env/pairing-guest
 */

import { EventEmitter } from 'node:events'
import process from 'node:process'

import { exportIdentity, exportPublicKey, fingerprint, generateIdentity, restoreIdentity } from './e2ee.js'
import { normalizeDeviceCode, normalizePassword } from './device-code.js'
import { createDeviceJoin, describeInvite, parseInviteUri, validateInvite } from './pairing.js'
import { establishPairedStream } from './pairing-session.js'
import { acceptanceRecord, acceptanceStatus } from './terms.js'

/** The credential record name that holds this machine's pairing identity. */
export const IDENTITY_SECRET = 'guest-identity'

/** The credential record name that holds the invite this guest is paired on. */
export const INVITE_SECRET = 'guest-invite'

/** How long to wait before reconnecting after a drop. */
const RECONNECT_DELAY_MS = 2000

/** Resolve after `ms`; the timer is unref'd so it never holds the process open. */
function delay(ms) {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms)
    timer.unref?.()
  })
}

/**
 * The guest's pairing service.
 *
 * Emits `paired` (`{ peer, stream, session }`), `unpaired` (`{ reason }`),
 * `status` (`status document`) and `failed` (`{ code, message }`).
 */
export class PairingGuest extends EventEmitter {
  /**
   * @param options.config - `{ autoReconnect, acceptTimeoutMs, label }`.
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
    this.label = options.label ?? 'dsh guest'
    /** @type {object | undefined} */
    this.invite = undefined
    this.connected = false
    this.connectedSince = undefined
    this.lastError = undefined
    this.attempts = 0
    this.peer = undefined
    /** The short authentication string, once a pairing has completed. */
    this.sas = undefined
    this.stopped = true
    this.loop = undefined
  }

  /**
   * Load this machine's identity, minting one on first use.
   *
   * @param options.config - the resolved plugin config.
   * @param options.logger - optional logger.
   * @param options.secrets - the secret store.
   * @param options.state - the state store.
   * @returns the guest service.
   */
  static async load(options) {
    const stored = await options.secrets.read(IDENTITY_SECRET)
    if (stored !== undefined) {
      try {
        return new PairingGuest({ ...options, identity: restoreIdentity(JSON.parse(stored)) })
      } catch (error) {
        options.logger?.warn?.(
          `native-env: the stored guest identity is unreadable (${String(error?.message ?? error)}); minting a new one. ` +
            'A host that already knows this machine will see it as a different machine.',
        )
      }
    }
    const identity = generateIdentity()
    await options.secrets.write(IDENTITY_SECRET, JSON.stringify(exportIdentity(identity)))
    return new PairingGuest({ ...options, identity })
  }

  /** @returns this machine's identity fingerprint, which a host records. */
  get fingerprint() {
    return fingerprint(this.identity.publicKey)
  }

  /** @returns this machine's public key, base64 SPKI. */
  get publicKey() {
    return exportPublicKey(this.identity.publicKey)
  }

  /** @returns the terms acceptance status. */
  termsStatus() {
    return acceptanceStatus(this.state.get('terms'))
  }

  /**
   * Record that the user accepted the notice.
   * @returns the stored record.
   */
  acceptTerms() {
    const record = acceptanceRecord({ role: 'guest' })
    this.state.write({ terms: record })
    this.logger?.info?.(`native-env: the disclaimer (version ${String(record.termsVersion)}) was accepted`)
    return record
  }

  /**
   * Attach to an invite and keep the connection up.
   *
   * @param uri - the invite URI, from a QR code or a clipboard.
   * @param options.remember - persist the invite for automatic reconnection after a
   *   restart; defaults to true.
   * @returns `{ invite, status }`.
   * @throws {Error} on a malformed, expired or version-mismatched invite, or when
   *   the terms have not been accepted.
   */
  async join(uri, options = {}) {
    const parsed = parseInviteUri(uri)
    if (!parsed.ok) {
      const error = new Error(`native-env: ${parsed.error}`)
      error.code = parsed.code
      throw error
    }
    return await this.attachDescriptor(parsed.invite, { ...options, describe: 'invite' })
  }

  /**
   * Join a TYPED pairing: a device code read off the host's screen, and its password.
   *
   * This is the flow people know from remote-desktop software, and it exists because a
   * desktop has no camera and the machine showing the code has nobody standing at it
   * with a phone.
   *
   * The relay is NOT typed: a nine-digit code cannot name one, so this machine must
   * already be configured with the relay the host is using (`relayUrls`). That is the
   * same model as any remote-desktop client, whose vendor's servers are baked in.
   *
   * @param options.deviceCode - nine digits, with or without separators.
   * @param options.password - the temporary password, with or without separators.
   * @param options.remember - persist the pairing for reconnection; defaults to true.
   * @returns `{ invite, status }`.
   * @throws {Error} with a code of `bad-device-code`, `bad-password`, `no-relay`,
   *   `expired` or `terms-required`.
   */
  async joinWithCode(options = {}) {
    const deviceCode = normalizeDeviceCode(options.deviceCode)
    if (deviceCode === undefined) {
      const error = new Error('native-env: a device code is nine digits, for example 123 456 789')
      error.code = 'bad-device-code'
      throw error
    }
    const password = normalizePassword(options.password)
    if (password === undefined) {
      const error = new Error('native-env: that does not look like a pairing password (twelve characters, as shown on the host)')
      error.code = 'bad-password'
      throw error
    }
    const relay = this.config.relayUrls?.[0]
    if (typeof relay !== 'string' || relay.length === 0) {
      const error = new Error(
        'native-env: no relay is configured on this machine, so a device code cannot be resolved. ' +
          'A nine-digit code cannot name a relay — set `relayUrls` to the same relay the host is using.',
      )
      error.code = 'no-relay'
      throw error
    }
    const descriptor = createDeviceJoin({ relay, deviceCode, password, expiresAt: options.expiresAt })
    return await this.attachDescriptor(descriptor, { ...options, describe: 'device card' })
  }

  /**
   * The one path both join flavours take once a descriptor exists.
   *
   * Kept as a single method on purpose: the validation, the terms gate, the stored
   * credential and the reconnect loop must not be able to differ between a scanned
   * invite and a typed card, or one of the two would quietly lose a guarantee.
   *
   * @param descriptor - the join descriptor (a QR invite or a typed card join).
   * @param options.remember - persist for reconnection.
   * @param options.describe - how to name it in the log.
   * @returns `{ invite, status }`.
   */
  async attachDescriptor(descriptor, options = {}) {
    const verdict = validateInvite(descriptor)
    if (!verdict.ok) {
      const error = new Error(`native-env: ${verdict.error}`)
      error.code = verdict.code
      throw error
    }
    if (this.config.requireTerms !== false) {
      const status = this.termsStatus()
      if (!status.accepted) {
        const error = new Error(
          `native-env: the disclaimer must be accepted before joining an invite (${status.reason}). ` +
            'Read it with /env terms and accept it with /env terms accept.',
        )
        error.code = 'terms-required'
        throw error
      }
    }

    await this.stop()
    this.invite = descriptor
    this.lastError = undefined
    this.attempts = 0
    this.stopped = false
    this.sas = undefined
    if (options.remember !== false) {
      // Stored as a SECRET, not in the state file: it carries the password.
      await this.secrets.write(INVITE_SECRET, JSON.stringify(descriptor))
    }
    const described = describeInvite(descriptor)
    this.logger?.info(
      `native-env: joined ${options.describe ?? 'a pairing'} on ${described.relay}` +
        (described.mode === 'code' ? ` as device ${described.deviceCode}` : ` (invite ${described.inviteIdPrefix})`),
    )
    this.loop = this.runLoop()
    return { invite: descriptor, status: this.status() }
  }

  /**
   * Restore a previously joined invite from the credential store.
   *
   * @returns the restored invite, or `undefined` when there is none or it expired.
   */
  async restore() {
    const stored = await this.secrets.read(INVITE_SECRET)
    if (stored === undefined) return undefined
    let invite
    try {
      invite = JSON.parse(stored)
    } catch (error) {
      this.logger?.warn?.(`native-env: the stored invite is unreadable (${String(error?.message ?? error)})`)
      return undefined
    }
    const verdict = validateInvite(invite)
    if (!verdict.ok) {
      // An expired invite is not an error worth keeping: forget it, and say so, so
      // the operator knows a new QR code is the only way forward.
      this.logger?.info?.(`native-env: the stored invite is no longer usable (${verdict.error})`)
      await this.secrets.remove(INVITE_SECRET)
      return undefined
    }
    this.invite = invite
    return invite
  }

  /** The connect/reconnect loop. Runs until stopped or the invite expires. */
  async runLoop() {
    while (!this.stopped && this.invite !== undefined) {
      const verdict = validateInvite(this.invite)
      if (!verdict.ok) {
        this.lastError = verdict.error
        this.logger?.info?.(`native-env: stopping the guest loop — ${verdict.error}`)
        break
      }
      this.attempts += 1
      try {
        this.controller = new AbortController()
        const paired = await establishPairedStream({
          invite: this.invite,
          role: 'guest',
          identity: this.identity,
          label: this.label,
          platform: process.platform,
          timeoutMs: this.config.acceptTimeoutMs,
          logger: this.logger,
          signal: this.controller.signal,
        })
        this.connected = true
        this.connectedSince = Date.now()
        this.lastError = undefined
        this.peer = paired.peer
        // The value a human compares with what the host shows. In a typed pairing it
        // is the ONLY thing that can reveal a relay in the middle, so it is carried
        // all the way out to the status document and the UI.
        this.sas = paired.peer.sas
        // Kept so `stop()` can close an ESTABLISHED connection. Aborting the
        // controller only cancels an attempt that is still in flight — its signal
        // listener is removed once the handshake succeeds — so a stop during a
        // healthy pairing would otherwise leave the socket open forever.
        this.active = paired
        this.emit('paired', { peer: paired.peer, stream: paired.stream, session: paired.session })
        // Hold until the connection ends, then loop and reconnect: the invite is
        // still registered at the relay until it expires.
        await new Promise((resolve) => {
          paired.stream.once('end', resolve)
          paired.session.once('close', resolve)
        })
        this.active = undefined
        this.connected = false
        this.connectedSince = undefined
        if (!this.stopped) {
          this.emit('unpaired', { reason: 'the host connection closed' })
          this.logger?.warn?.('native-env: the host connection closed; reconnecting while the invite lasts')
        }
      } catch (error) {
        this.connected = false
        this.connectedSince = undefined
        this.lastError = String(error?.message ?? error)
        this.emit('failed', { code: error?.code ?? 'unknown', message: this.lastError })
        this.logger?.warn?.(`native-env: connection attempt failed: ${this.lastError}`)
      }
      if (this.stopped) break
      if (this.config.autoReconnect === false) {
        this.logger?.info?.('native-env: autoReconnect is off, so the guest stops after the first attempt')
        break
      }
      await delay(RECONNECT_DELAY_MS)
    }
    this.stopped = true
  }

  /** A redacted status document. */
  status() {
    return {
      role: 'guest',
      fingerprint: this.fingerprint,
      connected: this.connected,
      connectedSince: this.connectedSince,
      attempts: this.attempts,
      lastError: this.lastError,
      peer: this.peer,
      /** The short string to compare with the host's screen. See `device-code.js`. */
      sas: this.sas,
      /** Whether this pairing pinned the host's identity (QR) or could not (typed). */
      pinned: this.peer?.pinned === true,
      invite: this.invite === undefined ? null : describeInvite(this.invite),
      terms: this.termsStatus(),
    }
  }

  /**
   * Stop reconnecting.
   *
   * `forget` defaults to FALSE, and that default is load-bearing: this method is
   * called when the plugin unmounts, and forgetting the invite there would mean the
   * guest could never resume after a runtime restart — the whole point of storing
   * it. A user who wants it gone runs `/env disconnect`, which passes `forget`.
   *
   * @param options.forget - also remove the stored invite.
   */
  async stop(options = {}) {
    this.stopped = true
    const loop = this.loop
    this.loop = undefined
    // Two distinct cancellations, and BOTH are needed: the abort cancels an attempt
    // still in flight, and closing the active handle tears down a connection that
    // already succeeded. Without the second, a stop during a healthy pairing leaves
    // the socket open, the relay slot occupied, and the guest permanently believed
    // to be connected.
    this.controller?.abort()
    try {
      this.active?.close()
    } catch {
      /* already closed */
    }
    this.active = undefined
    this.connected = false
    this.connectedSince = undefined
    this.invite = undefined
    this.peer = undefined
    this.sas = undefined
    if (options.forget === true) await this.secrets.remove(INVITE_SECRET)
    void loop
  }

  /**
   * Forget the stored invite without touching the running connection.
   * @returns true when the credential store was reachable.
   */
  async forget() {
    return await this.secrets.remove(INVITE_SECRET)
  }
}
