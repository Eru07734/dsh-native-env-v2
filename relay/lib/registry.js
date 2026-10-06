/**
 * dsh-native-env-relay / registry — who may occupy which invite, and for how long.
 *
 * This is the relay's entire security policy, kept in one file so it can be read
 * and tested on its own. Everything the relay knows about a session is here:
 *
 *   - an invite id (32 hex characters, which the client picks),
 *   - the invite secret (which the relay MUST hold, because it is the verifier for
 *     the rendezvous proof),
 *   - an expiry,
 *   - at most one `host` connection and one `guest` connection.
 *
 * Three deliberate properties:
 *
 *   1. **The registry is memory-only and self-expiring.** An invite lives for its
 *      TTL and no longer. Nothing is written to disk, so a relay restart simply
 *      forgets every invite — which is the correct failure mode for a rendezvous
 *      service, and the reason the client treats `invite-unknown` as "make a new
 *      invite" rather than as an error worth retrying.
 *   2. **Registration cannot hijack a live invite.** Re-registering an id that is
 *      already live is refused (`already-registered`) rather than overwriting it.
 *      Without that check, anyone who observed an invite id (it travels in the
 *      WebSocket path, so a proxy log is enough) could re-register it with their
 *      own secret and take over the rendezvous. The exception is a re-registration
 *      that presents the SAME secret, which only the machine already holding the
 *      slot can do — and which a STABLE device code depends on, because the same
 *      host must be able to reclaim its own code after a restart.
 *   3. **Roles are exclusive but re-claimable.** One host and one guest at a time.
 *      A role that disconnects frees its slot immediately and the SLOT SURVIVES
 *      until its TTL, so a dropped connection reconnects on the same invite
 *      instead of forcing the operator to carry a new QR code to the other
 *      machine. That does not weaken anything: claiming a free role still requires
 *      the invite secret, and the invite is a bearer credential for its whole
 *      lifetime either way — dropping the empty slot would only have punished the
 *      legitimate holder.
 *   4. **A nine-digit device code is a SMALL address space, and the relay is what
 *      makes guessing it pointless.** 10^9 is enumerable, so `server.js` throttles
 *      failed authentications per client address. The password carries 60 bits, so a
 *      throttle is the only defence the code needs.
 *
 * The honest consequence, stated in the README: an invite is a BEARER credential
 * for its whole lifetime. Anyone who obtains the URI before it expires can claim
 * the free role. That is why the TTL is ten minutes by default.
 *
 * @module dsh-native-env-relay/registry
 */

import { RELAY_ERROR } from '../../plugins/dsh-native-env-v2/lib/relay-protocol.js'

/** The default invite lifetime: long enough to walk to another machine. */
export const DEFAULT_INVITE_TTL_MS = 10 * 60 * 1000

/** The longest TTL a client may request. A week-long invite is a password. */
export const MAX_INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000

/** 4 to 64 lower-case letters or digits: a 32-hex invite id, or a nine-digit code. */
const SLOT_ID_PATTERN = /^[0-9a-z]{4,64}$/

/**
 * The accepted pairing secret shape.
 *
 * Deliberately WIDER than one format, because the two pairing modes hand over
 * different things and both must work: a QR invite carries 43 base64url characters,
 * and a typed device card carries a twelve-character password from a space that also
 * fits here. The relay does not need to know which it received — it only verifies that
 * the client can prove possession of whatever the host registered.
 */
const SECRET_PATTERN = /^[A-Za-z0-9_-]{8,64}$/

/** A registration or claim failure, carrying a relay error code. */
export class RegistryError extends Error {
  /**
   * @param code - a {@link RELAY_ERROR} value.
   * @param message - the human-readable explanation.
   */
  constructor(code, message) {
    super(message)
    this.name = 'RegistryError'
    this.code = code
  }
}

/** One invite's live state. */
class Slot {
  /**
   * @param options.inviteId - the invite id.
   * @param options.secret - the invite secret.
   * @param options.expiresAt - the expiry.
   * @param options.createdAt - when it was registered.
   * @param options.now - the clock reading used for diagnostics.
   */
  constructor(options) {
    this.inviteId = options.inviteId
    this.secret = options.secret
    this.expiresAt = options.expiresAt
    this.createdAt = options.now
    /** @type {{ host: object | undefined, guest: object | undefined }} */
    this.roles = { host: undefined, guest: undefined }
    this.pairedAt = undefined
  }

  /** @returns true when both roles are occupied. */
  get paired() {
    return this.roles.host !== undefined && this.roles.guest !== undefined
  }

  /**
   * The other role's connection, or `undefined`.
   * @param role - this side's role.
   * @returns the peer's connection handle.
   */
  peerOf(role) {
    return role === 'host' ? this.roles.guest : this.roles.host
  }

  /** Wipe the secret before dropping the slot. */
  destroy() {
    this.secret = undefined
  }
}

/** The invite registry. */
export class InviteRegistry {
  /**
   * @param options.ttlMs - the default invite lifetime.
   * @param options.maxSlots - the ceiling on concurrent invites.
   * @param options.now - the clock, injectable for tests.
   */
  constructor(options = {}) {
    this.ttlMs = Number.isSafeInteger(options.ttlMs) ? options.ttlMs : DEFAULT_INVITE_TTL_MS
    this.maxSlots = Number.isSafeInteger(options.maxSlots) ? options.maxSlots : 10000
    this.now = typeof options.now === 'function' ? options.now : () => Date.now()
    /** @type {Map<string, Slot>} */
    this.slots = new Map()
  }

  /**
   * Register one invite.
   *
   * @param input - `{ inviteId, secret, expiresAt }`.
   * @returns the registered slot's receipt.
   * @throws {RegistryError} when the input is malformed, expired, or already live.
   */
  register(input) {
    const inviteId = String(input?.inviteId ?? '')
    if (!SLOT_ID_PATTERN.test(inviteId)) {
      throw new RegistryError(RELAY_ERROR.badMessage, 'a slot id must be 4 to 64 lower-case letters or digits')
    }
    const secret = String(input?.secret ?? '')
    if (!SECRET_PATTERN.test(secret)) {
      throw new RegistryError(RELAY_ERROR.badMessage, 'a pairing secret must be 8 to 64 characters from A-Z, a-z, 0-9, "_" or "-"')
    }
    const now = this.now()
    this.sweep()
    const requested = Number(input?.expiresAt)
    if (!Number.isSafeInteger(requested) || requested <= now) {
      throw new RegistryError(RELAY_ERROR.inviteExpired, 'the invite is already expired')
    }
    const expiresAt = Math.min(requested, now + MAX_INVITE_TTL_MS)
    const existing = this.slots.get(inviteId)
    if (existing !== undefined) {
      // Three outcomes, and the middle one is what makes a STABLE device code with a
      // ROTATING password possible:
      //
      //   - the same secret again  → idempotent, just extend (a host restarting);
      //   - the PREVIOUS secret    → replace (the host rotated the password, and only
      //                              it knows what the old one was);
      //   - anything else          → refused, so an observer of a leaked code cannot
      //                              seize the rendezvous.
      if (existing.secret === secret) {
        existing.expiresAt = expiresAt
        existing.reRegistered = (existing.reRegistered ?? 0) + 1
        return { inviteId, expiresAt, reRegistered: true }
      }
      const previous = String(input?.previousSecret ?? '')
      if (previous.length > 0 && previous === existing.secret) {
        existing.secret = secret
        existing.expiresAt = expiresAt
        existing.rotated = (existing.rotated ?? 0) + 1
        return { inviteId, expiresAt, rotated: true }
      }
      throw new RegistryError(
        RELAY_ERROR.inviteUsed,
        'this device code is already in use by a pairing this relay cannot verify; wait for it to expire or use another code',
      )
    }
    if (this.slots.size >= this.maxSlots) {
      throw new RegistryError(RELAY_ERROR.rateLimited, 'the relay is at its invite capacity; try again shortly')
    }
    this.slots.set(inviteId, new Slot({ inviteId, secret, expiresAt, createdAt: now, now }))
    return { inviteId, expiresAt, reRegistered: false }
  }

  /**
   * Look up a live invite, expiring it if its time has passed.
   * @param inviteId - the invite id.
   * @returns the slot.
   * @throws {RegistryError} when there is no live invite with that id.
   */
  require(inviteId) {
    const slot = this.slots.get(String(inviteId))
    if (slot === undefined) {
      throw new RegistryError(RELAY_ERROR.inviteUnknown, 'no such device code or invite; it may have expired, been consumed, or belong to another relay')
    }
    if (this.now() > slot.expiresAt) {
      this.drop(slot.inviteId)
      throw new RegistryError(RELAY_ERROR.inviteExpired, 'this invite has expired')
    }
    return slot
  }

  /**
   * Claim one role in a slot.
   *
   * @param slot - the slot.
   * @param role - `host` or `guest`.
   * @param connection - the claiming connection handle.
   * @returns `{ peer, isPaired }` where `peer` is the other role's connection
   *   handle when it is present.
   * @throws {RegistryError} when the role is already occupied.
   */
  claim(slot, role, connection) {
    if (role !== 'host' && role !== 'guest') {
      throw new RegistryError(RELAY_ERROR.badRole, `unknown role ${JSON.stringify(role)}`)
    }
    if (slot.roles[role] !== undefined) {
      throw new RegistryError(
        RELAY_ERROR.roleTaken,
        `a ${role} is already connected to this invite; one ${role} at a time`,
      )
    }
    slot.roles[role] = connection
    if (slot.paired && slot.pairedAt === undefined) slot.pairedAt = this.now()
    return { peer: slot.peerOf(role), isPaired: slot.paired }
  }

  /**
   * Release one role.
   *
   * The slot is deliberately KEPT until its TTL even when both roles are gone.
   * Dropping it here was the first implementation, and it made a dropped
   * connection unrecoverable: the client's very next join was answered
   * `invite-unknown`, so the only fix was carrying a fresh QR code to the other
   * machine. Keeping the slot costs a few hundred bytes until the TTL and grants
   * nothing to an attacker, because claiming a role still requires the secret.
   *
   * @param slot - the slot.
   * @param role - the role leaving.
   * @returns the peer connection that should be told, if any.
   */
  release(slot, role) {
    if (slot.roles[role] === undefined) return { peer: undefined }
    slot.roles[role] = undefined
    return { peer: slot.peerOf(role) }
  }

  /**
   * Remove one slot and wipe its secret.
   * @param inviteId - the invite id.
   * @returns true when a slot was removed.
   */
  drop(inviteId) {
    const slot = this.slots.get(String(inviteId))
    if (slot === undefined) return false
    slot.destroy()
    this.slots.delete(String(inviteId))
    return true
  }

  /**
   * Drop every expired slot.
   * @returns the number of slots removed.
   */
  sweep() {
    const now = this.now()
    let removed = 0
    for (const slot of [...this.slots.values()]) {
      if (now > slot.expiresAt) {
        this.drop(slot.inviteId)
        removed += 1
      }
    }
    return removed
  }

  /**
   * A redacted status document.
   *
   * Deliberately contains no invite id and no secret: it is served on the health
   * endpoint, which is unauthenticated.
   *
   * @returns `{ invites, paired, waiting }`.
   */
  stats() {
    let paired = 0
    let waiting = 0
    for (const slot of this.slots.values()) {
      if (slot.paired) paired += 1
      else waiting += 1
    }
    return { invites: this.slots.size, paired, waiting }
  }

  /** Drop every slot, wiping secrets. Used on shutdown. */
  clear() {
    for (const slot of this.slots.values()) slot.destroy()
    this.slots.clear()
  }
}
