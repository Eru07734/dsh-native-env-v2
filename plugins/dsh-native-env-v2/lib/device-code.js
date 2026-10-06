/**
 * dsh-native-env / device-code — the human-typeable form of a pairing.
 *
 * A QR code is the wrong primary affordance on a desktop. The machine being paired
 * usually has no camera, the machine showing the code usually has no one standing at
 * it with a phone, and the flow people already know from remote-desktop software is
 * simply: read a device code off one screen, type it and a temporary password into
 * the other. That is what this module produces.
 *
 * Two values, with deliberately different lifetimes:
 *
 *   - **The device code is STABLE per machine** (nine digits, derived from the host's
 *     identity key, so it needs no storage and never changes unless the identity
 *     does). That is the property that makes it recognizable: the same computer is
 *     always `123 456 789`. It is an ADDRESS, not a secret — it identifies where to
 *     knock, and nothing more.
 *   - **The password ROTATES per pairing session** (twelve characters, grouped
 *     `XXXX-XXXX-XXXX`). It is the credential, it expires with the session, and it is
 *     meant to be read aloud and typed once.
 *
 * Three formatting decisions are load-bearing rather than cosmetic:
 *
 *   1. **The password alphabet is derived by excluding every ambiguous glyph** (see
 *      `AMBIGUOUS_GLYPHS`), leaving 25 symbols. That is 55 bits over twelve
 *      characters, which is far more than a rate-limited rendezvous needs — and a
 *      symbol set that cannot be confused is what makes twelve characters typeable at
 *      all. Read-aloud pairing fails on transcription far more often than it fails on
 *      anything cryptographic.
 *   2. **Grouping is for display only.** `normalizePassword` and
 *      `normalizeDeviceCode` strip every separator, so a user may type the dashes, the
 *      spaces, or nothing at all.
 *   3. **Nine digits is a small space, and it is treated as one.** 10^9 is guessable
 *      by enumeration, which is why the relay rate-limits failed joins per address and
 *      why the password carries 60 bits. This module produces the code; the relay is
 *      what has to make guessing it pointless.
 *
 * What a typed pairing CANNOT do is pin the host's identity, because there is nothing
 * to carry a fingerprint: the human typed two values, not a signed blob. The
 * consequence is stated where it matters rather than here — see the note on
 * `pairing-session.js` and the `Short authentication` section of the disclaimers.
 * The QR path is unchanged and still pins it.
 *
 * @module dsh-native-env/device-code
 */

import { createHash, randomBytes, randomInt } from 'node:crypto'

import { exportPublicKey } from './e2ee.js'

/** Nine digits, as remote-desktop software has trained users to expect. */
export const DEVICE_CODE_DIGITS = 9

/**
 * The glyphs a human reads aloud or transcribes wrongly.
 *
 * Stated as a rule rather than as a hand-picked alphabet, because a hand-picked list
 * and a comment about it drift apart — which is exactly what the first version of this
 * file did (the comment claimed `L`, `S` and `B` were excluded while the alphabet
 * contained all three).
 *
 *   - `0`/`O`, `1`/`I`/`L` — the classic pairs, in every font.
 *   - `S`/`5`, `Z`/`2`, `B`/`8`, `G`/`6` — the pairs that survive a monospace screen
 *     but not a phone photograph of one.
 *   - `Q`/`O`, `U`/`V` — worse in handwriting than in print, and a card is often
 *     copied onto paper.
 */
export const AMBIGUOUS_GLYPHS = '01ILOSZBGQU'

/** The symbols a pairing password may use. Derived, so it cannot disagree with the rule. */
export const PASSWORD_ALPHABET = [...'23456789ABCDEFGHIJKLMNOPQRSTUVWXYZ']
  .filter((character) => !AMBIGUOUS_GLYPHS.includes(character))
  .join('')

/** Twelve symbols over that alphabet: 55 bits, which the relay's throttle makes ample. */
export const PASSWORD_LENGTH = 12

/** How a device code is grouped for display. */
export const DEVICE_CODE_GROUP = 3

/** How a password is grouped for display. */
export const PASSWORD_GROUP = 4

/** A pairing failure the caller can show a human. */
export class DeviceCodeError extends Error {
  /**
   * @param code - a stable machine-readable code.
   * @param message - the human-readable explanation.
   */
  constructor(code, message) {
    super(message)
    this.name = 'DeviceCodeError'
    this.code = code
  }
}

/**
 * Derive this machine's device code from its identity public key.
 *
 * Derived rather than stored so that it cannot drift from the identity it belongs
 * to, and so a reinstall of the plugin keeps the same code as long as the identity
 * survives. `salt` exists for exactly one situation: the relay already has that code
 * registered to a different machine, which is a 1-in-10^9 collision the operator can
 * still hit, and the fix must not be "reinstall and hope".
 *
 * @param publicKey - the identity public key (KeyObject, DER Buffer, or base64).
 * @param salt - a collision counter; 0 for the machine's own code.
 * @returns the nine-digit code as a string.
 */
export function deriveDeviceCode(publicKey, salt = 0) {
  const base = exportPublicKey(publicKey)
  const digest = createHash('sha256').update(`dsh-native-env/device-code|${base}|${String(salt)}`).digest()
  // The first four bytes are read as one unsigned integer and reduced; the bias
  // from `mod` over 2^32 is on the order of 10^-7 and is irrelevant for an address
  // that the relay rate-limits anyway.
  const value = digest.readUInt32BE(0) % 1_000_000_000
  return String(value).padStart(DEVICE_CODE_DIGITS, '0')
}

/**
 * Group a device code for display: `123456789` becomes `123 456 789`.
 * @param code - the raw code.
 * @returns the grouped form.
 */
export function formatDeviceCode(code) {
  const raw = String(code)
  const groups = []
  for (let index = 0; index < raw.length; index += DEVICE_CODE_GROUP) {
    groups.push(raw.slice(index, index + DEVICE_CODE_GROUP))
  }
  return groups.join(' ')
}

/**
 * Strip whatever separators a human used and validate a device code.
 * @param text - the typed value.
 * @returns the nine digits, or `undefined` when it is not a device code.
 */
export function normalizeDeviceCode(text) {
  const digits = String(text ?? '').replace(/[\s\-_.]/g, '')
  if (!/^\d{9}$/.test(digits)) return undefined
  return digits
}

/**
 * Mint one pairing password.
 *
 * `randomInt` rather than `% alphabet.length` over random bytes: the modulo bias of
 * the shortcut is small, but this is a credential and the unbiased call is the same
 * number of lines.
 *
 * @returns the twelve raw characters (no separators).
 */
export function newPassword() {
  let value = ''
  for (let index = 0; index < PASSWORD_LENGTH; index += 1) {
    value += PASSWORD_ALPHABET[randomInt(PASSWORD_ALPHABET.length)]
  }
  return value
}

/**
 * Group a password for display: `K7FM2QXP9RAZ` becomes `K7FM-2QXP-9RAZ`.
 * @param password - the raw password.
 * @returns the grouped form.
 */
export function formatPassword(password) {
  const raw = String(password)
  const groups = []
  for (let index = 0; index < raw.length; index += PASSWORD_GROUP) {
    groups.push(raw.slice(index, index + PASSWORD_GROUP))
  }
  return groups.join('-')
}

/**
 * Upper-case and de-separate a typed password.
 *
 * Case is ignored on input because a user reading `K7FM` may type `k7fm`, and the
 * alphabet has no case pairs that could collide — every symbol is upper-case, so
 * folding case cannot merge two different passwords.
 *
 * @param text - the typed value.
 * @returns the twelve raw characters, or `undefined` when it is not a password.
 */
export function normalizePassword(text) {
  const raw = String(text ?? '')
    .trim()
    .toUpperCase()
    .replace(/[\s\-_.]/g, '')
  if (raw.length !== PASSWORD_LENGTH) return undefined
  for (const character of raw) {
    if (!PASSWORD_ALPHABET.includes(character)) return undefined
  }
  return raw
}

/**
 * Whether one string could be a pairing password, without normalizing it.
 *
 * The relay needs this check and must NOT import the alphabet's meaning from the
 * client — it only has to know the accepted character set and length. Exported
 * separately so the relay's validation can be read on its own.
 *
 * @param text - the candidate.
 * @returns true when it is a shapely password.
 */
export function looksLikePassword(text) {
  return typeof text === 'string' && /^[A-Za-z0-9_-]{8,64}$/.test(text)
}

/**
 * One shareable device card.
 *
 * `raw` fields go on the wire; `display` fields go on a screen. Keeping them apart in
 * one object is what stops a caller from accidentally sending the grouped form (with
 * spaces) as the actual credential.
 */
export class DeviceCard {
  /**
   * @param options.deviceCode - the nine raw digits.
   * @param options.password - the twelve raw characters.
   * @param options.expiresAt - when the password stops being accepted.
   * @param options.hostFingerprint - this host's identity fingerprint.
   * @param options.label - this host's display label.
   */
  constructor(options) {
    this.deviceCode = options.deviceCode
    this.password = options.password
    this.expiresAt = options.expiresAt
    this.hostFingerprint = options.hostFingerprint
    this.label = options.label
  }

  /** @returns the card in the form a UI renders, with no secret removed. */
  toDisplay() {
    return {
      deviceCode: this.deviceCode,
      displayCode: formatDeviceCode(this.deviceCode),
      password: this.password,
      displayPassword: formatPassword(this.password),
      expiresAt: this.expiresAt,
      hostFingerprint: this.hostFingerprint,
      label: this.label,
    }
  }

  /**
   * @returns the card WITHOUT the password, for anything loggable, listable or
   *   remotely readable that is not the owner's own screen. A status document that
   *   carries the credential is a status document that leaks it.
   */
  toRedacted() {
    return {
      deviceCode: this.deviceCode,
      displayCode: formatDeviceCode(this.deviceCode),
      expiresAt: this.expiresAt,
      hostFingerprint: this.hostFingerprint,
      label: this.label,
    }
  }
}

/**
 * Mint a full device card.
 * @param options.publicKey - the host identity's public key, for the code.
 * @param options.codeSalt - the collision counter for the code.
 * @param options.ttlMs - the password's lifetime.
 * @param options.hostFingerprint - the host identity's fingerprint.
 * @param options.label - the host's display label.
 * @param options.now - the clock, injectable for tests.
 * @returns the card.
 */
export function createDeviceCard(options) {
  const now = Number.isSafeInteger(options.now) ? options.now : Date.now()
  return new DeviceCard({
    deviceCode: deriveDeviceCode(options.publicKey, options.codeSalt ?? 0),
    password: newPassword(),
    expiresAt: now + (Number.isSafeInteger(options.ttlMs) ? options.ttlMs : 10 * 60 * 1000),
    hostFingerprint: options.hostFingerprint,
    label: options.label,
  })
}

/** @returns `n` random bytes, hex — re-exported so callers need one import for the pairing family. */
export function randomHex(bytes = 8) {
  return randomBytes(bytes).toString('hex')
}
