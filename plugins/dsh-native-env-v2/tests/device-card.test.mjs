/**
 * dsh-native-env / device-code tests.
 *
 * The device card is the one part of this plugin a human TRANSCRIBES, so the tests
 * are mostly about the properties that make transcription survive: an alphabet with
 * no confusable glyphs, separators that may be typed or omitted, and case folding that
 * cannot merge two different passwords. The cryptographic half — that a relay in the
 * middle makes the two short codes disagree — is pinned through `shortAuthString`.
 *
 * @module dsh-native-env/tests/device-code
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { exportPublicKey, generateIdentity, newNonce, shortAuthString } from '../lib/e2ee.js'
import {
  AMBIGUOUS_GLYPHS,
  DEVICE_CODE_DIGITS,
  PASSWORD_ALPHABET,
  PASSWORD_LENGTH,
  createDeviceCard,
  deriveDeviceCode,
  formatDeviceCode,
  formatPassword,
  looksLikePassword,
  newPassword,
  normalizeDeviceCode,
  normalizePassword,
} from '../lib/device-code.js'
import { JOIN_MODE, createDeviceJoin, describeInvite, validateInvite } from '../lib/pairing.js'

// ── the alphabet ─────────────────────────────────────────────────────────────

test('the password alphabet omits every glyph a human confuses', () => {
  // Asserted as the RULE rather than as a hand-written list: the first version of the
  // alphabet and its comment disagreed, and a test that re-states the list would have
  // had the same defect.
  for (const glyph of AMBIGUOUS_GLYPHS) {
    assert.equal(PASSWORD_ALPHABET.includes(glyph), false, `${glyph} is ambiguous and must not be in the alphabet`)
  }
  assert.equal(PASSWORD_ALPHABET.length, 25, 'the alphabet size is what the bit arithmetic claims')
  assert.equal(new Set(PASSWORD_ALPHABET).size, PASSWORD_ALPHABET.length, 'no symbol may repeat')
  assert.match(PASSWORD_ALPHABET, /^[2-9A-Z]+$/, 'every symbol must be an uppercase letter or a digit that is not 0 or 1')
  for (const glyph of ['2', '9', 'A', 'H', 'K', 'M', 'X']) {
    assert.equal(PASSWORD_ALPHABET.includes(glyph), true, `${glyph} should be in the alphabet`)
  }
})

test('a minted password is exactly as long as advertised and drawn from the alphabet', () => {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const password = newPassword()
    assert.equal(password.length, PASSWORD_LENGTH)
    for (const character of password) assert.ok(PASSWORD_ALPHABET.includes(character), `${character} is outside the alphabet`)
  }
})

test('two minted passwords are not the same', () => {
  const seen = new Set()
  for (let attempt = 0; attempt < 50; attempt += 1) seen.add(newPassword())
  assert.equal(seen.size, 50, 'a password generator that repeats is not a generator')
})

// ── typing it back in ────────────────────────────────────────────────────────

test('a password survives being typed with separators, spaces or lower case', () => {
  const password = 'K7FM2XNP9RAV'
  assert.equal(normalizePassword(password), password)
  assert.equal(normalizePassword('K7FM-2XNP-9RAV'), password)
  assert.equal(normalizePassword('k7fm 2xnp 9rav'), password)
  assert.equal(normalizePassword('  K7FM_2XNP_9RAV  '), password)
  assert.equal(formatPassword(password), 'K7FM-2XNP-9RAV')
})

test('a password that is not one is refused rather than repaired', () => {
  assert.equal(normalizePassword(''), undefined)
  assert.equal(normalizePassword('K7FM2XNP9RA'), undefined, 'too short')
  assert.equal(normalizePassword('K7FM2XNP9RAVZ'), undefined, 'too long')
  // The excluded glyphs must be REFUSED, not silently folded to something else: a
  // user who reads `O` off a screen and types `O` has been shown a card that contains
  // no `O`, which is a different problem from a typo.
  assert.equal(normalizePassword('O7FM2XNP9RAV'), undefined)
  assert.equal(normalizePassword('K7FM2XNP9RA!'), undefined)
})

test('looksLikePassword accepts both a typed password and a QR invite secret', () => {
  assert.equal(looksLikePassword(newPassword()), true)
  // The QR path's 43-character base64url secret must still pass the relay's check.
  assert.equal(looksLikePassword('A'.repeat(43)), true)
  assert.equal(looksLikePassword('short'), false)
  assert.equal(looksLikePassword('has spaces inside'), false)
  assert.equal(looksLikePassword('x'.repeat(65)), false)
  assert.equal(looksLikePassword(undefined), false)
})

// ── the device code ──────────────────────────────────────────────────────────

test('a device code is nine digits, stable for one identity, and different for another', () => {
  const identity = generateIdentity()
  const code = deriveDeviceCode(identity.publicKey)
  assert.match(code, /^\d{9}$/)
  assert.equal(code.length, DEVICE_CODE_DIGITS)
  assert.equal(formatDeviceCode(code), `${code.slice(0, 3)} ${code.slice(3, 6)} ${code.slice(6)}`)
  // STABLE is the property that makes the card recognizable: the same computer always
  // shows the same code, derived rather than stored.
  assert.equal(deriveDeviceCode(identity.publicKey), code)
  assert.equal(deriveDeviceCode(exportPublicKey(identity.publicKey)), code, 'a different encoding of one key is one code')
  // A collision counter is the only thing that changes it.
  assert.notEqual(deriveDeviceCode(identity.publicKey, 1), code)
  assert.notEqual(deriveDeviceCode(generateIdentity().publicKey), code)
})

test('a device code survives being typed with separators', () => {
  assert.equal(normalizeDeviceCode('123456789'), '123456789')
  assert.equal(normalizeDeviceCode('123 456 789'), '123456789')
  assert.equal(normalizeDeviceCode('123-456-789'), '123456789')
  assert.equal(normalizeDeviceCode(' 123.456.789 '), '123456789')
  assert.equal(normalizeDeviceCode('12345678'), undefined)
  assert.equal(normalizeDeviceCode('1234567890'), undefined)
  assert.equal(normalizeDeviceCode('12345678a'), undefined)
  assert.equal(normalizeDeviceCode(undefined), undefined)
})

// ── the card object ──────────────────────────────────────────────────────────

test('a card shows the password but a redacted card never does', () => {
  const identity = generateIdentity()
  const card = createDeviceCard({ publicKey: identity.publicKey, ttlMs: 60_000, hostFingerprint: 'a1b2c3d4e5f60718', label: 'test host' })
  const display = card.toDisplay()
  assert.equal(display.password, card.password)
  assert.equal(display.displayPassword, formatPassword(card.password))
  assert.equal(display.displayCode, formatDeviceCode(card.deviceCode))
  assert.ok(display.expiresAt > Date.now())

  const redacted = card.toRedacted()
  const serialized = JSON.stringify(redacted)
  assert.equal(serialized.includes(card.password), false, 'the redacted form must not carry the password')
  assert.equal(serialized.includes('password'), false)
  // The code IS in the redacted form: it is an address, meant to be read aloud.
  assert.equal(redacted.deviceCode, card.deviceCode)
})

// ── the join descriptor ──────────────────────────────────────────────────────

test('a typed join is a valid descriptor with no fingerprint, and says so', () => {
  const join = createDeviceJoin({ relay: 'wss://relay.test/v2/relay', deviceCode: '123 456 789', password: 'k7fm-2xnp-9rav' })
  assert.equal(join.mode, JOIN_MODE.code)
  assert.equal(join.inviteId, '123456789')
  assert.equal(join.pairSecret, 'K7FM2XNP9RAV', 'the descriptor must carry the normalized password, not what was typed')
  assert.equal('fingerprint' in join, false, 'a typed join must not pretend to pin an identity')

  const verdict = validateInvite(join)
  assert.equal(verdict.ok, true, verdict.error)
  assert.equal(verdict.mode, JOIN_MODE.code)

  const described = describeInvite(join)
  assert.equal(described.mode, 'code')
  assert.equal(described.deviceCode, '123456789')
  assert.equal(JSON.stringify(described).includes(join.pairSecret), false, 'the description must never carry the password')
})

test('a typed join refuses a malformed code, password or relay', () => {
  const base = { relay: 'wss://relay.test/v2/relay', deviceCode: '123456789', password: 'K7FM2XNP9RAV' }
  // A five-digit value must be refused HERE: as a slot key it is technically valid,
  // which is exactly why the typed path has to be stricter than the relay's pattern.
  assert.throws(() => createDeviceJoin({ ...base, deviceCode: '12345' }), /nine digits/)
  assert.throws(() => createDeviceJoin({ ...base, password: 'short' }), /twelve characters/)
  assert.throws(() => createDeviceJoin({ ...base, relay: 'https://relay.test/v2/relay' }), /ws:\/\/ or wss:\/\//)
})

test('a QR invite still requires a fingerprint, and a typed one must not have one', () => {
  const pinned = { version: 2, mode: 'qr', relay: 'wss://relay.test/v2/relay', inviteId: 'a'.repeat(32), expiresAt: Date.now() + 60_000, pairSecret: 'A'.repeat(43) }
  assert.equal(validateInvite(pinned).code, 'bad-fingerprint')
  const codeJoin = { ...pinned, mode: 'code', inviteId: '123456789', pairSecret: 'K7FM2XNP9RAV' }
  assert.equal(validateInvite(codeJoin).ok, true)
})

// ── the short authentication string ──────────────────────────────────────────

test('the short code is six digits, stable for one session, and different for another', () => {
  const secret = Buffer.alloc(32, 7)
  const parts = ['guest-key', 'host-key', 'invite']
  const value = shortAuthString(secret, ...parts)
  assert.match(value, /^\d{6}$/)
  assert.equal(shortAuthString(secret, ...parts), value)
  // A different secret is a different session, which is the whole mechanism: a relay
  // terminating two sessions derives two secrets and therefore two different codes, so
  // the two screens disagree and the human sees it.
  assert.notEqual(shortAuthString(Buffer.alloc(32, 8), ...parts), value)
  // A different transcript with the same secret also differs, so the code is bound to
  // the keys rather than only to the shared value.
  assert.notEqual(shortAuthString(secret, 'guest-key', 'OTHER-host-key', 'invite'), value)
  assert.notEqual(shortAuthString(secret, ...parts, newNonce()), value)
})
