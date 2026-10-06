/**
 * dsh-native-env / e2ee tests.
 *
 * These pin the properties that make a PUBLIC relay acceptable at all. Each one
 * corresponds to a concrete way the pairing transport could be broken by a
 * third party that sits between the two machines:
 *
 *   - the relay is not trusted with plaintext, so a frame must not decrypt under
 *     the wrong key, the wrong direction, or the wrong sequence;
 *   - the relay holds the invite secret (it has to, to authorize the rendezvous),
 *     so a GUEST must be able to reject a relay that tries to impersonate the
 *     host — that is the fingerprint plus signature check;
 *   - a low-order X25519 point yields an all-zero shared secret, which Node
 *     happily returns; deriving a session key from it would hand an attacker a
 *     key it already knows.
 *
 * @module dsh-native-env/tests/e2ee
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  CryptoFailure,
  DIRECTION_GUEST_TO_HOST,
  DIRECTION_HOST_TO_GUEST,
  deriveSessionKeys,
  exportIdentity,
  exportPublicKey,
  fingerprint,
  generateEphemeral,
  generateIdentity,
  hmacProof,
  newInviteId,
  newIvPrefix,
  newNonce,
  newPairSecret,
  openFrame,
  publicKeyDer,
  restoreIdentity,
  sameString,
  sealFrame,
  sharedSecret,
  signTranscript,
  verifyTranscript,
} from '../lib/e2ee.js'

/** A complete host/guest session, the way the pairing session builds one. */
function session() {
  const hostIdentity = generateIdentity()
  const guestIdentity = generateIdentity()
  const hostEph = generateEphemeral()
  const guestEph = generateEphemeral()
  const inviteId = newInviteId()
  const guestNonce = newNonce()
  const hostNonce = newNonce()

  const guestSecret = sharedSecret(guestEph.privateKey, exportPublicKey(hostEph.publicKey))
  const hostSecret = sharedSecret(hostEph.privateKey, exportPublicKey(guestEph.publicKey))
  assert.deepEqual(guestSecret, hostSecret, 'both sides must reach the same shared secret')

  const salt = `${guestNonce}${hostNonce}`
  return {
    hostIdentity,
    guestIdentity,
    inviteId,
    guestNonce,
    hostNonce,
    hostKeys: deriveSessionKeys(hostSecret, salt, inviteId),
    guestKeys: deriveSessionKeys(guestSecret, salt, inviteId),
    hostIv: newIvPrefix(),
    guestIv: newIvPrefix(),
  }
}

// ── identities and fingerprints ──────────────────────────────────────────────

test('an identity survives export and restore', () => {
  const identity = generateIdentity()
  const stored = exportIdentity(identity)
  const restored = restoreIdentity(stored)
  assert.equal(fingerprint(restored.publicKey), fingerprint(identity.publicKey))
  assert.equal(exportPublicKey(restored.publicKey), exportPublicKey(identity.publicKey))
})

test('a fingerprint is 16 hex characters and follows the key, not the encoding', () => {
  const identity = generateIdentity()
  const value = fingerprint(identity.publicKey)
  assert.match(value, /^[0-9a-f]{16}$/)
  // KeyObject, DER Buffer and base64 string are the same key and must agree.
  assert.equal(fingerprint(publicKeyDer(identity.publicKey)), value)
  assert.equal(fingerprint(identity.publicKey.export({ type: 'spki', format: 'der' })), value)
  // A different key is a different fingerprint.
  assert.notEqual(fingerprint(generateIdentity().publicKey), value)
})

test('a truncated identity record is refused by name', () => {
  const identity = generateIdentity()
  const stored = exportIdentity(identity)
  assert.throws(() => restoreIdentity({ publicKey: stored.publicKey }), /missing one of its two halves/)
  assert.throws(() => restoreIdentity({ publicKey: 'AAAA', privateKey: 'AAAA' }), /cannot be read/)
})

// ── signatures ───────────────────────────────────────────────────────────────

test('an identity signature verifies only for its own transcript and key', () => {
  const host = generateIdentity()
  const other = generateIdentity()
  const transcript = `dsh-native-env/pair-ack|2|abc|def`
  const signature = signTranscript(host.privateKey, transcript)

  assert.equal(verifyTranscript(host.publicKey, transcript, signature), true)
  assert.equal(verifyTranscript(other.publicKey, transcript, signature), false, 'another key must not verify it')
  assert.equal(verifyTranscript(host.publicKey, `${transcript}!`, signature), false, 'a changed transcript must not verify')
  assert.equal(verifyTranscript(host.publicKey, transcript, 'not-base64-signature'), false, 'garbage must be a failed verification, not a throw')
})

// ── the key exchange ─────────────────────────────────────────────────────────

test('a degenerate peer key is refused instead of deriving a known key', () => {
  // The X25519 identity point: a low-order point whose shared secret is all zero.
  const lowOrder = Buffer.from('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'base64')
  const ephemeral = generateEphemeral()
  assert.throws(
    () => sharedSecret(ephemeral.privateKey, lowOrder.toString('base64')),
    (error) => {
      assert.ok(error instanceof CryptoFailure)
      return ['ecdh-degenerate', 'ecdh-failed', 'public-key-unreadable'].includes(error.code)
    },
  )
})

test('a non-key is refused with the public-key code', () => {
  const ephemeral = generateEphemeral()
  assert.throws(
    () => sharedSecret(ephemeral.privateKey, Buffer.from('not a key').toString('base64')),
    (error) => error instanceof CryptoFailure && error.code === 'public-key-unreadable',
  )
})

// ── frame sealing ────────────────────────────────────────────────────────────

test('a sealed frame round-trips in its own direction', () => {
  const s = session()
  const payload = JSON.stringify({ jsonrpc: '2.0', method: 'env/list' })
  const sealed = sealFrame(s.hostKeys.hostToGuest, s.hostIv, DIRECTION_HOST_TO_GUEST, 1, s.inviteId, payload)
  assert.notEqual(sealed.toString('utf8'), payload, 'the payload must not travel in the clear')
  const opened = openFrame(s.guestKeys.hostToGuest, s.hostIv, DIRECTION_HOST_TO_GUEST, 1, s.inviteId, sealed)
  assert.equal(opened, payload)
})

test('a frame does not open under the other direction key', () => {
  const s = session()
  const sealed = sealFrame(s.hostKeys.hostToGuest, s.hostIv, DIRECTION_HOST_TO_GUEST, 1, s.inviteId, 'secret')
  // The classic reflection attack: hand the frame back to its sender using the
  // opposite direction. It must fail, not decrypt.
  assert.throws(
    () => openFrame(s.hostKeys.guestToHost, s.hostIv, DIRECTION_GUEST_TO_HOST, 1, s.inviteId, sealed),
    (error) => error instanceof CryptoFailure && error.code === 'frame-auth-failed',
  )
})

test('a replayed frame is refused at a different sequence number', () => {
  const s = session()
  const sealed = sealFrame(s.hostKeys.hostToGuest, s.hostIv, DIRECTION_HOST_TO_GUEST, 7, s.inviteId, 'once')
  assert.equal(openFrame(s.guestKeys.hostToGuest, s.hostIv, DIRECTION_HOST_TO_GUEST, 7, s.inviteId, sealed), 'once')
  // Presenting the SAME bytes as sequence 8 must fail: the sequence is bound
  // into the AAD, so a replay cannot masquerade as the next frame.
  assert.throws(
    () => openFrame(s.guestKeys.hostToGuest, s.hostIv, DIRECTION_HOST_TO_GUEST, 8, s.inviteId, sealed),
    (error) => error instanceof CryptoFailure && error.code === 'frame-auth-failed',
  )
})

test('a tampered frame is refused', () => {
  const s = session()
  const sealed = sealFrame(s.hostKeys.hostToGuest, s.hostIv, DIRECTION_HOST_TO_GUEST, 1, s.inviteId, 'run rm -rf /')
  const tampered = Buffer.from(sealed)
  tampered[0] ^= 0x01
  assert.throws(
    () => openFrame(s.guestKeys.hostToGuest, s.hostIv, DIRECTION_HOST_TO_GUEST, 1, s.inviteId, tampered),
    (error) => error instanceof CryptoFailure && error.code === 'frame-auth-failed',
  )
})

test('a truncated frame is refused before any decryption', () => {
  const s = session()
  const sealed = sealFrame(s.hostKeys.hostToGuest, s.hostIv, DIRECTION_HOST_TO_GUEST, 1, s.inviteId, 'hello')
  assert.throws(
    () => openFrame(s.guestKeys.hostToGuest, s.hostIv, DIRECTION_HOST_TO_GUEST, 1, s.inviteId, sealed.subarray(0, 8)),
    (error) => error instanceof CryptoFailure && error.code === 'frame-truncated',
  )
})

test('a frame sealed for one invite does not open under another', () => {
  const s = session()
  const sealed = sealFrame(s.hostKeys.hostToGuest, s.hostIv, DIRECTION_HOST_TO_GUEST, 1, s.inviteId, 'hello')
  assert.throws(
    () => openFrame(s.guestKeys.hostToGuest, s.hostIv, DIRECTION_HOST_TO_GUEST, 1, newInviteId(), sealed),
    (error) => error instanceof CryptoFailure && error.code === 'frame-auth-failed',
  )
})

test('two sessions derive different keys from the same identities', () => {
  const a = session()
  const b = session()
  assert.notDeepEqual(a.hostKeys.hostToGuest, b.hostKeys.hostToGuest, 'session keys must not be reusable across invites')
})

// ── small helpers ────────────────────────────────────────────────────────────

test('sameString is constant-time-shaped and length-strict', () => {
  assert.equal(sameString('abcdef', 'abcdef'), true)
  assert.equal(sameString('abcdef', 'abcdeg'), false)
  assert.equal(sameString('abc', 'abcdef'), false)
  assert.equal(sameString('', ''), false)
  assert.equal(sameString(undefined, 'x'), false)
})

test('the generated secrets have the advertised shape', () => {
  assert.match(newInviteId(), /^[0-9a-f]{32}$/)
  assert.match(newPairSecret(), /^[A-Za-z0-9_-]{43}$/)
  assert.match(newNonce(), /^[0-9a-f]{32}$/)
  assert.equal(newIvPrefix().length, 4)
})

test('the relay proof is reproducible by the relay and differs by role', () => {
  const secret = newPairSecret()
  const clientNonce = newNonce()
  const serverNonce = newNonce()
  const asHost = hmacProof(secret, 'relay', 'abc', 'host', clientNonce, serverNonce)
  assert.equal(asHost, hmacProof(secret, 'relay', 'abc', 'host', clientNonce, serverNonce))
  assert.notEqual(asHost, hmacProof(secret, 'relay', 'abc', 'guest', clientNonce, serverNonce))
  assert.notEqual(asHost, hmacProof(newPairSecret(), 'relay', 'abc', 'host', clientNonce, serverNonce))
})
