/**
 * dsh-native-env / e2ee — the cryptography the pairing transport adds on top of
 * the legacy wire.
 *
 * The legacy `tcp` transport is authenticated but NOT confidential: the shared
 * token is never sent, yet every tool name, argument, file path and result
 * travels in the clear (see `handshake.js`). Over `ssh` that did not matter,
 * because ssh already encrypts. A PUBLIC relay is a different situation: the
 * relay is a third party both ends must reach over the open internet, and the
 * whole point of the pairing transport is that the relay must not be able to
 * read — or silently rewrite — the environment traffic it forwards.
 *
 * Three primitives, chosen because Node has all of them built in and this plugin
 * is zero-dependency by construction (an absolute-path-mounted plugin cannot
 * resolve bare specifiers — see `wire.js`):
 *
 *   - **Ed25519 identities.** Persistent per machine. The HOST identity is what a
 *     QR code pins: `fingerprint()` is short enough to fit in a QR code and long
 *     enough (64 bits) that a relay cannot grind a collision that also matches a
 *     one-time invite. This is the property that survives a COMPROMISED relay —
 *     the relay holds the invite secret (it has to, to authorize the
 *     rendezvous), so only a signature check against the pinned host key can stop
 *     it from impersonating the host.
 *   - **X25519 ephemeral ECDH.** One fresh keypair per connection, so the session
 *     key has forward secrecy: recovering a machine's long-term identity key
 *     later does not decrypt a recorded session.
 *   - **HKDF-SHA-256 → AES-256-GCM.** Two DIRECTION-SEPARATED keys, a per-frame
 *     sequence number bound into the AAD, and a 128-bit tag. Direction
 *     separation is not decoration: with one shared key an attacker can reflect a
 *     frame back at its sender (the classic reflection attack), and a reflected
 *     `env/call` would execute a tool twice.
 *
 * What this file deliberately does NOT do:
 *
 *   - It does not store anything. Key material lives in the caller; persistence
 *     is `pairing-store.js`, and secrets go to `ctx.credentials`, never a config
 *     file — the same rule the legacy token follows.
 *   - It does not encrypt the RELAY rendezvous frames (the ones carrying public
 *     keys and signatures). Those are public values by design; what matters is
 *     that they authenticate, and that the env payloads after them never appear
 *     in the clear.
 *
 * @module dsh-native-env/e2ee
 */

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
} from 'node:crypto'

/** Wire version of the pairing protocol. Bumped when a frame shape changes. */
export const PAIRING_VERSION = 2

/** Bytes of a fresh nonce. */
export const NONCE_BYTES = 16

/** Bytes in a pairing secret. 256 bits: it authorizes a rendezvous, not a session. */
export const PAIR_SECRET_BYTES = 32

/** Bytes in an invite id. 128 bits, and it travels to the relay in the clear. */
export const INVITE_ID_BYTES = 16

/** AES-256-GCM appends a 16-byte tag to every ciphertext. */
export const GCM_TAG_BYTES = 16

/** Per-direction IV prefix width; the remaining 8 bytes are the sequence number. */
const IV_PREFIX_BYTES = 4

/** HKDF output: two 32-byte keys, one per direction. */
const DERIVED_KEY_BYTES = 64

/** The two directions a session has, named from the host's point of view. */
export const DIRECTION_HOST_TO_GUEST = 'h2g'
export const DIRECTION_GUEST_TO_HOST = 'g2h'

/** Domain separator for every key this module derives. */
const KEY_INFO = 'dsh-native-env/v2 session keys'

/**
 * A malformed or unverifiable cryptographic input.
 *
 * Every failure here carries a REASON a human can act on: "the peer proved the
 * wrong secret" and "the peer is not the host this invite pins" are different
 * problems with different fixes, and collapsing them into one message is what
 * makes a pairing failure unloggable.
 */
export class CryptoFailure extends Error {
  /**
   * @param code - a stable machine-readable code.
   * @param message - the human-readable explanation.
   */
  constructor(code, message) {
    super(message)
    this.name = 'CryptoFailure'
    this.code = code
  }
}

/** @returns a fresh lowercase-hex nonce. */
export function newNonce(bytes = NONCE_BYTES) {
  return randomBytes(bytes).toString('hex')
}

/** @returns a fresh base64url pairing secret. */
export function newPairSecret() {
  return randomBytes(PAIR_SECRET_BYTES).toString('base64url')
}

/** @returns a fresh lowercase-hex invite id. */
export function newInviteId() {
  return randomBytes(INVITE_ID_BYTES).toString('hex')
}

/** @returns 4 fresh random bytes for one direction's IV prefix. */
export function newIvPrefix() {
  return randomBytes(IV_PREFIX_BYTES)
}

/**
 * Constant-time comparison of two equal-length strings.
 *
 * A length mismatch returns false WITHOUT comparing: `timingSafeEqual` throws on
 * unequal lengths, and a length check leaks only the length, which the protocol
 * fixes anyway.
 *
 * @param a - first string.
 * @param b - second string.
 * @returns true only when both are non-empty and byte-identical.
 */
export function sameString(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  if (a.length === 0 || a.length !== b.length) return false
  const left = Buffer.from(a, 'utf8')
  const right = Buffer.from(b, 'utf8')
  if (left.length !== right.length) return false
  return timingSafeEqual(left, right)
}

// ── identity keys (Ed25519) ──────────────────────────────────────────────────

/**
 * Mint one persistent machine identity.
 *
 * Ed25519 rather than a shared secret because the GUEST must be able to verify
 * the HOST with nothing but a public value it already holds: the fingerprint in
 * the QR code. A shared-secret scheme cannot express that.
 *
 * @returns `{ publicKey, privateKey }` as Node KeyObjects.
 */
export function generateIdentity() {
  return generateKeyPairSync('ed25519')
}

/**
 * Serialize one identity into the two base64 strings a credential record holds.
 *
 * SPKI/PKCS8 DER rather than raw bytes: they are self-describing, so a wrong
 * import fails loudly instead of silently building a key from the wrong bytes.
 *
 * @param identity - `{ publicKey, privateKey }`.
 * @returns `{ publicKey, privateKey }` as base64 strings.
 */
export function exportIdentity(identity) {
  return {
    publicKey: identity.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    privateKey: identity.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  }
}

/**
 * Rebuild one identity from its stored form.
 * @param stored - `{ publicKey, privateKey }` base64 strings.
 * @returns `{ publicKey, privateKey }` KeyObjects.
 * @throws {CryptoFailure} when the record is incomplete or unparseable.
 */
export function restoreIdentity(stored) {
  if (typeof stored?.publicKey !== 'string' || typeof stored?.privateKey !== 'string') {
    throw new CryptoFailure('identity-incomplete', 'the stored identity record is missing one of its two halves')
  }
  try {
    return {
      publicKey: createPublicKey({ key: Buffer.from(stored.publicKey, 'base64'), type: 'spki', format: 'der' }),
      privateKey: createPrivateKey({ key: Buffer.from(stored.privateKey, 'base64'), type: 'pkcs8', format: 'der' }),
    }
  } catch (error) {
    throw new CryptoFailure('identity-unreadable', `the stored identity cannot be read: ${String(error?.message ?? error)}`)
  }
}

/**
 * The short, human-comparable fingerprint of one identity public key.
 *
 * 16 hex characters (64 bits) is the deliberate compromise: long enough that a
 * relay cannot produce a second key with the same fingerprint, short enough to
 * fit in a QR code and be read out loud. It is NOT a secret and is not treated
 * as one.
 *
 * @param publicKey - a KeyObject, an SPKI DER Buffer, or a base64 SPKI string.
 * @returns lowercase hex, 16 characters.
 */
export function fingerprint(publicKey) {
  return createHash('sha256').update(publicKeyDer(publicKey)).digest('hex').slice(0, 16)
}

/**
 * Normalize the several acceptable public-key shapes to SPKI DER.
 * @param publicKey - KeyObject, Buffer, or base64 string.
 * @returns the DER bytes.
 * @throws {CryptoFailure} on anything else.
 */
export function publicKeyDer(publicKey) {
  if (Buffer.isBuffer(publicKey)) return publicKey
  if (typeof publicKey === 'string') return Buffer.from(publicKey, 'base64')
  if (publicKey !== null && typeof publicKey === 'object' && typeof publicKey.export === 'function') {
    return Buffer.from(publicKey.export({ type: 'spki', format: 'der' }))
  }
  throw new CryptoFailure('public-key-shape', 'a public key must be a KeyObject, a Buffer, or a base64 string')
}

/** @returns the base64 SPKI form of one public key. */
export function exportPublicKey(publicKey) {
  return publicKeyDer(publicKey).toString('base64')
}

/**
 * Import one SPKI public key.
 * @param base64 - base64 SPKI DER.
 * @returns the public KeyObject.
 * @throws {CryptoFailure} when it does not parse.
 */
export function importPublicKey(base64) {
  try {
    return createPublicKey({ key: Buffer.from(base64, 'base64'), type: 'spki', format: 'der' })
  } catch (error) {
    throw new CryptoFailure('public-key-unreadable', `the public key is not a valid SPKI DER key: ${String(error?.message ?? error)}`)
  }
}

/**
 * Sign one transcript with an identity private key.
 * @param privateKey - the Ed25519 private KeyObject.
 * @param transcript - the exact bytes being bound.
 * @returns base64 signature.
 */
export function signTranscript(privateKey, transcript) {
  return sign(null, Buffer.from(transcript, 'utf8'), privateKey).toString('base64')
}

/**
 * Verify one transcript signature.
 *
 * A malformed signature is a FAILED verification, not a thrown error: the caller
 * is deciding whether to trust a peer, and "those bytes were not even a
 * signature" is the same answer as "the signature was wrong".
 *
 * @param publicKey - the Ed25519 public KeyObject.
 * @param transcript - the exact bytes that were signed.
 * @param signatureB64 - the base64 signature.
 * @returns true only when the signature is valid.
 */
export function verifyTranscript(publicKey, transcript, signatureB64) {
  try {
    return verify(null, Buffer.from(transcript, 'utf8'), publicKey, Buffer.from(String(signatureB64), 'base64'))
  } catch {
    return false
  }
}

// ── ephemeral ECDH (X25519) ──────────────────────────────────────────────────

/** @returns one fresh X25519 keypair as `{ publicKey, privateKey }`. */
export function generateEphemeral() {
  return generateKeyPairSync('x25519')
}

/**
 * Compute the shared secret with the peer's ephemeral public key.
 * @param privateKey - this side's X25519 private KeyObject.
 * @param peerPublicBase64 - the peer's SPKI DER public key, base64.
 * @returns the 32-byte shared secret.
 * @throws {CryptoFailure} when the peer key does not parse, the exchange fails,
 *   or the peer supplied a low-order point.
 */
export function sharedSecret(privateKey, peerPublicBase64) {
  const peerPublicKey = importPublicKey(peerPublicBase64)
  let secret
  try {
    secret = diffieHellman({ privateKey, publicKey: peerPublicKey })
  } catch (error) {
    throw new CryptoFailure('ecdh-failed', `the key exchange failed: ${String(error?.message ?? error)}`)
  }
  // X25519 yields an all-zero shared secret when the peer supplied a low-order
  // point. Node does not reject that for us, and proceeding would derive a
  // session key the attacker knows. This check is the fix.
  if (secret.length === 0 || secret.every((byte) => byte === 0)) {
    throw new CryptoFailure('ecdh-degenerate', 'the peer sent a degenerate public key (all-zero shared secret)')
  }
  return secret
}

// ── session keys ─────────────────────────────────────────────────────────────

/**
 * Derive the two direction-separated session keys.
 *
 * @param secret - the X25519 shared secret.
 * @param salt - the two nonces, concatenated (guest first, then host).
 * @param inviteId - bound into the key so a session key cannot be replayed onto
 *   a different invite.
 * @returns `{ hostToGuest, guestToHost }` as 32-byte Buffers.
 */
export function deriveSessionKeys(secret, salt, inviteId) {
  const okm = Buffer.from(hkdfSync('sha256', secret, Buffer.from(salt, 'utf8'), `${KEY_INFO}|${inviteId}`, DERIVED_KEY_BYTES))
  return {
    hostToGuest: okm.subarray(0, 32),
    guestToHost: okm.subarray(32, 64),
  }
}

/** @returns the key for one direction. */
export function keyForDirection(keys, direction) {
  if (direction === DIRECTION_HOST_TO_GUEST) return keys.hostToGuest
  if (direction === DIRECTION_GUEST_TO_HOST) return keys.guestToHost
  throw new CryptoFailure('bad-direction', `unknown frame direction ${JSON.stringify(direction)}`)
}

/**
 * The short authentication string both ends display for a human to compare.
 *
 * This is what keeps a TYPED pairing (device code + password, no QR) from being
 * unconditionally at the relay's mercy. Without a pinned fingerprint, a relay that
 * knows the password can sit in the middle and terminate the encryption on both
 * sides — but it then has to run TWO sessions, and each session derives a different
 * key. Deriving the comparison string from the session secret therefore makes the two
 * screens disagree, and a human comparing six digits catches what no amount of
 * cryptography can catch on its own: that the peer is not the peer.
 *
 * Six digits, SSH-style. It is not a substitute for the QR path's pinned fingerprint
 * — comparing it is a HUMAN step, and a user who skips it gets nothing — which is why
 * the QR path stays the recommended one and why the disclaimer says so.
 *
 * @param secret - the session's X25519 shared secret.
 * @param parts - transcript parts to bind (both ephemeral keys, the invite id).
 * @returns six decimal digits, zero-padded.
 */
export function shortAuthString(secret, ...parts) {
  const okm = Buffer.from(hkdfSync('sha256', secret, Buffer.from(parts.join('|'), 'utf8'), 'dsh-native-env/v2 sas', 4))
  const value = okm.readUInt32BE(0) % 1_000_000
  return String(value).padStart(6, '0')
}

/**
 * The additional authenticated data for one frame.
 *
 * Binding the direction AND the sequence number means a frame cannot be
 * replayed, reordered, or reflected onto the other direction without the tag
 * failing: the receiver decrypts with the AAD it EXPECTS, and any other value
 * fails the tag check instead of producing plaintext.
 *
 * @param direction - `h2g` or `g2h`.
 * @param seq - the sender's monotonic sequence number.
 * @param inviteId - the session's invite id.
 * @returns the AAD bytes.
 */
export function frameAad(direction, seq, inviteId) {
  return Buffer.from(`${KEY_INFO}|${direction}|${seq}|${inviteId}`, 'utf8')
}

/**
 * The 12-byte IV for one frame: a per-direction prefix plus the sequence number.
 *
 * Deterministic rather than random because a repeated (key, IV) pair is
 * catastrophic for GCM, and a counter cannot repeat while a random value can.
 *
 * @param ivPrefix - 4 bytes.
 * @param seq - the sequence number.
 * @returns the 12-byte IV.
 */
export function frameIv(ivPrefix, seq) {
  const iv = Buffer.alloc(IV_PREFIX_BYTES + 8)
  Buffer.from(ivPrefix).copy(iv, 0, 0, IV_PREFIX_BYTES)
  iv.writeBigUInt64BE(BigInt(seq), IV_PREFIX_BYTES)
  return iv
}

/**
 * Encrypt one plaintext frame.
 *
 * @param key - the 32-byte key for this direction.
 * @param ivPrefix - 4 bytes, fixed for the session's direction.
 * @param direction - `h2g` or `g2h`.
 * @param seq - the sender's monotonic sequence number, which must never repeat.
 * @param inviteId - the session's invite id.
 * @param plaintext - the frame body (a UTF-8 JSON-RPC line, without its newline).
 * @returns the ciphertext with its 16-byte GCM tag appended.
 */
export function sealFrame(key, ivPrefix, direction, seq, inviteId, plaintext) {
  const cipher = createCipheriv('aes-256-gcm', key, frameIv(ivPrefix, seq))
  cipher.setAAD(frameAad(direction, seq, inviteId))
  const body = Buffer.from(plaintext, 'utf8')
  return Buffer.concat([cipher.update(body), cipher.final(), cipher.getAuthTag()])
}

/**
 * Decrypt one frame.
 *
 * @param key - the 32-byte key for this direction.
 * @param ivPrefix - the SENDER's 4-byte IV prefix for this direction.
 * @param direction - `h2g` or `g2h`.
 * @param seq - the sequence number the sender used; it must match the AAD exactly.
 * @param inviteId - the session's invite id.
 * @param payload - the ciphertext with its tag.
 * @returns the plaintext as a UTF-8 string.
 * @throws {CryptoFailure} when the payload is too short or the tag does not verify.
 */
export function openFrame(key, ivPrefix, direction, seq, inviteId, payload) {
  const bytes = Buffer.isBuffer(payload) ? payload : Buffer.from(payload)
  if (bytes.length <= GCM_TAG_BYTES) {
    throw new CryptoFailure('frame-truncated', 'the encrypted frame is shorter than its authentication tag')
  }
  const tag = bytes.subarray(bytes.length - GCM_TAG_BYTES)
  const body = bytes.subarray(0, bytes.length - GCM_TAG_BYTES)
  const decipher = createDecipheriv('aes-256-gcm', key, frameIv(ivPrefix, seq))
  decipher.setAAD(frameAad(direction, seq, inviteId))
  decipher.setAuthTag(tag)
  try {
    return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8')
  } catch {
    // One message for "wrong key", "wrong sequence" and "tampered": telling a
    // remote peer which of those it managed is an oracle, not a diagnostic.
    throw new CryptoFailure('frame-auth-failed', 'the frame failed authentication (wrong key, wrong sequence, or tampering)')
  }
}

// ── relay rendezvous proof ───────────────────────────────────────────────────

/**
 * HMAC-SHA-256 over a transcript, as lowercase hex.
 *
 * Used ONLY for the relay rendezvous proof, where the verifier (the relay) must
 * recompute the digest from a stored secret and therefore cannot use a signature
 * scheme. Session authentication never uses this: it uses Ed25519 signatures,
 * which need no shared secret and are what survive a compromised relay.
 *
 * @param secret - the invite secret.
 * @param parts - transcript parts, joined with `|`.
 * @returns lowercase hex digest.
 */
export function hmacProof(secret, ...parts) {
  return createHmac('sha256', secret).update(parts.join('|')).digest('hex')
}
