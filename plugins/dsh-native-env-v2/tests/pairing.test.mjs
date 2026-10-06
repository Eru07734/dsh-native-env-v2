/**
 * dsh-native-env / pairing tests — the invite payload.
 *
 * The invite is the one thing that crosses between two machines by hand, so the
 * tests below are mostly about what it must REFUSE. A parser that accepts a
 * near-miss invite produces a confusing failure two steps later, on a machine
 * the operator is not sitting at; a parser that refuses it by name produces a
 * sentence the operator can act on.
 *
 * The single most important assertion here is that the secret stays in the URI
 * fragment and is refused if it appears in the query: that is the difference
 * between a secret that reaches the relay and one that reaches every access log
 * between the two machines.
 *
 * @module dsh-native-env/tests/pairing
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { newInviteId, newPairSecret } from '../lib/e2ee.js'
import {
  DEFAULT_INVITE_TTL_MS,
  InviteError,
  MAX_URI_LENGTH,
  createInvite,
  describeInvite,
  parseInviteUri,
  relayLabel,
  validateInvite,
} from '../lib/pairing.js'

/** A valid invite for tests that only care about one field. */
function makeInvite(overrides = {}) {
  return createInvite({
    relay: 'wss://relay.example.test/v2/relay',
    fingerprint: 'a1b2c3d4e5f60718',
    ...overrides,
  })
}

// ── round trip ───────────────────────────────────────────────────────────────

test('an invite round-trips with every field intact', () => {
  const { uri, invite } = makeInvite()
  const parsed = parseInviteUri(uri)
  assert.equal(parsed.ok, true, parsed.error)
  assert.equal(parsed.invite.relay, 'wss://relay.example.test/v2/relay')
  assert.equal(parsed.invite.inviteId, invite.inviteId)
  assert.equal(parsed.invite.fingerprint, 'a1b2c3d4e5f60718')
  assert.equal(parsed.invite.pairSecret, invite.pairSecret)
  assert.equal(parsed.invite.secure, true)
})

test('the secret is in the fragment and never in the query', () => {
  const { uri, invite } = makeInvite()
  const [beforeHash, afterHash] = uri.split('#')
  assert.equal(afterHash, invite.pairSecret)
  assert.equal(beforeHash.includes(invite.pairSecret), false, 'the secret must not appear before the "#"')
  const query = new URL(uri).searchParams
  assert.equal(query.has('pairSecret'), false)
  assert.equal(query.has('secret'), false)
})

test('an invite is addressed to the pairing scheme only', () => {
  const { uri } = makeInvite()
  assert.match(uri, /^dsh\+env:\/\/pair\?/)
})

test('a ws:// relay is accepted and reported as insecure', () => {
  const { uri } = makeInvite({ relay: 'ws://127.0.0.1:8931/v2/relay' })
  const parsed = parseInviteUri(uri)
  assert.equal(parsed.ok, true, parsed.error)
  assert.equal(parsed.invite.secure, false)
})

// ── refusals, each one by name ───────────────────────────────────────────────

test('a non-invite string is refused as unparseable rather than thrown', () => {
  for (const text of ['', '   ', 'hello', 'https://example.test/', 'dsh+env://other?v=2#x']) {
    const parsed = parseInviteUri(text)
    assert.equal(parsed.ok, false, `${JSON.stringify(text)} should not parse`)
    assert.equal(typeof parsed.code, 'string')
    assert.equal(typeof parsed.error, 'string')
  }
})

test('a secret supplied in the query string is refused by name', () => {
  const secret = newPairSecret()
  const text = `dsh+env://pair?v=2&relay=${encodeURIComponent('wss://r.test/x')}&inviteId=${newInviteId()}&exp=${String(Date.now() + 60000)}&fp=a1b2c3d4e5f60718&pairSecret=${secret}#${secret}`
  const parsed = parseInviteUri(text)
  assert.equal(parsed.ok, false)
  assert.equal(parsed.code, 'secret-in-query')
})

test('a wrong protocol version is refused by name', () => {
  const { uri } = makeInvite()
  const text = uri.replace('v=2', 'v=1')
  const parsed = parseInviteUri(text)
  assert.equal(parsed.ok, false)
  assert.equal(parsed.code, 'version-mismatch')
})

test('an https relay is refused with a usable hint', () => {
  const { invite } = makeInvite()
  const text = `dsh+env://pair?v=2&relay=${encodeURIComponent('https://relay.test/x')}&inviteId=${invite.inviteId}&exp=${String(invite.expiresAt)}&fp=${invite.fingerprint}#${invite.pairSecret}`
  const parsed = parseInviteUri(text)
  assert.equal(parsed.ok, false)
  assert.equal(parsed.code, 'bad-relay')
  assert.match(parsed.error, /use wss:\/\/, not https:\/\//)
})

test('a malformed field is refused rather than defaulted', () => {
  const { invite } = makeInvite()
  const cases = [
    // A slot id is `[0-9a-z]{4,64}`, so the invalid examples have to leave that set:
    // upper case and punctuation are refused, and so is a too-short value.
    ['inviteId', 'NOT-HEX', 'bad-invite-id'],
    ['inviteId', 'ab', 'bad-invite-id'],
    ['fp', 'SHORT', 'bad-fingerprint'],
    ['exp', 'later', 'bad-expiry'],
    ['v', 'two', 'missing-version'],
  ]
  for (const [key, value, code] of cases) {
    const query = new URLSearchParams({
      v: '2',
      relay: 'wss://relay.test/x',
      inviteId: invite.inviteId,
      exp: String(invite.expiresAt),
      fp: invite.fingerprint,
    })
    query.set(key, value)
    const parsed = parseInviteUri(`dsh+env://pair?${query.toString()}#${invite.pairSecret}`)
    assert.equal(parsed.ok, false, `${key}=${value} should not parse`)
    assert.equal(parsed.code, code, `${key}=${value} gave ${parsed.code}`)
  }
})

test('an unknown field is refused instead of ignored', () => {
  const { invite } = makeInvite()
  const text = `dsh+env://pair?v=2&relay=${encodeURIComponent(invite.relay)}&inviteId=${invite.inviteId}&exp=${String(invite.expiresAt)}&fp=${invite.fingerprint}&extra=1#${invite.pairSecret}`
  const parsed = parseInviteUri(text)
  assert.equal(parsed.ok, false)
  assert.equal(parsed.code, 'unknown-field')
})

test('a missing or malformed secret is refused', () => {
  const missing = parseInviteUri('dsh+env://pair?v=2&relay=wss%3A%2F%2Fr.test%2Fx&inviteId=0123456789abcdef0123456789abcdef&exp=9999999999999&fp=a1b2c3d4e5f60718')
  assert.equal(missing.ok, false)
  assert.equal(missing.code, 'missing-secret')
  const short = parseInviteUri(`${'dsh+env://pair?v=2&relay=wss%3A%2F%2Fr.test%2Fx&inviteId=0123456789abcdef0123456789abcdef&exp=9999999999999&fp=a1b2c3d4e5f60718'}#tooshort`)
  assert.equal(short.ok, false)
  assert.equal(short.code, 'bad-secret')
})

test('an over-long invite is refused before parsing anything', () => {
  const parsed = parseInviteUri(`dsh+env://pair?v=2&relay=${'x'.repeat(MAX_URI_LENGTH)}#abc`)
  assert.equal(parsed.ok, false)
  assert.equal(parsed.code, 'invite-too-long')
})

test('createInvite throws a coded error rather than emitting a broken invite', () => {
  assert.throws(() => createInvite({ relay: 'https://r.test/x', fingerprint: 'a1b2c3d4e5f60718' }), InviteError)
  assert.throws(() => createInvite({ relay: 'wss://r.test/x', fingerprint: 'nope' }), /16 lowercase hex/)
  assert.throws(() => createInvite({ relay: 'wss://r.test/x', fingerprint: 'a1b2c3d4e5f60718', inviteId: 'NO!' }), /4 to 64 lower-case/)
  assert.throws(() => createInvite({ relay: 'wss://r.test/x', fingerprint: 'a1b2c3d4e5f60718', inviteId: 'ab' }), /4 to 64 lower-case/)
  assert.throws(() => createInvite({ relay: 'wss://r.test/x', fingerprint: 'a1b2c3d4e5f60718', pairSecret: 'short' }), /43 characters|base64url/)
})

// ── expiry and description ───────────────────────────────────────────────────

test('an expired invite is reported with how long ago it expired', () => {
  const { invite } = makeInvite({ expiresAt: Date.now() - 5000 })
  const verdict = validateInvite(invite, Date.now())
  assert.equal(verdict.ok, false)
  assert.equal(verdict.code, 'expired')
  assert.match(verdict.error, /expired \d+s ago/)
})

test('a fresh invite validates, and an implausible lifetime is refused', () => {
  const { invite } = makeInvite()
  assert.equal(validateInvite(invite, Date.now()).ok, true)
  const far = { ...invite, expiresAt: Date.now() + (48 * 60 * 60 * 1000) }
  const verdict = validateInvite(far, Date.now())
  assert.equal(verdict.ok, false)
  assert.equal(verdict.code, 'implausible-expiry')
})

test('the default lifetime is ten minutes', () => {
  const before = Date.now()
  const { invite } = makeInvite()
  const lifetime = invite.expiresAt - before
  assert.ok(Math.abs(lifetime - DEFAULT_INVITE_TTL_MS) < 5000, `lifetime was ${String(lifetime)}`)
})

test('the loggable description never contains the secret', () => {
  const { invite } = makeInvite()
  const described = describeInvite(invite)
  const serialized = JSON.stringify(described)
  assert.equal(serialized.includes(invite.pairSecret), false, 'the secret must never be loggable')
  assert.equal(described.inviteIdPrefix, invite.inviteId.slice(0, 8))
  assert.equal(described.inviteIdPrefix.length, 8)
  assert.equal(described.fingerprint, invite.fingerprint)
  assert.equal(described.relay, 'relay.example.test')
})

test('a relay label degrades to a placeholder instead of throwing', () => {
  assert.equal(relayLabel('wss://relay.test:8443/v2/relay'), 'relay.test:8443')
  assert.equal(relayLabel('ws://127.0.0.1:8931/v2/relay'), '127.0.0.1:8931')
  assert.equal(relayLabel('not a url'), '(unparseable relay)')
})
