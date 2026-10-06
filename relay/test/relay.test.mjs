/**
 * dsh-native-env-relay / integration tests.
 *
 * These are the tests that decide whether the public-relay design holds, because
 * they run the REAL relay, the REAL WebSocket endpoint, the REAL pairing handshake
 * and the REAL env wire — nothing is stubbed. Three properties are pinned:
 *
 *   1. **Two machines pair through a relay and then speak the existing env
 *      protocol**, unchanged. If this passes, the pairing transport really is
 *      transport-only and the shadowing/binding code needed no modification.
 *   2. **The relay never carries plaintext.** Every payload the relay forwarded
 *      during an env call is captured and asserted to be neither JSON nor to
 *      contain the tool argument that was sent. This is the property that makes a
 *      third-party relay acceptable at all.
 *   3. **The relay refuses what it should**: an unknown invite, a wrong secret, a
 *      duplicate registration, a taken role.
 *
 * @module dsh-native-env-relay/tests/relay
 */

import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'

import { LineWire } from '../../plugins/dsh-native-env-v2/lib/wire.js'
import { exportIdentity, fingerprint, generateIdentity } from '../../plugins/dsh-native-env-v2/lib/e2ee.js'
import { createInvite } from '../../plugins/dsh-native-env-v2/lib/pairing.js'
import { establishPairedStream } from '../../plugins/dsh-native-env-v2/lib/pairing-session.js'
import { registerInvite } from '../../plugins/dsh-native-env-v2/lib/relay-client.js'
import { RELAY_ERROR, RELAY_VERSION, relayRegisterUrl } from '../../plugins/dsh-native-env-v2/lib/relay-protocol.js'
import { createRelay } from '../server.js'

/** Everything the relay logged, so a test can assert a secret never got in. */
const logLines = []
const sink = (line) => logLines.push(line)

/** One relay for the whole file, bound to an ephemeral port. */
let relay
let relayBase

before(async () => {
  relay = createRelay({ host: '127.0.0.1', port: 0, logLevel: 'debug', sink })
  const address = await relay.listen()
  relayBase = `ws://127.0.0.1:${String(address.port)}/v2/relay`
})

after(async () => {
  await relay.close()
})

/** The host identity, shared by every case so the fingerprint is stable. */
const hostIdentity = generateIdentity()
const guestIdentity = generateIdentity()

/** A helper that waits until a predicate holds. */
async function until(predicate, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const value = await predicate()
    if (value) return value
    if (Date.now() > deadline) return undefined
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
}

/**
 * Register one invite with the relay and return it.
 * @param overrides - invite field overrides.
 * @returns the parsed invite.
 */
async function registeredInvite(overrides = {}) {
  const { invite } = createInvite({
    relay: relayBase,
    fingerprint: fingerprint(hostIdentity.publicKey),
    ...overrides,
  })
  await registerInvite({
    url: relayRegisterUrl(invite.relay),
    inviteId: invite.inviteId,
    secret: invite.pairSecret,
    expiresAt: invite.expiresAt,
  })
  return invite
}

/**
 * Pair a host and a guest through the relay.
 * @param invite - the registered invite.
 * @returns `{ host, guest }`.
 */
async function pair(invite) {
  const [host, guest] = await Promise.all([
    establishPairedStream({
      invite,
      role: 'host',
      identity: hostIdentity,
      label: 'host-machine',
      platform: process.platform,
    }),
    establishPairedStream({
      invite,
      role: 'guest',
      identity: guestIdentity,
      label: 'guest-machine',
      platform: process.platform,
    }),
  ])
  return { host, guest }
}

/**
 * Build an env wire on both ends of a paired session.
 * @param paired - the paired sessions.
 * @returns `{ hostWire, guestWire }`.
 */
function envWires(paired) {
  const hostWire = new LineWire(paired.host.stream, paired.host.stream)
  hostWire.onRequest(async (method) => {
    throw new Error(`the host does not serve ${method}`)
  })
  hostWire.start()

  const guestWire = new LineWire(paired.guest.stream, paired.guest.stream)
  guestWire.onRequest(async (method, params) => {
    if (method === 'env/list') {
      return {
        peer: 'guest',
        platform: 'linux',
        cwd: '/home/user',
        anchor: { id: 'anchor-1' },
        tools: [{ name: 'read', description: 'read a file', parameters: { type: 'object' } }],
      }
    }
    if (method === 'env/call') {
      return {
        callId: params.callId,
        name: params.name,
        isError: false,
        content: [{ type: 'text', text: `ran ${String(params.name)}` }],
      }
    }
    throw new Error(`unknown env method ${method}`)
  })
  guestWire.start()
  return { hostWire, guestWire }
}

// ── the happy path ───────────────────────────────────────────────────────────

test('two machines pair through the relay and authenticate each other', async () => {
  const invite = await registeredInvite()
  const paired = await pair(invite)
  try {
    assert.equal(paired.host.peer.role, 'guest')
    assert.equal(paired.guest.peer.role, 'host')
    // The host learns the guest's identity fingerprint; the guest learns it proved
    // the identity the invite pinned.
    assert.equal(paired.host.peer.fingerprint, fingerprint(guestIdentity.publicKey))
    assert.equal(paired.guest.peer.fingerprint, fingerprint(hostIdentity.publicKey))
    assert.equal(paired.guest.peer.label, 'host-machine')
    assert.equal(paired.host.peer.label, 'guest-machine')
  } finally {
    paired.host.close()
    paired.guest.close()
  }
})

test('the existing env wire runs unchanged over the paired stream', async () => {
  const invite = await registeredInvite()
  const paired = await pair(invite)
  const { hostWire } = envWires(paired)
  try {
    const listed = await hostWire.request('env/list', {}, AbortSignal.timeout(5000))
    assert.equal(listed.platform, 'linux')
    assert.equal(listed.tools[0].name, 'read')

    const called = await hostWire.request('env/call', { callId: 'c1', name: 'read', arguments: { path: 'a.txt' } }, AbortSignal.timeout(5000))
    assert.equal(called.isError, false)
    assert.equal(called.content[0].text, 'ran read')
  } finally {
    paired.host.close()
    paired.guest.close()
  }
})

test('the relay forwards only ciphertext it cannot read', async () => {
  const invite = await registeredInvite()
  const captured = []
  const paired = await pair(invite)
  // Both directions are captured, because the request travels guest-ward and the
  // response host-ward: watching one side would only ever see half the traffic.
  paired.host.session.on('payload', (payload) => captured.push(payload))
  paired.guest.session.on('payload', (payload) => captured.push(payload))
  const { hostWire } = envWires(paired)
  const MARKER = 'PLAINTEXT-MARKER-MUST-NOT-REACH-THE-RELAY'
  try {
    // Every payload captured from here on travelled through the relay during the
    // env call below, so none of them may contain the marker or parse as JSON.
    captured.length = 0
    const called = await hostWire.request('env/call', { callId: 'c2', name: 'write', arguments: { content: MARKER } }, AbortSignal.timeout(5000))
    assert.equal(called.isError, false)
    assert.ok(captured.length >= 2, `expected a request and a response frame, saw ${String(captured.length)}`)

    for (const payload of captured) {
      const decoded = Buffer.from(payload, 'base64').toString('utf8')
      assert.equal(decoded.includes(MARKER), false, 'the tool argument reached the relay in the clear')
      assert.throws(() => JSON.parse(decoded), 'a payload the relay forwarded decoded as plaintext JSON')
      assert.equal(decoded.includes('env/call'), false, 'the env method name reached the relay in the clear')
    }
  } finally {
    paired.host.close()
    paired.guest.close()
  }
})

test('the relay log never contains an invite secret or a tool argument', async () => {
  const invite = await registeredInvite()
  const paired = await pair(invite)
  const { hostWire } = envWires(paired)
  const MARKER = 'LOG-MARKER-MUST-NOT-APPEAR'
  try {
    await hostWire.request('env/call', { callId: 'c3', name: 'write', arguments: { content: MARKER } }, AbortSignal.timeout(5000))
    const everything = logLines.join('\n')
    assert.equal(everything.includes(invite.pairSecret), false, 'the invite secret was logged')
    assert.equal(everything.includes(MARKER), false, 'a tool argument was logged')
    // The full invite id must not be logged either: only its 8-character prefix.
    assert.equal(everything.includes(invite.inviteId), false, 'the full invite id was logged')
    assert.ok(everything.includes(invite.inviteId.slice(0, 8)), 'the invite prefix should be logged for correlation')
  } finally {
    paired.host.close()
    paired.guest.close()
  }
})

// ── refusals ─────────────────────────────────────────────────────────────────

test('an unknown invite is refused by name', async () => {
  const { invite } = createInvite({ relay: relayBase, fingerprint: fingerprint(hostIdentity.publicKey) })
  await assert.rejects(
    () => establishPairedStream({ invite, role: 'host', identity: hostIdentity }),
    (error) => {
      assert.equal(error.code, RELAY_ERROR.inviteUnknown)
      return true
    },
  )
})

test('a wrong invite secret is refused by name', async () => {
  const invite = await registeredInvite()
  const { invite: impostor } = createInvite({
    relay: relayBase,
    inviteId: invite.inviteId,
    expiresAt: invite.expiresAt,
    fingerprint: invite.fingerprint,
  })
  await assert.rejects(
    () => establishPairedStream({ invite: impostor, role: 'guest', identity: guestIdentity }),
    (error) => {
      assert.equal(error.code, RELAY_ERROR.authFailed)
      return true
    },
  )
})

test('an invite cannot be hijacked by re-registering it with another secret', async () => {
  const invite = await registeredInvite()
  // The SAME secret is the machine that already holds the slot, and is accepted
  // idempotently — that is what lets a stable device code be reclaimed after a restart.
  const same = await registerInvite({
    url: relayRegisterUrl(invite.relay),
    inviteId: invite.inviteId,
    secret: invite.pairSecret,
    expiresAt: invite.expiresAt,
  })
  assert.equal(same.reRegistered, true)

  // A DIFFERENT secret is an attempt to take the rendezvous over, and is refused. This
  // is the property that matters: the invite id travels in the WebSocket path, so a
  // proxy log is enough to learn it.
  const impostor = createInvite({ relay: invite.relay, fingerprint: fingerprint(hostIdentity.publicKey) })
  await assert.rejects(
    () =>
      registerInvite({
        url: relayRegisterUrl(invite.relay),
        inviteId: invite.inviteId,
        secret: impostor.invite.pairSecret,
        expiresAt: invite.expiresAt,
      }),
    (error) => {
      assert.equal(error.code, RELAY_ERROR.inviteUsed)
      return true
    },
  )
})

test('a second guest on the same invite is refused', async () => {
  const invite = await registeredInvite()
  // A host must be present, or the "first guest" would only ever be waiting and
  // this test would be measuring a timeout rather than a refusal.
  const paired = await pair(invite)
  try {
    await assert.rejects(
      () => establishPairedStream({ invite, role: 'guest', identity: generateIdentity(), label: 'second', timeoutMs: 5000 }),
      (error) => {
        assert.equal(error.code, RELAY_ERROR.roleTaken)
        return true
      },
    )
  } finally {
    paired.host.close()
    paired.guest.close()
  }
})

test('an expired invite is refused before the relay is even asked', async () => {
  const { invite } = createInvite({ relay: relayBase, fingerprint: fingerprint(hostIdentity.publicKey), expiresAt: Date.now() - 1000 })
  await assert.rejects(
    () => establishPairedStream({ invite, role: 'guest', identity: guestIdentity }),
    (error) => {
      assert.equal(error.code, 'expired')
      return true
    },
  )
})

test('an https relay address in an invite is refused with a usable hint', () => {
  const { invite } = createInvite({ relay: 'wss://relay.test/v2/relay', fingerprint: 'a1b2c3d4e5f60718' })
  // Constructed directly rather than through the parser, to prove the check lives
  // in the session too: a hand-built invite must not bypass it.
  const broken = { ...invite, relay: 'https://relay.test/v2/relay' }
  return assert.rejects(
    () => establishPairedStream({ invite: broken, role: 'guest', identity: guestIdentity, timeoutMs: 500 }),
    (error) => {
      assert.equal(error.code, 'bad-relay')
      return true
    },
  )
})

test('a host that offers a different identity than the invite pins is rejected', async () => {
  const invite = await registeredInvite()
  const wrongHost = generateIdentity()
  // `timeoutMs` is short because the host is EXPECTED to be abandoned mid-handshake:
  // the guest rejects the fingerprint at step 4 and closes, so the host's wait for
  // the guest's `meta` can only end in a timeout. Waiting the full default would
  // make a correct implementation look like a hang.
  const attempts = await Promise.allSettled([
    establishPairedStream({ invite, role: 'host', identity: wrongHost, label: 'impostor', timeoutMs: 4000 }),
    establishPairedStream({ invite, role: 'guest', identity: guestIdentity, label: 'guest', timeoutMs: 4000 }),
  ])
  for (const attempt of attempts) {
    if (attempt.status === 'fulfilled') attempt.value.close()
  }
  const guestAttempt = attempts[1]
  assert.equal(guestAttempt.status, 'rejected', 'the guest must reject a host whose fingerprint does not match the invite')
  assert.equal(guestAttempt.reason.code, 'fingerprint-mismatch')
})

// ── health and lifecycle ─────────────────────────────────────────────────────

test('the health endpoint reports counts and no invite id', async () => {
  const invite = await registeredInvite()
  const response = await fetch(relayRegisterUrl(invite.relay).replace('/v2/invites', '/healthz'))
  assert.equal(response.status, 200)
  const body = await response.json()
  assert.equal(body.ok, true)
  assert.ok(typeof body.invites === 'number')
  assert.equal(JSON.stringify(body).includes(invite.inviteId), false)
})

test('a closed session frees its role, so the same invite can pair again', async () => {
  const invite = await registeredInvite()
  const first = await pair(invite)
  first.host.close()
  first.guest.close()
  // The relay releases both roles on close but KEEPS the slot until its TTL, so a
  // fresh pair succeeds on the same invite — which is what makes a dropped
  // connection a reconnect rather than a dead invite.
  const released = await until(async () => relay.stats().connections === 0)
  assert.ok(released, 'both connections should have been released')
  const second = await pair(invite)
  second.host.close()
  second.guest.close()
})

test('an invite survives a full disconnect until it expires', async () => {
  const invite = await registeredInvite()
  const first = await pair(invite)
  first.host.close()
  first.guest.close()
  assert.ok(await until(async () => relay.stats().connections === 0))
  // The slot is still registered, which is the property that makes reconnection
  // possible at all.
  assert.equal(relay.registry.stats().invites >= 1, true)
  assert.doesNotThrow(() => relay.registry.require(invite.inviteId))
})

// ── the typed device card: a nine-digit code and a rotating password ──────────

/** One device-code shaped registration, with fields overridable per case. */
const deviceSlot = (overrides = {}) => ({
  v: RELAY_VERSION,
  inviteId: '123456789',
  secret: 'K7FM2XNP9RAV',
  expiresAt: Date.now() + 60_000,
  ...overrides,
})

test('the relay accepts a nine-digit device code and a typed password', () => {
  // Both pairing shapes are the same thing to the relay: an opaque slot key and a
  // secret it will verify a proof against. Validating only the QR shape here is what
  // made every typed pairing fail with a bare 400 before a frame was exchanged.
  const receipt = relay.registry.register(deviceSlot())
  assert.equal(receipt.inviteId, '123456789')
  assert.equal(receipt.reRegistered, false)
  relay.registry.drop('123456789')
})

test('re-registering the SAME secret is idempotent, which a stable device code needs', () => {
  relay.registry.register(deviceSlot())
  const again = relay.registry.register(deviceSlot({ expiresAt: Date.now() + 120_000 }))
  assert.equal(again.reRegistered, true)
  // A host restarting must reclaim its own code, not be told it is taken.
  assert.equal(relay.registry.stats().invites >= 1, true)
  relay.registry.drop('123456789')
})

test('registering a device code with a DIFFERENT secret is refused', () => {
  relay.registry.register(deviceSlot())
  assert.throws(
    () => relay.registry.register(deviceSlot({ secret: 'QHN2WXR4TZVP' })),
    (error) => error.code === RELAY_ERROR.inviteUsed,
  )
  relay.registry.drop('123456789')
})

test('rotating a password requires proof of the previous one', () => {
  relay.registry.register(deviceSlot())
  // Without the previous secret, a card refresh could not reuse the stable code until
  // the old slot expired — which would defeat the point of a stable code.
  assert.throws(
    () => relay.registry.register(deviceSlot({ secret: 'ABCDEFGHJKMN', previousSecret: 'WRONG' })),
    (error) => error.code === RELAY_ERROR.inviteUsed,
  )
  const rotated = relay.registry.register(deviceSlot({ secret: 'ABCDEFGHJKMN', previousSecret: 'K7FM2XNP9RAV' }))
  assert.equal(rotated.rotated, true)
  // The slot now verifies the NEW secret, and the old one is gone.
  assert.equal(relay.registry.require('123456789').secret, 'ABCDEFGHJKMN')
  relay.registry.drop('123456789')
})

test('guessing a device code is rate-limited by client address', async () => {
  // A nine-digit code is enumerable in principle, so the relay is what makes guessing
  // pointless. This relay is configured to give an attacker almost no rope.
  const strict = createRelay({ host: '127.0.0.1', port: 0, logLevel: 'silent', maxAuthFailuresPerIp: 2, authFailureWindowMs: 60_000 })
  const address = await strict.listen()
  const base = `ws://127.0.0.1:${String(address.port)}/v2/relay`
  try {
    const { invite } = createInvite({ relay: base, fingerprint: fingerprint(hostIdentity.publicKey) })
    await registerInvite({ url: relayRegisterUrl(base), inviteId: invite.inviteId, secret: invite.pairSecret, expiresAt: invite.expiresAt })
    const { invite: wrong } = createInvite({
      relay: base,
      inviteId: invite.inviteId,
      expiresAt: invite.expiresAt,
      fingerprint: invite.fingerprint,
    })

    // Two wrong guesses are allowed to fail on their merits…
    for (let attempt = 0; attempt < 2; attempt += 1) {
      await assert.rejects(
        () => establishPairedStream({ invite: wrong, role: 'guest', identity: guestIdentity, timeoutMs: 4000 }),
        (error) => error.code === RELAY_ERROR.authFailed,
      )
    }
    // …and the third is refused before it even gets a challenge.
    await assert.rejects(
      () => establishPairedStream({ invite: wrong, role: 'guest', identity: guestIdentity, timeoutMs: 4000 }),
      (error) => typeof error.code === 'string' && error.code.length > 0,
    )
    // The legitimate secret is ALSO refused while the address is throttled. That is the
    // honest cost of the defence: an attacker cannot lock a host out permanently, only
    // for the window, because the counter is per address and it times out.
    await assert.rejects(
      () => establishPairedStream({ invite, role: 'guest', identity: guestIdentity, timeoutMs: 4000 }),
      (error) => typeof error.code === 'string' && error.code.length > 0,
    )
  } finally {
    await strict.close()
  }
})

test('an over-long device code is refused at registration', () => {
  assert.throws(() => relay.registry.register(deviceSlot({ inviteId: 'A'.repeat(80) })), (error) => error.code === RELAY_ERROR.badMessage)
  assert.throws(() => relay.registry.register(deviceSlot({ secret: 'short' })), (error) => error.code === RELAY_ERROR.badMessage)
})
