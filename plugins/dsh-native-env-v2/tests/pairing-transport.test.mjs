/**
 * dsh-native-env / pairing transport tests — the integration the revision exists
 * for: two machines that share NOTHING but a relay URL and a scanned token.
 *
 * These run the real `PairingHost`, the real `PairingGuest`, the real relay and the
 * real `EnvClient`, and they assert the three things that would make the feature
 * useless if wrong:
 *
 *   1. **A peer appears with no configuration.** No `peers`, no address, no port,
 *      no token file — the host learns about the machine only when it authenticates.
 *   2. **The existing env protocol runs over it unchanged**, through `EnvClient`,
 *      which is the same object the tcp and ssh transports use.
 *   3. **A dropped pairing connection THROWS rather than running locally.** This is
 *      the plugin's cardinal safety property, and it has to survive a new transport.
 *
 * @module dsh-native-env/tests/pairing-transport
 */

import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, test } from 'node:test'

import { createRelay } from '../../../relay/server.js'
import { EnvClient, EnvOfflineError } from '../lib/client.js'
import { PairingGuest } from '../lib/pairing-guest.js'
import { PairingHost } from '../lib/pairing-host.js'
import { SecretStore, StateStore } from '../lib/state-store.js'
import { LineWire } from '../lib/wire.js'

/** A logger that records nothing, so test output stays readable. */
const quiet = { info: () => {}, warn: () => {} }

/** One relay for the whole file, bound to an ephemeral port. */
let relay
let relayBase

before(async () => {
  relay = createRelay({ host: '127.0.0.1', port: 0, logLevel: 'silent' })
  const address = await relay.listen()
  relayBase = `ws://127.0.0.1:${String(address.port)}/v2/relay`
})

after(async () => {
  await relay.close()
})

/** Wait until a predicate holds or the budget runs out. */
async function until(predicate, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const value = await predicate()
    if (value) return value
    if (Date.now() > deadline) return undefined
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
}

/** A fresh secret store with no credential service: identity is per-process. */
function ephemeralSecrets() {
  return new SecretStore({ credentials: undefined, namespace: `test-${String(Math.random())}`, logger: quiet })
}

/** A fresh state store in its own temporary directory. */
function tempState() {
  return new StateStore({ file: join(mkdtempSync(join(tmpdir(), 'native-env-')), 'state.json'), logger: quiet })
}

/**
 * The guest's env handler, standing in for the anchor agent's tool surface.
 * @param calls - collects the calls that arrived, so a test can prove they crossed.
 */
function guestHandler(calls) {
  return async (method, params) => {
    calls.push({ method, params })
    if (method === 'env/list') {
      return {
        peer: 'guest',
        platform: 'linux',
        cwd: '/home/guest',
        anchor: { id: 'anchor-1', cwd: '/home/guest', preset: null },
        tools: [
          { name: 'read', description: 'read a file', parameters: { type: 'object' } },
          { name: 'pwsh', description: 'run a shell', parameters: { type: 'object' } },
        ],
      }
    }
    if (method === 'env/status') return { peer: 'guest', inflight: 0 }
    if (method === 'env/call') {
      return { callId: params.callId, name: params.name, isError: false, content: [{ type: 'text', text: `ran ${String(params.name)} on the guest` }] }
    }
    throw new Error(`the guest does not serve ${method}`)
  }
}

/**
 * Stand up a host and a guest, pair them, and return both sides plus the adopted
 * client — the same wiring `host.js` performs, so the test exercises the real path.
 *
 * @param options.requireTerms - whether the host demands the disclaimer.
 * @returns `{ host, guest, client, guestCalls, close }`.
 */
async function pairBoth(options = {}) {
  const host = await PairingHost.load({
    config: { relayUrls: [relayBase], inviteTtlMs: 60_000, requireTerms: options.requireTerms === true },
    logger: quiet,
    secrets: ephemeralSecrets(),
    state: tempState(),
    label: 'test-host',
  })

  const guestCalls = []
  const guest = await PairingGuest.load({
    config: { autoReconnect: false, requireTerms: false, acceptTimeoutMs: 10_000 },
    logger: quiet,
    secrets: ephemeralSecrets(),
    state: tempState(),
    label: 'test-guest',
  })

  /** The host's adopted client, built the way `host.js` builds it. */
  let client
  const adopted = new Promise((resolve) => {
    host.once('peer-adopted', ({ peerName, peer, stream }) => {
      client = new EnvClient({
        config: { name: peerName, transport: 'relay', label: peer.label, minBackoffMs: 1000, maxBackoffMs: 30_000, listTimeoutMs: 10_000 },
        logger: quiet,
      })
      client.attach({ wire: new LineWire(stream, stream), remoteAddress: 'relay:test' })
      resolve(client)
    })
  })

  guest.on('paired', ({ stream }) => {
    const wire = new LineWire(stream, stream)
    wire.onRequest(guestHandler(guestCalls))
    wire.start()
  })

  const created = await host.createInvite()
  await guest.join(created.uri)
  const clientOut = await Promise.race([
    adopted,
    new Promise((_resolve, reject) => setTimeout(() => reject(new Error('the host never adopted a peer')), 10_000)),
  ])

  return {
    host,
    guest,
    client: clientOut,
    guestCalls,
    close: async () => {
      await guest.stop()
      await host.stop()
    },
  }
}

// ── the happy path ───────────────────────────────────────────────────────────

test('a peer appears with no configured address, port or token', async () => {
  const paired = await pairBoth()
  try {
    assert.ok(paired.client, 'the host must adopt a client for the arrived guest')
    assert.match(paired.client.name, /^guest-[0-9a-f]{8}$/)
    assert.equal(paired.client.connected, true)
    // The name is derived from the guest IDENTITY, not from the invite, which is
    // what lets the same machine reconnect onto the same peer.
    assert.equal(paired.client.name, `guest-${paired.guest.fingerprint.slice(0, 8)}`)
  } finally {
    await paired.close()
  }
})

test('the env protocol runs over the pairing transport unchanged', async () => {
  const paired = await pairBoth()
  try {
    const listed = await paired.client.list()
    assert.equal(listed.platform, 'linux')
    assert.equal(listed.cwd, '/home/guest')
    assert.deepEqual(listed.tools.map((tool) => tool.name).sort(), ['pwsh', 'read'])

    const called = await paired.client.call('read', { path: '/etc/os-release' })
    assert.equal(called.isError, false)
    assert.match(called.content[0].text, /ran read on the guest/)
    assert.ok(paired.guestCalls.some((entry) => entry.method === 'env/call'))
  } finally {
    await paired.close()
  }
})

test('the host reports the peer the way env_status needs', async () => {
  const paired = await pairBoth()
  try {
    await paired.client.list()
    const status = await paired.client.status()
    assert.equal(status.connected, true)
    assert.equal(status.platform, 'linux')
    assert.equal(status.transport, 'relay')
    assert.deepEqual(status.tools, ['read', 'pwsh'])
  } finally {
    await paired.close()
  }
})

test('an invite carries this host fingerprint, and the guest records the host it proved', async () => {
  const paired = await pairBoth()
  try {
    const invites = paired.host.invites()
    assert.equal(invites.length, 1)
    assert.equal(invites[0].fingerprint, paired.host.fingerprint)
    assert.equal(invites[0].secure, false, 'a ws:// test relay must be reported as insecure')
    // The guest authenticated the host by the pinned fingerprint, so the peer it
    // recorded is that exact host.
    assert.equal(paired.guest.status().peer.fingerprint, paired.host.fingerprint)
  } finally {
    await paired.close()
  }
})

// ── the safety property ──────────────────────────────────────────────────────

test('a call after the pairing connection drops throws instead of running locally', async () => {
  const paired = await pairBoth()
  try {
    assert.equal((await paired.client.call('read', {})).isError, false)
    // Drop the connection the way a network failure would. This is the plugin's
    // cardinal safety property, and it has to hold for the pairing transport too:
    // a silent fall back to the local tool would run the command on the wrong
    // machine, which is the one failure a takeover must not have.
    paired.client.detach('simulated pairing drop')
    await assert.rejects(
      () => paired.client.call('read', {}),
      (error) => {
        assert.ok(error instanceof EnvOfflineError, `expected an offline error, got ${error?.name}: ${error?.message}`)
        assert.equal(error.peer, paired.client.name)
        return true
      },
    )
  } finally {
    await paired.close()
  }
})

// ── refusals ─────────────────────────────────────────────────────────────────

test('the disclaimer gate blocks invite creation until it is accepted', async () => {
  const host = await PairingHost.load({
    config: { relayUrls: [relayBase], inviteTtlMs: 60_000, requireTerms: true },
    logger: quiet,
    secrets: ephemeralSecrets(),
    state: tempState(),
    label: 'gated-host',
  })
  try {
    await assert.rejects(() => host.createInvite(), /disclaimer must be accepted/)
    host.acceptTerms('host')
    const created = await host.createInvite()
    assert.match(created.uri, /^dsh\+env:\/\/pair\?/)
  } finally {
    await host.stop()
  }
})

test('with no relay configured, invite creation fails clearly instead of guessing', async () => {
  const host = await PairingHost.load({
    config: { relayUrls: [], requireTerms: false },
    logger: quiet,
    secrets: ephemeralSecrets(),
    state: tempState(),
    label: 'relayless-host',
  })
  try {
    await assert.rejects(() => host.createInvite(), /no relay is configured/)
  } finally {
    await host.stop()
  }
})

test('a guest refuses a garbage token without contacting anything', async () => {
  const guest = await PairingGuest.load({
    config: { autoReconnect: false, requireTerms: false },
    logger: quiet,
    secrets: ephemeralSecrets(),
    state: tempState(),
  })
  await assert.rejects(
    () => guest.join('not an invite'),
    (error) => {
      assert.equal(error.code, 'unparseable')
      return true
    },
  )
})

test('revoking an invite stops the accept loop', async () => {
  const host = await PairingHost.load({
    config: { relayUrls: [relayBase], inviteTtlMs: 60_000, requireTerms: false },
    logger: quiet,
    secrets: ephemeralSecrets(),
    state: tempState(),
    label: 'revoking-host',
  })
  try {
    const created = await host.createInvite()
    assert.equal(host.invites().length, 1)
    assert.equal(host.revoke(created.status.inviteIdPrefix), 1)
    assert.equal(host.invites().length, 0)
  } finally {
    await host.stop()
  }
})

test('the host identity is stable across a reload when the credential store persists it', async () => {
  // A real credential service stand-in: one Map shared by two loads.
  const records = new Map()
  const credentials = {
    async readRecord(key) {
      return records.get(key)
    },
    async modifyRecord(key, mutate) {
      const next = await mutate(records.get(key))
      if (next !== undefined) records.set(key, next)
      return next
    },
    async deleteRecord(key) {
      records.delete(key)
    },
  }
  const secrets = new SecretStore({ credentials, namespace: 'stable-test', logger: quiet })
  const base = { config: { relayUrls: [relayBase], requireTerms: false }, logger: quiet, secrets, state: tempState(), label: 'stable-host' }
  const first = await PairingHost.load(base)
  const second = await PairingHost.load(base)
  // The fingerprint is what every issued invite pins, so a reload MUST keep it.
  assert.equal(second.fingerprint, first.fingerprint)
  await first.stop()
  await second.stop()
})

test('the guest remembers and resumes an invite across a reload', async () => {
  const records = new Map()
  const credentials = {
    async readRecord(key) {
      return records.get(key)
    },
    async modifyRecord(key, mutate) {
      const next = await mutate(records.get(key))
      if (next !== undefined) records.set(key, next)
      return next
    },
    async deleteRecord(key) {
      records.delete(key)
    },
  }
  const host = await PairingHost.load({
    config: { relayUrls: [relayBase], inviteTtlMs: 60_000, requireTerms: false },
    logger: quiet,
    secrets: ephemeralSecrets(),
    state: tempState(),
    label: 'resume-host',
  })
  try {
    const created = await host.createInvite()
    const guestSecrets = new SecretStore({ credentials, namespace: 'resume-guest', logger: quiet })
    const guestOptions = {
      config: { autoReconnect: false, requireTerms: false, acceptTimeoutMs: 10_000 },
      logger: quiet,
      secrets: guestSecrets,
      state: tempState(),
    }
    const first = await PairingGuest.load(guestOptions)
    await first.join(created.uri)
    await first.stop()

    // A restarted guest process: same credentials, no invite in its config.
    const second = await PairingGuest.load(guestOptions)
    const restored = await second.restore()
    assert.notEqual(restored, undefined, 'the invite should have been remembered')
    assert.equal(restored.inviteId, created.status.inviteId)
    await second.stop()
  } finally {
    await host.stop()
  }
})

test('the guest status projection never contains the invite secret', async () => {
  const paired = await pairBoth()
  try {
    await paired.client.list()
    const status = paired.guest.status()
    const serialized = JSON.stringify(status)
    // The status document goes to logs, to `env_status` and to the Web API, so the
    // secret must not survive the projection that builds it. (The URI itself is a
    // separate, deliberate exception: only the owner's own UI receives it.)
    assert.equal(serialized.includes(paired.guest.invite.pairSecret), false, 'the invite secret leaked into the status document')
    assert.equal(serialized.includes('pairSecret'), false)
    assert.equal(status.connected, true)
    assert.equal(status.invite.inviteIdPrefix.length, 8)
  } finally {
    await paired.close()
  }
})

// ── the typed device card: code + password, no QR, no fingerprint ────────────

/**
 * Pair by typing a device code and a password, the way the remote-desktop flow works.
 *
 * @returns `{ host, guest, client, guestCalls, hostPeer, close }`.
 */
async function pairByDeviceCard() {
  const host = await PairingHost.load({
    config: { relayUrls: [relayBase], inviteTtlMs: 60_000, requireTerms: false },
    logger: quiet,
    secrets: ephemeralSecrets(),
    state: tempState(),
    label: 'card-host',
  })
  const guestCalls = []
  const guest = await PairingGuest.load({
    // The relay is CONFIGURED on this machine, not typed: a nine-digit code cannot
    // name one. That is the same model as any remote-desktop client.
    config: { relayUrls: [relayBase], autoReconnect: false, requireTerms: false, acceptTimeoutMs: 10_000 },
    logger: quiet,
    secrets: ephemeralSecrets(),
    state: tempState(),
    label: 'card-guest',
  })

  let client
  let hostPeer
  const adopted = new Promise((resolve) => {
    host.once('peer-adopted', ({ peerName, peer, stream }) => {
      hostPeer = peer
      client = new EnvClient({
        config: { name: peerName, transport: 'relay', label: peer.label, minBackoffMs: 1000, maxBackoffMs: 30_000, listTimeoutMs: 10_000 },
        logger: quiet,
      })
      client.pairingSas = peer.sas
      client.pairingPinned = peer.pinned === true
      client.attach({ wire: new LineWire(stream, stream), remoteAddress: 'relay:test' })
      resolve(client)
    })
  })
  guest.on('paired', ({ stream }) => {
    const wire = new LineWire(stream, stream)
    wire.onRequest(guestHandler(guestCalls))
    wire.start()
  })

  const created = await host.createDeviceCard()
  await guest.joinWithCode({ deviceCode: created.card.deviceCode, password: created.card.password })
  const clientOut = await Promise.race([
    adopted,
    new Promise((_resolve, reject) => setTimeout(() => reject(new Error('the host never adopted the typed peer')), 10_000)),
  ])

  return {
    host,
    guest,
    client: clientOut,
    guestCalls,
    created,
    hostPeer,
    close: async () => {
      await guest.stop()
      await host.stop()
    },
  }
}

test('a typed device card pairs two machines and carries the env protocol', async () => {
  const paired = await pairByDeviceCard()
  try {
    // The card a human reads off the screen: grouped for display, raw underneath.
    assert.match(paired.created.card.displayCode, /^\d{3} \d{3} \d{3}$/)
    assert.match(paired.created.card.displayPassword, /^[2-9A-Z]{4}-[2-9A-Z]{4}-[2-9A-Z]{4}$/)
    assert.equal(paired.created.status.mode, 'code')
    assert.equal(paired.created.status.deviceCode, paired.created.card.deviceCode)

    const listed = await paired.client.list()
    assert.deepEqual(listed.tools.map((tool) => tool.name).sort(), ['pwsh', 'read'])
    const called = await paired.client.call('read', { path: '/etc/os-release' })
    assert.match(called.content[0].text, /ran read on the guest/)
  } finally {
    await paired.close()
  }
})

test('a typed pairing reports that it could NOT pin the host, and both sides show one short code', async () => {
  const paired = await pairByDeviceCard()
  try {
    // The honest part: this mode cannot pin the host's identity, and the peer record
    // says so rather than implying a guarantee it does not provide.
    assert.equal(paired.hostPeer.pinned, false)
    assert.equal(paired.guest.status().pinned, false)
    // The short code is the check that replaces the pin, and the two ends must agree
    // on it — a relay in the middle derives two different secrets and therefore two
    // different codes, which is exactly what the human comparison catches.
    assert.match(paired.hostPeer.sas, /^\d{6}$/)
    assert.equal(paired.guest.status().sas, paired.hostPeer.sas)
  } finally {
    await paired.close()
  }
})

test('a QR invite still pins the host, and still shows a matching short code', async () => {
  const paired = await pairBoth()
  try {
    const peerAdopted = await until(async () => paired.host.invites().length > 0)
    assert.ok(peerAdopted)
    assert.equal(paired.guest.status().pinned, true, 'a QR invite must still pin the host identity')
    assert.match(paired.guest.status().sas, /^\d{6}$/)
  } finally {
    await paired.close()
  }
})

test('refreshing a device card keeps the code and replaces the password', async () => {
  const host = await PairingHost.load({
    config: { relayUrls: [relayBase], inviteTtlMs: 60_000, requireTerms: false },
    logger: quiet,
    secrets: ephemeralSecrets(),
    state: tempState(),
    label: 'rotate-host',
  })
  try {
    const first = await host.createDeviceCard()
    const second = await host.createDeviceCard({ refresh: true })
    // The code is an ADDRESS and must not move; the password is the credential and must.
    assert.equal(second.card.deviceCode, first.card.deviceCode, 'a refresh must keep the device code stable')
    assert.notEqual(second.card.password, first.card.password, 'a refresh must mint a new password')

    // `joinWithCode` does NOT reject when the connection fails: it starts the reconnect
    // loop and reports through events and status. So the assertion is on the FAILURE,
    // not on a rejected promise — an earlier version of this test asserted a rejection
    // and would have passed even if the old password still worked.
    const stale = await PairingGuest.load({
      config: { relayUrls: [relayBase], autoReconnect: false, requireTerms: false, acceptTimeoutMs: 5000 },
      logger: quiet,
      secrets: ephemeralSecrets(),
      state: tempState(),
    })
    try {
      const failure = new Promise((resolve) => stale.once('failed', resolve))
      await stale.joinWithCode({ deviceCode: first.card.deviceCode, password: first.card.password })
      const reported = await Promise.race([
        failure,
        new Promise((resolve) => setTimeout(() => resolve(undefined), 8000)),
      ])
      assert.notEqual(reported, undefined, 'the old password must be refused by the relay')
      assert.match(String(reported.message), /proof|secret|verify/i)
      assert.equal(stale.status().connected, false)
    } finally {
      await stale.stop()
    }

    // And the new one still pairs.
    const fresh = await PairingGuest.load({
      config: { relayUrls: [relayBase], autoReconnect: false, requireTerms: false, acceptTimeoutMs: 10_000 },
      logger: quiet,
      secrets: ephemeralSecrets(),
      state: tempState(),
    })
    try {
      const pairedEvent = new Promise((resolve) => fresh.once('paired', resolve))
      await fresh.joinWithCode({ deviceCode: second.card.deviceCode, password: second.card.password })
      const event = await Promise.race([
        pairedEvent,
        new Promise((resolve) => setTimeout(() => resolve(undefined), 10_000)),
      ])
      assert.notEqual(event, undefined, 'the refreshed password must pair')
      assert.match(event.peer.sas, /^\d{6}$/)
    } finally {
      await fresh.stop()
    }
  } finally {
    await host.stop()
  }
})

test('a typed join on a machine with no relay configured fails with a usable reason', async () => {
  const guest = await PairingGuest.load({
    config: { autoReconnect: false, requireTerms: false },
    logger: quiet,
    secrets: ephemeralSecrets(),
    state: tempState(),
  })
  await assert.rejects(
    () => guest.joinWithCode({ deviceCode: '123456789', password: 'K7FM2XNP9RAV' }),
    (error) => {
      assert.equal(error.code, 'no-relay')
      assert.match(error.message, /cannot name a relay/)
      return true
    },
  )
})

test('a typed join refuses a mistyped code or password before contacting anything', async () => {
  const guest = await PairingGuest.load({
    config: { relayUrls: [relayBase], autoReconnect: false, requireTerms: false },
    logger: quiet,
    secrets: ephemeralSecrets(),
    state: tempState(),
  })
  await assert.rejects(
    () => guest.joinWithCode({ deviceCode: '12345', password: 'K7FM2XNP9RAV' }),
    (error) => error.code === 'bad-device-code',
  )
  await assert.rejects(
    () => guest.joinWithCode({ deviceCode: '123456789', password: 'nope' }),
    (error) => error.code === 'bad-password',
  )
})
