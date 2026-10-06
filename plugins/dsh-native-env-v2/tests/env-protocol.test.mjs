/**
 * dsh-native-env / env-protocol + handshake tests.
 *
 * Two things are load-bearing here and neither is visible from the outside once
 * the plugin is mounted, so they are pinned directly:
 *
 *   - the CHANNEL tag: this wire must refuse a dial-in meant for the net-bridge,
 *     because the two listeners differ only by port;
 *   - the DENYLIST: it decides which remote tools are never shadowed, and a
 *     silently widened list would move orchestration or attachment-bearing tools
 *     across machines.
 *
 * @module dsh-native-env/tests/env-protocol
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { LineWire } from '../lib/wire.js'
import {
  AUTH_METHOD,
  BRIDGE_VERSION,
  CHANNEL_ENV,
  CHANNEL_RUNTIME,
  HELLO_METHOD,
  authenticateAsPeer,
  hostProof,
  newNonce,
  parseHello,
  peerProof,
  sameProof,
} from '../lib/handshake.js'
import { METHODS, denialReason, parseCallParams, parseCancelParams } from '../lib/env-protocol.js'
import { DuplexEnd } from './helpers/duplex.mjs'

/** A hello frame with every required field, overridable per case. */
const hello = (overrides = {}) => ({ version: BRIDGE_VERSION, peer: 'win10', nonce: newNonce(), ...overrides })

/**
 * Stand up the host half of the handshake on one end of a duplex pair.
 * @param end - the host-side duplex end.
 * @param token - the shared secret this host accepts.
 * @param expectedChannel - the channel this listener serves.
 * @returns the started host wire.
 */
function startHost(end, token, expectedChannel) {
  const wire = new LineWire(end, end)
  let stage = 'hello'
  let clientNonce
  let serverNonce
  let peerName
  wire.onRequest(async (method, params) => {
    if (stage === 'hello') {
      if (method !== HELLO_METHOD) throw new Error(`handshake required (expected ${HELLO_METHOD})`)
      const parsed = parseHello(params, expectedChannel)
      peerName = parsed.peer
      clientNonce = parsed.nonce
      serverNonce = newNonce()
      stage = 'auth'
      return {
        ok: true,
        version: BRIDGE_VERSION,
        nonce: serverNonce,
        hmac: hostProof(token, clientNonce, serverNonce),
        peer: peerName,
        channel: parsed.channel,
      }
    }
    if (method !== AUTH_METHOD) throw new Error(`handshake required (expected ${AUTH_METHOD})`)
    if (!sameProof(params.hmac, peerProof(token, clientNonce, serverNonce))) throw new Error('the peer failed to prove the token')
    stage = 'ready'
    return { ok: true, peer: peerName }
  })
  wire.start()
  return wire
}

// ── channel tagging ──────────────────────────────────────────────────────────

test('parseHello defaults the channel to runtime, so an older net-bridge guest still parses', () => {
  assert.equal(parseHello(hello()).channel, CHANNEL_RUNTIME)
})

test('parseHello accepts the env channel when the listener serves it', () => {
  assert.equal(parseHello(hello({ channel: CHANNEL_ENV }), CHANNEL_ENV).channel, CHANNEL_ENV)
})

test('parseHello refuses a dial-in meant for the other listener', () => {
  assert.throws(
    () => parseHello(hello({ channel: CHANNEL_RUNTIME }), CHANNEL_ENV),
    /this listener serves channel "env" but the peer asked for "runtime"/,
  )
})

test('parseHello refuses an unknown channel', () => {
  assert.throws(() => parseHello(hello({ channel: 'sneaky' })), /hello\.channel must be/)
})

test('parseHello refuses a bad version, peer name, or nonce before any state exists', () => {
  assert.throws(() => parseHello(hello({ version: 99 })), /unsupported protocol version/)
  assert.throws(() => parseHello(hello({ peer: '../etc' })), /hello\.peer must match/)
  assert.throws(() => parseHello(hello({ nonce: 'NOTHEX' })), /hello\.nonce must be/)
})

// ── the exchange itself ──────────────────────────────────────────────────────

test('the handshake round-trips on the env channel', async () => {
  const [peerEnd, hostEnd] = DuplexEnd.pair()
  startHost(hostEnd, 'shared-token', CHANNEL_ENV)
  const peerWire = new LineWire(peerEnd, peerEnd)
  peerWire.start()

  const result = await authenticateAsPeer(peerWire, { token: 'shared-token', peer: 'win10', channel: CHANNEL_ENV, timeoutMs: 2000 })
  assert.equal(result.peer, 'win10')
  assert.equal(result.channel, CHANNEL_ENV)
})

test('the handshake refuses a peer that proves the wrong token', async () => {
  const [peerEnd, hostEnd] = DuplexEnd.pair()
  startHost(hostEnd, 'shared-token', CHANNEL_ENV)
  const peerWire = new LineWire(peerEnd, peerEnd)
  peerWire.start()

  await assert.rejects(
    authenticateAsPeer(peerWire, { token: 'wrong-token', peer: 'win10', channel: CHANNEL_ENV, timeoutMs: 2000 }),
    /host failed to prove the shared token/,
  )
})

test('the handshake refuses a dial-in on the wrong channel end to end', async () => {
  const [peerEnd, hostEnd] = DuplexEnd.pair()
  startHost(hostEnd, 'shared-token', CHANNEL_RUNTIME)
  const peerWire = new LineWire(peerEnd, peerEnd)
  peerWire.start()

  // The refusal names the mismatch rather than a generic "refused the hello":
  // parseHello throws, so the host answers a JSON-RPC error and the dialing side
  // surfaces that message verbatim. That is the behaviour worth pinning — a
  // channel mix-up between two listeners that differ only by port is otherwise
  // an infuriating thing to debug.
  await assert.rejects(
    authenticateAsPeer(peerWire, { token: 'shared-token', peer: 'win10', channel: CHANNEL_ENV, timeoutMs: 2000 }),
    /this listener serves channel "runtime" but the peer asked for "env"/,
  )
})

// ── the denylist ─────────────────────────────────────────────────────────────

test('the denylist blocks orchestration, UI, attachment and egress tools', () => {
  for (const name of ['subagent_net_win10', 'net_peers', 'env_enter', 'workflow', 'ralph', 'todo_write', 'job_output']) {
    assert.ok(denialReason(name) !== undefined, `${name} must be denied`)
  }
  for (const name of ['ask_user_question', 'read_image', 'computer_click', 'web_search', 'present', 'skill', 'run_code']) {
    assert.ok(denialReason(name) !== undefined, `${name} must be denied`)
  }
})

test('the denylist lets the environment tools through', () => {
  for (const name of ['read', 'write', 'edit', 'glob', 'grep', 'pwsh', 'bash', 'read_file', 'list_directory']) {
    assert.equal(denialReason(name), undefined, `${name} must be shadowable`)
  }
})

test('a prefix pattern does not over-match a longer unrelated name', () => {
  // `net_*` must not swallow `network_diag`, which is an ordinary remote tool.
  assert.equal(denialReason('network_diag'), undefined)
  assert.ok(denialReason('net_peers') !== undefined)
})

test('caller-supplied exclusions win and explain themselves', () => {
  assert.equal(denialReason('read', [{ pattern: 'read', reason: 'deployment policy' }]), 'deployment policy')
  assert.equal(denialReason('read'), undefined)
})

test('full access drops the default denylist but preserves local leave controls', () => {
  assert.equal(denialReason('computer_click', [], { fullAccess: true }), undefined)
  assert.equal(denialReason('web_fetch', [], { fullAccess: true }), undefined)
  assert.match(denialReason('env_exit', [], { fullAccess: true }), /exit control/)
  assert.match(denialReason('env_status', [], { fullAccess: true }), /environment status/)
  assert.match(denialReason('run_code', [], { fullAccess: true }), /reserved/)
  assert.equal(denialReason('read', [{ pattern: 'read', reason: 'profile denylist' }], { fullAccess: true }), 'profile denylist')
})

// ── argument validation ──────────────────────────────────────────────────────

test('env/call params are validated', () => {
  assert.deepEqual(parseCallParams({ callId: 'c1', name: 'read', arguments: { path: 'a' } }), {
    callId: 'c1',
    name: 'read',
    arguments: { path: 'a' },
  })
  assert.deepEqual(parseCallParams({ callId: 'c1', name: 'read' }).arguments, {})
  assert.throws(() => parseCallParams({ name: 'read' }), /callId must be/)
  assert.throws(() => parseCallParams({ callId: 'c1' }), /name must be/)
  assert.throws(() => parseCallParams({ callId: 'c1', name: 'read', arguments: [] }), /arguments must be an object/)
})

test('env/cancel params are validated', () => {
  assert.deepEqual(parseCancelParams({ callId: 'c1' }), { callId: 'c1' })
  assert.throws(() => parseCancelParams({}), /callId must be/)
})

test('the method table is frozen and uses the env namespace', () => {
  assert.ok(Object.isFrozen(METHODS))
  for (const value of Object.values(METHODS)) assert.match(value, /^env\//)
})
