/**
 * dsh-native-env / EnvClient tests — the reconnect and failure semantics.
 *
 * These are the behaviours that decide whether a takeover is safe, and none of
 * them is visible from a successful run:
 *
 *   - **a call on an offline peer THROWS.** The single most dangerous possible
 *     bug in this plugin is a silent fall back to the local tool: the model would
 *     believe it ran a command on the remote machine while it ran here. Every
 *     other assertion in this file is secondary to that one.
 *   - **a dropped and restored connection keeps working**, because the shadow
 *     holds the client, not a wire.
 *   - **`list()` must not fire `onToolsChanged`.** A refresh is driven by
 *     `onToolsChanged` and a refresh calls `list()`, so notifying from the
 *     explicit path would recurse `list → notify → refresh → list` forever.
 *   - **a detached wire rejects calls already in flight** rather than leaving them
 *     pending forever.
 *
 * @module dsh-native-env/tests/client
 */

import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import process from 'node:process'
import { test } from 'node:test'

import { EnvClient, EnvOfflineError } from '../lib/client.js'
import { METHODS } from '../lib/env-protocol.js'
import { LineWire } from '../lib/wire.js'
import { DuplexEnd, until } from './helpers/duplex.mjs'

/** A logger that records nothing, so test output stays readable. */
const quiet = { info: () => {}, warn: () => {} }

/** A client config with retry delays short enough to test. */
const config = (overrides = {}) => ({
  name: 'fixture-peer',
  transport: 'tcp',
  minBackoffMs: 50,
  maxBackoffMs: 200,
  listTimeoutMs: 2000,
  ...overrides,
})

const LIST_PAYLOAD = {
  peer: 'fixture-peer',
  platform: 'linux',
  cwd: '/home/user',
  anchor: { id: 'anchor-1', cwd: '/home/user', preset: null },
  tools: [{ name: 'read', description: 'read', parameters: { type: 'object' } }],
}

/**
 * Stand up a peer on one end of a duplex pair.
 * @param end - the peer-side duplex end.
 * @param options.onCall - overrides the `env/call` answer.
 * @param options.neverAnswerCall - when true, `env/call` is left unanswered.
 * @returns the started peer wire.
 */
function fakePeer(end, options = {}) {
  const wire = new LineWire(end, end)
  wire.onRequest(async (method, params) => {
    if (method === METHODS.list) return LIST_PAYLOAD
    if (method === METHODS.status) return { peer: 'fixture-peer', inflight: 0 }
    if (method === METHODS.cancel) return { ok: true, callId: params?.callId }
    if (method === METHODS.call) {
      if (options.neverAnswerCall === true) return new Promise(() => {})
      if (options.onCall !== undefined) return options.onCall(params)
      return { callId: params?.callId, isError: false, content: [{ type: 'text', text: `ran ${params?.name}` }] }
    }
    throw new Error(`peer does not serve ${method}`)
  })
  wire.start()
  return wire
}

/** Attach a client to a fresh wire over a duplex pair, with a peer behind it. */
function connectedClient(options = {}) {
  const [clientEnd, peerEnd] = DuplexEnd.pair()
  const peer = fakePeer(peerEnd, options)
  const client = new EnvClient({ config: config(options.config), logger: quiet, onToolsChanged: options.onToolsChanged })
  client.attach({ wire: new LineWire(clientEnd, clientEnd), remoteAddress: 'test' })
  return { client, peer, clientEnd }
}

// ── the safety property ──────────────────────────────────────────────────────

test('a call on an offline peer throws instead of falling back to anything', async () => {
  const client = new EnvClient({ config: config(), logger: quiet })
  await assert.rejects(
    () => client.call('read', { file_path: 'x' }),
    (error) => {
      assert.ok(error instanceof EnvOfflineError, `expected EnvOfflineError, got ${error?.name}`)
      assert.equal(error.peer, 'fixture-peer')
      return true
    },
  )
})

test('the offline error carries why the peer went away', async () => {
  const { client } = connectedClient()
  client.detach('socket closed')
  await assert.rejects(
    () => client.call('read', {}),
    (error) => {
      assert.match(error.message, /socket closed/)
      return true
    },
  )
})

test('an already-aborted signal is refused before anything is sent', async () => {
  const { client } = connectedClient()
  const controller = new AbortController()
  controller.abort(new Error('cancelled by the caller'))
  await assert.rejects(() => client.call('read', {}, controller.signal), /cancelled by the caller/)
})

// ── the happy path and reconnection ──────────────────────────────────────────

test('a call round-trips through an attached wire', async () => {
  const { client } = connectedClient()
  const result = await client.call('read', { file_path: 'a.txt' })
  assert.equal(result.isError, false)
  assert.equal(result.content[0].text, 'ran read')
})

test('a dropped and restored connection keeps working', async () => {
  const { client, clientEnd } = connectedClient()
  assert.equal((await client.call('read', {})).isError, false)

  client.detach('simulated drop')
  assert.equal(client.connected, false)
  await assert.rejects(() => client.call('read', {}), EnvOfflineError)

  // A new connection for the same peer: the shadow holds the CLIENT, not a wire,
  // so it must start working again with no re-enter.
  const [nextClientEnd, nextPeerEnd] = DuplexEnd.pair()
  fakePeer(nextPeerEnd)
  client.attach({ wire: new LineWire(nextClientEnd, nextClientEnd), remoteAddress: 'test-2' })

  assert.equal(client.connected, true)
  assert.equal((await client.call('read', {})).isError, false)
  assert.equal(client.attempts, 2)
  assert.equal(clientEnd.destroyed, false)
})

test('detaching rejects a call that is already in flight', async () => {
  const { client } = connectedClient({ neverAnswerCall: true })
  const pending = client.call('read', {})
  // Let the request reach the peer, then pull the connection.
  await new Promise((resolve) => setTimeout(resolve, 20))
  client.detach('connection lost mid-call')
  await assert.rejects(() => pending, /connection lost mid-call/)
})

// ── the tool-list notification ───────────────────────────────────────────────

test('an env/tools-changed notification updates the list and notifies the owner', async () => {
  let notified = 0
  const { client, peer } = connectedClient({ onToolsChanged: () => { notified += 1 } })

  peer.notify(METHODS.toolsChanged, { ...LIST_PAYLOAD, tools: [{ name: 'pwsh' }, { name: 'read' }] })
  const seen = await until(() => client.tools.length === 2)
  assert.ok(seen, 'the notification should have updated the tool list')
  assert.equal(notified, 1)
  assert.equal(client.cwd, '/home/user')
  assert.equal(client.anchor?.id, 'anchor-1')
})

test('list() does NOT notify, which is what breaks the refresh recursion', async () => {
  let notified = 0
  const { client } = connectedClient({ onToolsChanged: () => { notified += 1 } })
  const payload = await client.list()
  assert.equal(payload.tools.length, 1)
  assert.equal(client.tools.length, 1)
  // A refresh is driven by onToolsChanged and a refresh calls list(); notifying
  // here would recurse forever.
  assert.equal(notified, 0)
})

test('status() reports the peer and asks the guest for its own view', async () => {
  const { client } = connectedClient()
  await client.list()
  const status = await client.status()
  assert.equal(status.name, 'fixture-peer')
  assert.equal(status.connected, true)
  assert.deepEqual(status.tools, ['read'])
  assert.equal(status.guest.peer, 'fixture-peer')
})

test('status() on an offline peer still answers, so it can explain the outage', async () => {
  const { client } = connectedClient()
  client.detach('socket closed')
  const status = await client.status()
  assert.equal(status.connected, false)
  assert.equal(status.disconnectReason, 'socket closed')
  assert.equal(status.guest, undefined)
})

// ── the spawned transport ────────────────────────────────────────────────────

test('a spawned peer is respawned after it exits', async () => {
  const client = new EnvClient({
    config: config({ transport: 'ssh', command: process.execPath, args: ['-e', 'setTimeout(() => {}, 60000)'] }),
    logger: quiet,
  })
  try {
    client.start()
    assert.ok(await until(() => client.attempts >= 1), 'the peer should have been spawned')
    assert.equal(client.connected, true)

    // Kill the child the way a crash would.
    client.child.kill()
    assert.ok(
      await until(() => client.attempts >= 2, 5000),
      `the peer should have been respawned (attempts=${client.attempts}, lastError=${client.lastError})`,
    )
  } finally {
    client.stop()
  }
})

test('stop() ends the respawn loop for good', async () => {
  const client = new EnvClient({
    config: config({ transport: 'ssh', command: process.execPath, args: ['-e', 'setTimeout(() => {}, 60000)'] }),
    logger: quiet,
  })
  client.start()
  assert.ok(await until(() => client.attempts >= 1))
  client.stop()
  const settled = client.attempts
  client.child?.kill()
  await new Promise((resolve) => setTimeout(resolve, 400))
  assert.equal(client.attempts, settled, 'no further spawn may happen after stop()')
  assert.equal(client.connected, false)
})
