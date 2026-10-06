import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { createRelay } from '../lib/embedded-relay.js'
import { EnvClient } from '../lib/client.js'
import { V2_METHODS } from '../lib/env-protocol.js'
import { PairingGuest } from '../lib/pairing-guest.js'
import { PairingHost } from '../lib/pairing-host.js'
import { SecretStore, StateStore } from '../lib/state-store.js'
import { LineWire } from '../lib/wire.js'
import { buildHello } from '../lib/protocol-v2.js'

const quiet = { info() {}, warn() {} }
const tempState = () => new StateStore({ file: join(mkdtempSync(join(tmpdir(), 'dsh-native-env-v2-')), 'state.json'), logger: quiet })
const secrets = () => new SecretStore({ credentials: undefined, namespace: `v2-test-${Math.random()}`, logger: quiet })

test('a long public invite registers through loopback and still produces a QR', async () => {
  const relay = createRelay({ host: '127.0.0.1', port: 0, logLevel: 'silent' })
  const address = await relay.listen()
  const local = `ws://127.0.0.1:${address.port}/v2/relay`
  const advertised = 'wss://long-test-public-host-with-several-words.trycloudflare.com/v2/relay'
  const host = await PairingHost.load({ config: { relayUrls: [advertised], publicRelay: { advertised, local }, requireTerms: false }, logger: quiet, secrets: secrets(), state: tempState(), label: 'loopback-public-host' })
  try {
    const invite = await host.createInvite()
    assert.equal(invite.invite.relay, advertised)
    assert.equal(host.connectionRelayFor(advertised), local)
    assert.equal(host.connectionRelayFor('ws://unrelated/v2/relay'), 'ws://unrelated/v2/relay')
    assert.match(invite.svg, /<svg/)
    assert.equal(relay.stats().invites, 1)
  } finally {
    await host.stop()
    await relay.close()
  }
})

test('two paired DSH halves negotiate v2 and call a remote tool', async () => {
  const relay = createRelay({ host: '127.0.0.1', port: 0, logLevel: 'silent' })
  const address = await relay.listen()
  const relayUrl = `ws://127.0.0.1:${address.port}/v2/relay`
  const host = await PairingHost.load({ config: { relayUrls: [relayUrl], requireTerms: false }, logger: quiet, secrets: secrets(), state: tempState(), label: 'v2-host' })
  const guest = await PairingGuest.load({ config: { autoReconnect: false, requireTerms: false }, logger: quiet, secrets: secrets(), state: tempState(), label: 'v2-guest' })
  let client
  const adopted = new Promise((resolve) => {
    host.once('peer-adopted', ({ peerName, peer, stream }) => {
      client = new EnvClient({ config: { name: peerName, transport: 'relay', label: peer.label, listTimeoutMs: 5000 }, logger: quiet })
      client.attach({ wire: new LineWire(stream, stream), remoteAddress: 'relay:v2-test' })
      resolve()
    })
  })
  guest.on('paired', ({ stream }) => {
    const wire = new LineWire(stream, stream)
    wire.onRequest(async (method, params) => {
      if (method === V2_METHODS.hello) return buildHello({ peer: 'v2-guest', platform: 'linux', cwd: '/tmp', revision: 1 })
      if (method === V2_METHODS.list) return { peer: 'v2-guest', platform: 'linux', cwd: '/tmp', revision: 1, tools: [{ name: 'third_party_echo', description: 'plugin tool', parameters: { type: 'object' } }] }
      if (method === V2_METHODS.call) return { callId: params.callId, name: params.name, isError: false, content: [{ type: 'text', text: 'remote plugin ran' }] }
      if (method === V2_METHODS.status) return { peer: 'v2-guest', protocol: 2 }
      if (method === V2_METHODS.cancel) return { ok: true, callId: params.callId }
      throw new Error(`method not found: ${method}`)
    })
    wire.start()
  })
  try {
    const invite = await host.createInvite()
    await guest.join(invite.uri)
    await adopted
    await client.readyPromise
    assert.equal(client.protocolVersion, 2)
    assert.deepEqual(client.tools.map((tool) => tool.name), ['third_party_echo'])
    const result = await client.call('third_party_echo', { value: 'x' })
    assert.equal(result.content[0].text, 'remote plugin ran')
  } finally {
    await guest.stop()
    await host.stop()
    await relay.close()
  }
})
