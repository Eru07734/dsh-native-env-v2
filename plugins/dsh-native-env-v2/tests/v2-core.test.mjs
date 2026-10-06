import test from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { V2_METHODS } from '../lib/env-protocol.js'
import { buildHello, validateHello } from '../lib/protocol-v2.js'
import { EnvClient } from '../lib/client.js'
import { LineWire } from '../lib/wire.js'
import { inspectLegacy } from '../lib/migration.js'

class MemoryEndpoint extends EventEmitter {
  constructor() {
    super()
    this.peer = undefined
  }
  write(chunk, callback) {
    if (this.peer === undefined) throw new Error('peer is closed')
    queueMicrotask(() => this.peer.emit('data', Buffer.from(String(chunk))))
    callback?.()
    return true
  }
}

function pair() {
  const a = new MemoryEndpoint()
  const b = new MemoryEndpoint()
  a.peer = b
  b.peer = a
  return [a, b]
}

test('v2 hello metadata validates and preserves capabilities/revision', () => {
  const hello = buildHello({ peer: 'ubuntu', platform: 'linux', cwd: '/home/user', revision: 7 })
  assert.equal(hello.protocol, 2)
  assert.equal(hello.platform, 'linux')
  assert.equal(validateHello(hello).revision, 7)
  assert.throws(() => validateHello({ ...hello, protocol: 1 }), /unsupported protocol/)
})

test('EnvClient negotiates v2 and uses env2 methods', async () => {
  const [hostEndpoint, guestEndpoint] = pair()
  const hostWire = new LineWire(hostEndpoint, hostEndpoint)
  const guestWire = new LineWire(guestEndpoint, guestEndpoint)
  guestWire.onRequest(async (method, params) => {
    if (method === V2_METHODS.hello) return buildHello({ peer: 'ubuntu', platform: 'linux', cwd: '/tmp', revision: 3 })
    if (method === V2_METHODS.list) return { peer: 'ubuntu', platform: 'linux', cwd: '/tmp', revision: 3, tools: [{ name: 'bash', description: 'remote shell', parameters: { type: 'object' } }] }
    if (method === V2_METHODS.call) return { callId: params.callId, name: params.name, isError: false, content: [{ type: 'text', text: 'ok' }] }
    if (method === V2_METHODS.status) return { peer: 'ubuntu', platform: 'linux', cwd: '/tmp', protocol: 2 }
    throw new Error(`method not found: ${method}`)
  })
  guestWire.start()
  const client = new EnvClient({ config: { name: 'ubuntu', transport: 'ssh', maxMessageBytes: 100000, listTimeoutMs: 1000 }, logger: {} })
  client.attach({ wire: hostWire, remoteAddress: 'test' })
  await client.readyPromise
  assert.equal(client.protocolVersion, 2)
  assert.deepEqual(client.tools.map((tool) => tool.name), ['bash'])
  const result = await client.call('bash', { command: 'true' })
  assert.equal(result.content[0].text, 'ok')
  assert.equal((await client.status()).protocolVersion, 2)
  hostWire.close()
  guestWire.close()
})

test('LineWire fail-closes EPIPE without throwing from notify', async () => {
  const input = new EventEmitter()
  const output = { write() { const error = new Error('broken pipe'); error.code = 'EPIPE'; throw error } }
  let disconnected = 0
  const wire = new LineWire(input, output, { onDisconnect: () => { disconnected += 1 } })
  wire.start()
  await assert.rejects(wire.request('env2/status', {}), /disconnected|closed|broken pipe/i)
  assert.equal(wire.notify('env2/tools-changed', {}), false)
  assert.equal(disconnected, 1)
  assert.equal(wire.pendingCount, 0)
})

test('migration discovery is read-only and keeps the old package separate', () => {
  const result = inspectLegacy({ dshHome: 'Z:\\path-that-does-not-exist' })
  assert.equal(result.found, false)
  assert.equal(result.config, null)
})

test('migration scan distinguishes the v2 bundle from a legacy package row', () => {
  const home = mkdtempSync(join(tmpdir(), 'native-env-v2-migration-'))
  const profile = join(home, 'profiles', 'web')
  mkdirSync(profile, { recursive: true })
  writeFileSync(join(profile, 'package.json'), JSON.stringify({ dependencies: { 'dsh-native-env-v2': 'link:../dsh-native-env-v2' } }))
  writeFileSync(join(profile, 'cordis.patch.yml'), '- insert:\n    - id: native-env-v2\n      name: ./lib/host.js\n')
  assert.equal(inspectLegacy({ dshHome: home }).found, false)
  writeFileSync(join(profile, 'package.json'), JSON.stringify({ dependencies: { 'dsh-native-env': 'link:../dsh-native-env' } }))
  assert.equal(inspectLegacy({ dshHome: home }).found, true)
})
