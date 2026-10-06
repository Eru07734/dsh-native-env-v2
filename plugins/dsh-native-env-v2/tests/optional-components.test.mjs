import assert from 'node:assert/strict'
import { test } from 'node:test'
import { EventEmitter } from 'node:events'
import { readFileSync } from 'node:fs'
import { SessionBinding } from '../lib/binding.js'
import { startPublicAccess } from '../lib/public.js'
import { startQuickTunnel, platformAsset } from '../lib/quick-tunnel.js'
import { SecretStore } from '../lib/state-store.js'

const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r }); return { promise, resolve } }
const fixture = () => {
  const registered = new Map()
  const calls = []
  const tools = ['read', 'computer_click', 'web_fetch', 'env_exit', 'run_code', 'third_party_echo'].map((name) => ({ name, description: name, parameters: { type: 'object' } }))
  const client = {
    name: 'test-peer', config: { transport: 'relay' }, tools,
    list: async () => ({ tools }),
    call: async (name) => { calls.push(name); return { content: [{ type: 'text', text: 'remote' }] } },
  }
  const agent = { ctx: { tools: { register(definition) {
    registered.set(definition.name, definition)
    return () => { if (registered.get(definition.name) === definition) registered.delete(definition.name) }
  } } } }
  const binding = new SessionBinding({ agent, client, config: { fullAccess: false, exclude: [] } })
  return { binding, registered, calls, client }
}

test('full-access policy expands and retracts session tools while keeping exit local', async () => {
  const { binding, registered, calls } = fixture()
  await binding.install()
  assert.deepEqual([...registered.keys()].sort(), ['read', 'third_party_echo'])
  binding.config.fullAccess = true
  await binding.refresh()
  assert(registered.has('computer_click'))
  assert(!registered.has('env_exit'))
  assert(!registered.has('run_code'))
  await registered.get('computer_click').execute({})
  assert.deepEqual(calls, ['computer_click'])
  binding.config.fullAccess = false
  await binding.refresh()
  assert.deepEqual([...registered.keys()].sort(), ['read', 'third_party_echo'])
  binding.dispose()
})

test('permission removal blocks queued remote calls before an asynchronous refresh completes', async () => {
  const { binding, registered, calls, client } = fixture()
  binding.config.fullAccess = true
  await binding.install()
  const queued = registered.get('computer_click')
  const listed = deferred()
  client.list = () => listed.promise
  binding.config.fullAccess = false
  const refresh = binding.refresh()
  assert(registered.has('read'), 'old remote shadows must survive the pending list')
  await assert.rejects(queued.execute({}), { code: 'REMOTE_POLICY_DENIED' })
  assert.deepEqual(calls, [])
  listed.resolve({ tools: client.tools })
  await refresh
  assert(!registered.has('computer_click'))
  binding.dispose()
})

test('disposing a session during refresh cannot resurrect its tool shadows', async () => {
  const { binding, registered, client } = fixture()
  await binding.install()
  const listed = deferred()
  client.list = () => listed.promise
  const refresh = binding.refresh()
  binding.dispose()
  listed.resolve({ tools: client.tools })
  await refresh
  assert.equal(registered.size, 0)
})

test('the shipped bundle contains four components and both new ones start disabled', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url)))
  const patch = readFileSync(new URL('../cordis.patch.yml', import.meta.url), 'utf8')
  assert.equal((patch.match(/    - id:/g) ?? []).length, 4)
  for (const component of ['public', 'full']) {
    assert(pkg.exports[`./${component}`])
    assert.match(patch, new RegExp(`id: native-env-v2-${component}\\n\\s+name: [^\\n]+\\n\\s+disabled: true`))
  }
})

const controllerFixture = () => {
  const state = {}
  return { state,
    setPublicState: (patch) => Object.assign(state, patch),
    setPublicRelay: (relay, patch) => Object.assign(state, { relay, phase: 'ready' }, patch),
    clearPublicRelay: (patch) => Object.assign(state, { relay: null, enabled: false, phase: 'off' }, patch),
  }
}

test('public startup failure closes the relay and records an error without rejecting activation', async () => {
  const controller = controllerFixture()
  let port
  const handle = startPublicAccess(controller, {}, {
    startQuickTunnel: async (options) => { port = options.port; throw new Error('injected tunnel failure') },
  })
  await handle.ready
  assert.equal(controller.state.phase, 'error')
  assert.equal(controller.state.enabled, true)
  assert.match(controller.state.error, /injected tunnel failure/)
  await assert.rejects(fetch(`http://127.0.0.1:${port}/healthz`))
  await handle.stop()
  assert.equal(controller.state.phase, 'off')
})

test('public off closes a ready tunnel and its real local relay', async () => {
  const controller = controllerFixture()
  const exited = deferred()
  let closed = 0
  let port
  const handle = startPublicAccess(controller, {}, {
    startQuickTunnel: async (options) => {
      port = options.port
      return { url: 'https://test-only.trycloudflare.com', exited: exited.promise, close: async () => { closed++; exited.resolve({ code: 0 }) } }
    },
  })
  await handle.ready
  assert.equal(controller.state.relay, 'wss://test-only.trycloudflare.com/v2/relay')
  assert.equal((await fetch(`http://127.0.0.1:${port}/healthz`)).status, 200)
  await handle.stop()
  assert.equal(closed, 1)
  assert.equal(controller.state.phase, 'off')
  await assert.rejects(fetch(`http://127.0.0.1:${port}/healthz`))
})

test('public off while the tunnel is starting cannot leave a late child process or listener', async () => {
  const controller = controllerFixture()
  const starting = deferred()
  const produced = deferred()
  const exited = deferred()
  let closed = 0
  let port
  const handle = startPublicAccess(controller, {}, { startQuickTunnel: async (options) => {
    port = options.port
    starting.resolve()
    return produced.promise
  } })
  await starting.promise
  const stopped = handle.stop()
  produced.resolve({ url: 'https://late.trycloudflare.com', exited: exited.promise, close: async () => { closed++; exited.resolve({ code: 0 }) } })
  await stopped
  assert(closed >= 1)
  assert.equal(controller.state.phase, 'off')
  assert.equal(controller.state.relay, null)
  await assert.rejects(fetch(`http://127.0.0.1:${port}/healthz`))
})

test('an unexpectedly exited public tunnel retracts its URL and listener', async () => {
  const controller = controllerFixture()
  const exited = deferred()
  let port
  const handle = startPublicAccess(controller, {}, { startQuickTunnel: async (options) => {
    port = options.port
    return { url: 'https://test-only.trycloudflare.com', exited: exited.promise, close: async () => {} }
  } })
  await handle.ready
  exited.resolve({ code: 1 })
  await new Promise((r) => setImmediate(r))
  assert.equal(controller.state.phase, 'error')
  assert.equal(controller.state.relay, null)
  await assert.rejects(fetch(`http://127.0.0.1:${port}/healthz`))
  await handle.stop()
})

function fakeChild() {
  const child = new EventEmitter()
  child.stdout = new EventEmitter()
  child.stderr = new EventEmitter()
  child.killed = false
  child.kill = () => { child.killed = true; queueMicrotask(() => child.emit('close', 0, 'SIGTERM')) }
  return child
}

test('quick tunnel reads fragmented URL output and remains abortable after ready', async () => {
  const child = fakeChild()
  const abort = new AbortController()
  const ready = startQuickTunnel({ port: 3000, signal: abort.signal }, {
    resolveCloudflared: async () => 'fake',
    spawn: (_binary, args, options) => {
      assert.equal(options.windowsHide, true)
      assert(args.includes('http://127.0.0.1:3000'))
      queueMicrotask(() => { child.stderr.emit('data', 'https://test-'); child.stderr.emit('data', 'only.trycloudflare.com |'); child.stderr.emit('data', '\nRegistered tunnel connection') })
      return child
    },
  })
  const tunnel = await ready
  assert.equal(tunnel.url, 'https://test-only.trycloudflare.com')
  abort.abort()
  await tunnel.exited
  assert.equal(child.killed, true)
})

test('an abort while resolving the binary prevents spawning altogether', async () => {
  const binary = deferred()
  const abort = new AbortController()
  let spawns = 0
  const ready = startQuickTunnel({ port: 3000, signal: abort.signal }, {
    resolveCloudflared: () => binary.promise,
    spawn: () => { spawns++; return fakeChild() },
  })
  abort.abort()
  binary.resolve('fake')
  await assert.rejects(ready, /cancelled/)
  assert.equal(spawns, 0)
})

test('quick tunnel timeouts and child errors reject cleanly', async () => {
  const child = fakeChild()
  await assert.rejects(startQuickTunnel({ port: 3000, timeoutMs: 5 }, { resolveCloudflared: async () => 'fake', spawn: () => child }), /did not establish/)
  assert(child.killed)
  const errored = fakeChild()
  await assert.rejects(startQuickTunnel({ port: 3000 }, { resolveCloudflared: async () => 'fake', spawn: () => {
    queueMicrotask(() => errored.emit('error', new Error('EPIPE injected')))
    return errored
  } }), /EPIPE/)
})

test('cloudflared assets match platform packaging and credential keys use the DSH namespace format', () => {
  assert.equal(platformAsset('win32', 'x64'), 'cloudflared-windows-amd64.exe')
  assert.equal(platformAsset('linux', 'arm64'), 'cloudflared-linux-arm64')
  assert.equal(platformAsset('darwin', 'arm64'), 'cloudflared-darwin-arm64.tgz')
  assert.throws(() => platformAsset('plan9', 'x64'), /unsupported/)
  assert.equal(new SecretStore({ namespace: 'native-env-v2' }).keyFor('guest-identity'), 'native-env-v2/guest-identity')
})
