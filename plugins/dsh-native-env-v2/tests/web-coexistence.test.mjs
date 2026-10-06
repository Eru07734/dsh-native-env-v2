import assert from 'node:assert/strict'
import { test } from 'node:test'
import { EventEmitter } from 'node:events'
import { setImmediate as tick } from 'node:timers/promises'
import { registerHostApi, API_PREFIX, SERVER_API_PREFIX } from '../lib/host-api.js'
import { apply as applyGuest } from '../lib/guest.js'
import { PairingGuest } from '../lib/pairing-guest.js'

function registry() {
  const routes = new Map()
  const connection = { fetch: { register(route) {
    if (routes.has(route.path)) throw new Error(`already registered: ${route.path}`)
    routes.set(route.path, route)
    return () => { if (routes.get(route.path) === route) routes.delete(route.path) }
  } } }
  return { routes, connection, async state(prefix) {
    const route = routes.get(`${prefix}/state`)
    return (await (await route.fetch(new Request(`http://localhost${prefix}/state`))).json()).state
  } }
}
function context(connection, active = true) {
  let disposed = false
  const effects = [], waiting = []
  const ctx = {
    tools: { schemas: () => [] }, agents: {}, on() {},
    get: (name) => name === 'connection' && active ? connection : undefined,
    effect(callback) { assert(!disposed); const dispose = callback(); if (dispose) effects.push(dispose) },
    inject(names, callback) {
      assert(!disposed)
      if (active) callback(ctx)
      else waiting.push(callback)
    },
  }
  return { ctx, activate() { active = true; if (!disposed) for (const callback of waiting.splice(0)) callback(ctx) },
    dispose() { disposed = true; for (const dispose of effects.splice(0).reverse()) dispose() } }
}
function service() {
  return Object.assign(new EventEmitter(), {
    stopped: 0, restored: 0, joined: 0,
    status: () => ({ connected: false, fingerprint: 'fixture', terms: { accepted: false } }),
    termsStatus: () => ({ accepted: false }),
    async stop() { this.stopped++ },
    async restore() { this.restored++; return undefined },
    async join() { this.joined++ },
  })
}

test('controller and server APIs coexist in either registration order and clean up independently', async () => {
  for (const reversed of [false, true]) {
    const r = registry(), c = context(r.connection)
    const definitions = [
      { key: 'controller', prefix: API_PREFIX }, { key: 'server', prefix: SERVER_API_PREFIX },
    ]
    if (reversed) definitions.reverse()
    const disposers = new Map(definitions.map(({ key, prefix }) => [key, registerHostApi({
      ctx: c.ctx, prefix, facade: { state: async () => ({ role: key }) },
    })]))
    assert.equal((await r.state(API_PREFIX)).role, 'controller')
    assert.equal((await r.state(SERVER_API_PREFIX)).role, 'server')
    for (const dispose of disposers.get('server')) dispose()
    assert.equal((await r.state(API_PREFIX)).role, 'controller')
    assert(!r.routes.has(`${SERVER_API_PREFIX}/state`))
    for (const dispose of disposers.get('controller')) dispose()
    assert.equal(r.routes.size, 0)
  }
})

test('a partial route registration failure releases its own routes only', () => {
  const r = registry(), c = context(r.connection)
  const occupied = { path: `${SERVER_API_PREFIX}/terms`, methods: ['GET'], fetch() {} }
  r.connection.fetch.register(occupied)
  assert.throws(() => registerHostApi({ ctx: c.ctx, prefix: SERVER_API_PREFIX, facade: {} }), /already registered/)
  assert.deepEqual([...r.routes.keys()], [occupied.path])
})

test('real guest initialization waits for the Web service and survives enable-disable-enable', async (t) => {
  const r = registry(), controller = context(r.connection)
  registerHostApi({ ctx: controller.ctx, facade: { state: async () => ({ role: 'controller' }) } })
  t.mock.method(PairingGuest, 'load', async () => service())
  for (let i = 0; i < 2; i++) {
    const guest = context(r.connection, false)
    t.after(() => guest.dispose())
    applyGuest(guest.ctx, {})
    await tick()
    assert(!r.routes.has(`${SERVER_API_PREFIX}/state`))
    guest.activate()
    assert.equal((await r.state(SERVER_API_PREFIX)).mode, 'guest')
    assert.equal((await r.state(API_PREFIX)).role, 'controller')
    guest.dispose()
    await tick()
    assert(!r.routes.has(`${SERVER_API_PREFIX}/state`))
    assert.equal((await r.state(API_PREFIX)).role, 'controller')
  }
})

test('disabling during identity loading cannot resurrect server routes or reconnect', async (t) => {
  const r = registry(), guest = context(r.connection), s = service()
  let resolve
  t.mock.method(PairingGuest, 'load', () => new Promise((r) => { resolve = r }))
  applyGuest(guest.ctx, {})
  guest.dispose()
  resolve(s)
  await tick()
  assert.equal(r.routes.size, 0)
  assert.equal(s.restored, 0)
  assert.equal(s.joined, 0)
  assert.equal(s.stopped, 1)
})

test('async initialization failure is handled without an unhandled rejection', async (t) => {
  const r = registry(), guest = context(r.connection), s = service()
  s.restore = async () => { throw new Error('fixture restore failed') }
  t.mock.method(PairingGuest, 'load', async () => s)
  applyGuest(guest.ctx, {})
  await tick()
  assert.equal(s.stopped, 1)
  assert.equal(s.joined, 0)
  guest.dispose()
})

test('a conflicting server route does not escape the asynchronous initializer', async (t) => {
  const r = registry(), guest = context(r.connection)
  r.connection.fetch.register({ path: `${SERVER_API_PREFIX}/state`, methods: ['GET'], fetch() {} })
  t.mock.method(PairingGuest, 'load', async () => service())
  applyGuest(guest.ctx, {})
  await tick()
  assert.equal(r.routes.size, 1)
  guest.dispose()
  assert.equal(r.routes.size, 1)
})
