/**
 * dsh-native-env-v2 / client module tests.
 *
 * The browser half cannot be exercised by Node's test runner the way the host half
 * can — it is a module-loader bundle that expects a DOM. What CAN be pinned, and is
 * worth pinning, is its CONTRACT with the harness:
 *
 *   - it announces itself through `window.__ModuleLoader__.load` under this
 *     package's id, because the loader looks bundles up by that exact name;
 *   - it takes ONLY `react` and `react/jsx-runtime` from the module table — the rule
 *     is that a plain-JavaScript plugin must not reach for
 *     `@deepseek-ai/dsh-client-ui-primitives`, whose contents change without notice
 *     and whose absence of types this plugin cannot check;
 *   - it registers its three surfaces in the slots it declares, with ids of its own
 *     so it ADDS to those slots rather than replacing a shipped entry;
 *   - each component RENDERS in its initial state without throwing. A component that
 *     throws blanks its slot entry with a console error, which is the single most
 *     common way a plugin's UI "does not appear".
 *
 * The React stub below is deliberately minimal: real hooks are not the point, the
 * shape of the render is. Effects are never run, so nothing here touches the network.
 *
 * @module dsh-native-env/tests/client-module
 */

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
// The browser bundle is NOT `lib/client.js`: that name belongs to the host half's
// `EnvClient` module, and the two must stay distinct files. `exports["./client"]` in
// package.json points here, which is what the loader follows.
const CLIENT_PATH = resolve(HERE, '..', 'lib', 'client-bundle.js')

/**
 * Evaluate the client bundle against a stubbed module loader.
 *
 * @returns `{ exports, requires, loadCalls }` where `requires` records every specifier
 *   the bundle asked for and `loadCalls` records its `__ModuleLoader__.load` calls.
 */
function loadClientModule() {
  const source = readFileSync(CLIENT_PATH, 'utf8')
  const requires = []
  const loadCalls = []

  /** The harness module table, with only what a client plugin may use. */
  const table = {
    react: {
      useState: (initial) => [initial, () => {}],
      useEffect: () => {},
      useCallback: (fn) => fn,
      Fragment: 'Fragment',
      createElement: (type, props, ...children) => ({ type, props: { ...props, children } }),
    },
    'react/jsx-runtime': {
      jsx: (type, props) => ({ type, props }),
      jsxs: (type, props) => ({ type, props }),
    },
  }

  const require = (specifier) => {
    requires.push(specifier)
    if (!Object.hasOwn(table, specifier)) throw new Error(`the client half required an unavailable module: ${specifier}`)
    return table[specifier]
  }

  const window = {
    __ModuleLoader__: {
      load: (entry) => {
        loadCalls.push(entry)
      },
    },
  }

  // The bundle is an IIFE-free script: it calls `window.__ModuleLoader__.load` at
  // top level, so evaluating it with a `window` in scope is the whole harness.
  const evaluate = new Function('window', source)
  evaluate(window)

  assert.equal(loadCalls.length, 1, 'the bundle must announce itself exactly once')
  const entry = loadCalls[0]
  assert.equal(entry.id, 'dsh-native-env-v2', 'the loader looks bundles up by package name')
  const exports = entry.factory(require)
  return { exports, requires, loadCalls }
}

test('the bundle announces itself under the package name and requires only react', () => {
  const { requires, exports } = loadClientModule()
  assert.deepEqual([...new Set(requires)].sort(), ['react', 'react/jsx-runtime'])
  assert.equal(typeof exports.apply, 'function')
  assert.deepEqual(exports.inject, ['slots'])
})

test('it registers its three surfaces, each beside the shipped entries', () => {
  const { exports } = loadClientModule()
  /** Every `slots.register` call the bundle makes, with the slot it targets. */
  const registrations = []
  const injections = []
  const ctx = {
    slots: {
      // `inject` is the owner-scoped wrapper the harness requires: the callback's
      // registrations are disposed when the owning declaration collapses, and
      // re-installed when it returns.
      inject: (owner, install) => {
        injections.push(owner)
        install()
      },
      register: (options, component) => {
        registrations.push({ options, component })
      },
    },
  }

  exports.apply(ctx)

  assert.deepEqual(injections.sort(), ['settings.section', 'shell.overlay', 'sidebar.footer.action'])
  const bySlot = new Map(registrations.map((entry) => [entry.options.name, entry]))
  assert.deepEqual([...bySlot.keys()].sort(), ['settings.section', 'shell.overlay', 'sidebar.footer.action'])
  // A fresh id ADDS a cell; reusing a shipped id would replace it.
  assert.equal(bySlot.get('settings.section').options.id, 'native-env-v2')
  assert.equal(bySlot.get('settings.section').options.label, 'DSH Native Env v2')
  assert.equal(bySlot.get('sidebar.footer.action').options.id, 'native-env-v2')
  assert.equal(bySlot.get('shell.overlay').options.id, 'native-env-v2-invite')
  for (const entry of registrations) assert.equal(typeof entry.component, 'function')
})

test('every component renders in its initial state without throwing', () => {
  const { exports } = loadClientModule()
  // The settings page before the first poll has resolved: the "reading the host
  // state" card. A throw here is what blanks a slot entry in a real browser.
  assert.doesNotThrow(() => exports.NativeEnvPage({}))
  // The sidebar pill with no data yet.
  assert.doesNotThrow(() => exports.NativeEnvPill({ wide: true }))
  assert.doesNotThrow(() => exports.NativeEnvPill({ wide: false }))
  // The overlay renders nothing until an invite exists.
  assert.equal(exports.InviteOverlay({}), null)
})

test('the invite store notifies subscribers and clears', () => {
  const { exports } = loadClientModule()
  const seen = []
  const unsubscribe = exports.inviteStore.subscribe((value) => seen.push(value))
  exports.inviteStore.set({ uri: 'dsh+env://pair?v=2#secret', invite: { inviteId: 'a'.repeat(32) } })
  assert.equal(seen.length, 1)
  assert.equal(exports.inviteStore.get().uri, 'dsh+env://pair?v=2#secret')
  exports.inviteStore.set(null)
  assert.equal(seen.length, 2)
  assert.equal(exports.inviteStore.get(), null)
  unsubscribe()
  exports.inviteStore.set({ uri: 'x', invite: {} })
  assert.equal(seen.length, 2, 'an unsubscribed listener must not be called')
  exports.inviteStore.set(null)
})

test('the bundle never reaches for a harness client package', () => {
  const source = readFileSync(CLIENT_PATH, 'utf8')
  for (const forbidden of ['dsh-client-ui-primitives', 'dsh-client-', '@deepseek-ai/']) {
    const inRequire = new RegExp(`require\\(\\s*['"]${forbidden.replace(/[/@]/g, '\\$&')}`)
    assert.equal(inRequire.test(source), false, `the client half must not require ${forbidden}`)
  }
})

test('the bundle fetches only this plugin\'s own API prefix', () => {
  const source = readFileSync(CLIENT_PATH, 'utf8')
  // The host half owns `/api/native-env-v2/v2`; a client that invented its own path
  // would 404 at runtime rather than at build time.
  assert.match(source, /const API = '\/api\/native-env-v2\/v2'/)
  const routeLiterals = [...source.matchAll(/call\(`(\/[^`$]*)/g)].map((match) => match[1])
  for (const route of routeLiterals) {
    assert.ok(route.startsWith('/'), `${route} should be a rooted route`)
    assert.equal(route.includes('api/native-env'), false, `${route} should be relative to the API prefix`)
  }
})
