/**
 * dsh-native-env / deployment guard — the guest half's file closure.
 *
 * The two halves are deployed differently and the difference is easy to get
 * wrong: the host half is mounted by absolute path from a directory the operator
 * controls, while the guest half is PUSHED as loose files to another machine. If
 * one file of its transitive import closure is left behind, the guest plugin
 * fails to load on a machine that is far more annoying to debug than this one.
 *
 * This test derives the closure from the source instead of trusting a hand-kept
 * list, then checks that BOTH installers ship exactly that set — and that no
 * host-only module has leaked into the guest's imports.
 *
 * @module dsh-native-env/tests/guest-closure
 */

import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'

const HERE = dirname(fileURLToPath(import.meta.url))
const PLUGIN = resolve(HERE, '..')
const LIB = resolve(HERE, '..', 'lib')
const BIN = resolve(HERE, '..', 'bin')

/** Modules that belong to the HOST half and must never be needed by the guest. */
const HOST_ONLY = [
  'host.js',
  'hub.js',
  'client.js',
  'client-bundle.js',
  'binding.js',
  'netaddr.js',
  'pairing-host.js',
  'qr.js',
  'tool-def.js',
]

/**
 * The guest half's import closure, stated once so every assertion below reads
 * against the same list.
 *
 * It grew from five modules to seventeen when the pairing transport landed and then
 * again when the guest gained its own Web API, and that growth is exactly why this
 * file exists: every one of these has to be pushed to the guest, and a missing one
 * fails as an unresolvable import on a machine the operator is not sitting at.
 *
 * Two entries are worth naming because they are not obvious:
 *
 *   - `host-api.js` is shared by BOTH halves. It is route REGISTRATION, not host
 *     policy: the guest registers the same route set minus everything it cannot do, so
 *     a machine with a screen can be paired by typing two values.
 *   - `handshake.js` stays even though the pairing path authenticates with `e2ee.js`
 *     instead: `guest-transport.js` still supports the legacy tcp dial-in, so the
 *     legacy mutual-HMAC handshake is part of the guest's closure whether or not a
 *     deployment uses it.
 */
const GUEST_CLOSURE = [
  'device-code.js',
  'e2ee-channel.js',
  'e2ee.js',
  'env-protocol.js',
  'guest-transport.js',
  'guest.js',
  'handshake.js',
  'host-api.js',
  'pairing-guest.js',
  'pairing-session.js',
  'pairing.js',
  'protocol-v2.js',
  'relay-client.js',
  'relay-protocol.js',
  'state-store.js',
  'terms.js',
  'wire.js',
  'ws.js',
]

/**
 * Every module specifier one file imports, taken from real import/export
 * statements.
 *
 * Anchored to the start of a line on purpose. A looser `from\s*['"]…` pattern
 * also matches PROSE inside a comment: the sentence `tell "the remote tool
 * failed" from "the env wire broke"` was read as an import of a module named
 * "the env wire broke", and this guard failed on its own documentation.
 *
 * @param source - the file's text.
 * @returns the module specifiers, deduplicated.
 */
function importSpecifiers(source) {
  const found = new Set()
  const patterns = [
    // A statement may continue onto further lines, and this codebase's style puts
    // the closing brace of a multi-line import at COLUMN ZERO:
    //     import {
    //       A,
    //     } from './x.js'
    // so a continuation line is one that is indented OR starts with `}`. That
    // rule still refuses to jump to the next statement, because a new `import`
    // starts at column 0 with a letter.
    /^[ \t]*(?:import|export)\b(?:[^\n]|\n(?=[ \t}]))*?\bfrom[ \t]*['"]([^'"]+)['"]/gm,
    // Side-effect import, which has no `from`.
    /^[ \t]*import[ \t]*['"]([^'"]+)['"]/gm,
  ]
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) found.add(match[1])
  }
  return [...found]
}

/**
 * Every relative module one file imports.
 * @param source - the file's text.
 * @returns the basenames of its `./`-relative imports.
 */
function relativeImports(source) {
  return importSpecifiers(source)
    .filter((specifier) => specifier.startsWith('.'))
    .map((specifier) => specifier.replace(/^\.\//, ''))
}

/**
 * Walk the transitive closure of relative imports from one entry file.
 * @param entry - the entry basename.
 * @returns the sorted closure including the entry.
 */
function closureOf(entry) {
  const seen = new Set()
  const queue = [entry]
  while (queue.length > 0) {
    const name = queue.shift()
    if (seen.has(name)) continue
    seen.add(name)
    const source = readFileSync(join(LIB, name), 'utf8')
    for (const dependency of relativeImports(source)) {
      if (!seen.has(dependency)) queue.push(dependency)
    }
  }
  return [...seen].sort()
}

test('the guest half\'s import closure is exactly the shipped file set', () => {
  const closure = closureOf('guest.js')
  assert.deepEqual(closure, GUEST_CLOSURE)
})

test('no host-only module leaks into the guest half', () => {
  const closure = new Set(closureOf('guest.js'))
  for (const name of HOST_ONLY) {
    assert.equal(closure.has(name), false, `${name} must not be reachable from guest.js`)
  }
})

test('the host half is self-contained too, and does not need the guest entry', () => {
  const closure = new Set(closureOf('host.js'))
  assert.equal(closure.has('guest.js'), false)
  assert.equal(closure.has('pairing-guest.js'), false)
  // The host needs its own transport plumbing plus the shared wire/def helpers, and
  // the pairing machinery it drives.
  for (const name of [
    'hub.js',
    'client.js',
    'binding.js',
    'env-protocol.js',
    'handshake.js',
    'wire.js',
    'tool-def.js',
    'netaddr.js',
    'pairing-host.js',
    'host-api.js',
    'qr.js',
    'state-store.js',
    'terms.js',
  ]) {
    assert.equal(closure.has(name), true, `host.js should reach ${name}`)
  }
})

test('every module in both closures is zero-dependency (node: builtins only)', () => {
  const modules = new Set([...closureOf('guest.js'), ...closureOf('host.js')])
  for (const name of modules) {
    const source = readFileSync(join(LIB, name), 'utf8')
    for (const specifier of importSpecifiers(source)) {
      const bare = !specifier.startsWith('.') && !specifier.startsWith('node:')
      assert.equal(bare, false, `${name} imports the bare specifier "${specifier}"; a plugin mounted by absolute path cannot resolve it`)
    }
  }
})

/** The launcher, which ships next to the installers rather than in `lib/`. */
const LAUNCHER = 'guest-runtime-launcher.mjs'

/** The `lib/` basenames of a checked list, as the closure is expressed. */
function libNames(listed) {
  return listed
    .filter((entry) => entry.replace(/\\/g, '/').startsWith('lib/'))
    .map((entry) => entry.replace(/\\/g, '/').replace(/^lib\//, ''))
    .sort()
}

test('the Windows installer ships exactly the guest closure', () => {
  const source = readFileSync(join(BIN, 'guest-install.ps1'), 'utf8')
  const match = source.match(/\$required\s*=\s*@\(([\s\S]*?)\)/)
  assert.ok(match, 'guest-install.ps1 should declare a $required list')
  const listed = [...match[1].matchAll(/'([^']+)'/g)].map((entry) => entry[1])
  assert.deepEqual(libNames(listed), closureOf('guest.js'))
  // The launcher is not an import of the guest entry, but the deployment is
  // broken without it: `guest-run-standalone.ps1` refuses to start.
  assert.ok(
    listed.some((entry) => entry.replace(/\\/g, '/') === `bin/${LAUNCHER}`),
    'guest-install.ps1 should list the launcher so a push is complete',
  )
})

test('the POSIX installer ships exactly the guest closure', () => {
  const source = readFileSync(join(BIN, 'guest-install.sh'), 'utf8')
  // The list is a multi-line `for name in \` continuation, not a one-line `; do`,
  // so the block is taken up to the terminating `do` and the line continuations and
  // comments are removed before the names are read. Pinning one exact layout would
  // mean a formatting change could break the guard silently.
  const match = source.match(/for name in([\s\S]*?)\bdo\b/)
  assert.ok(match, 'guest-install.sh should declare a file list')
  const listed = match[1]
    .split('\n')
    .map((line) => line.replace(/#.*$/, '').trim())
    .join(' ')
    .split(/\s+/)
    .filter((token) => token.length > 0 && token !== '\\')
    .sort()
  assert.deepEqual(listed, closureOf('guest.js'))
})

test('the standalone runner\'s checked paths exist, in the directory it names', () => {
  // This list is what a live Windows deployment hits FIRST, and it used to join
  // every bare name onto `lib\` — so it demanded `lib\guest-runtime-launcher.mjs`
  // and exited 2 before starting anything on a pristine guest. Paths are now
  // relative to the plugin dir and carry their own directory, so the guard is
  // that each one resolves to a real file.
  const source = readFileSync(join(BIN, 'guest-run-standalone.ps1'), 'utf8')
  const match = source.match(/\$required\s*=\s*@\(([\s\S]*?)\)/)
  assert.ok(match, 'guest-run-standalone.ps1 should declare a $required list')
  const listed = [...match[1].matchAll(/'([^']+)'/g)].map((entry) => entry[1]).sort()
  assert.deepEqual(listed, [...closureOf('guest.js').map((name) => `lib\\${name}`), `bin\\${LAUNCHER}`].sort())
  for (const entry of listed) {
    assert.ok(existsSync(join(PLUGIN, entry)), `${entry} does not exist under the plugin directory`)
  }
})
