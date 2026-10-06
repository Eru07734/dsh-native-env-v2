#!/usr/bin/env node
/**
 * dsh-native-env / guest-runtime-launcher — start a guest DSH runtime and keep it
 * alive, detached from whoever asked for it.
 *
 * Three problems this solves, all of them found by deploying to a real VM:
 *
 *  1. **The runtime must be started through the `dsh` shim, not as
 *     `node …/bin.js`.** On the Windows guest, `node bin.js --profile sdk` — the
 *     very profile the keeper runs happily — exits immediately with code 0 and no
 *     output at all, while `dsh --profile sdk` (the shim, via `shell: true`) stays
 *     up. That was measured directly on the guest, with the guest's own `sdk`
 *     profile as the control, so it is a launch-method difference and not a
 *     profile defect. This launcher therefore uses the shim, exactly as
 *     `dsh-net-bridge`'s guestkeeper does.
 *
 *  2. **`dsh` binds its lifetime to stdin EOF.** A runtime started detached has no
 *     stdin, sees EOF, and shuts down. This launcher owns the child's stdin pipe
 *     and never closes it.
 *
 *  3. **A failed connect must not end the process.** The guest routinely starts
 *     before the host's listener is up; the retry loop in `guest-transport.js`
 *     keeps itself alive, and this launcher anchors the process regardless.
 *
 * Usage:
 *   node guest-runtime-launcher.mjs <profile> <logPath> <pidPath>
 *
 * @module dsh-native-env/guest-runtime-launcher
 */

import { spawn } from 'node:child_process'
import { appendFileSync, writeFileSync } from 'node:fs'
import process from 'node:process'

const [profile, logPath, pidPath] = process.argv.slice(2)

if (profile === undefined) {
  process.stderr.write('usage: guest-runtime-launcher.mjs <profile> <logPath> <pidPath>\n')
  process.exit(2)
}

const append = (text) => {
  if (logPath === undefined) return
  try {
    appendFileSync(logPath, text)
  } catch {
    /* the log is best effort */
  }
}

append(`\n[launcher] starting profile "${profile}" via the dsh shim at ${new Date().toISOString()}\n`)

const child = spawn('dsh', ['--profile', profile], {
  // `shell: true` is load-bearing, not incidental: see (1) above. The shim is
  // what makes the runtime stay up on the guest.
  shell: true,
  windowsHide: true,
  // stdin is a pipe this process owns and never closes: that is (2).
  stdio: ['pipe', 'pipe', 'pipe'],
})

if (pidPath !== undefined) {
  try {
    writeFileSync(pidPath, String(child.pid))
  } catch (error) {
    append(`[launcher] cannot write ${pidPath}: ${error?.message ?? error}\n`)
  }
}
append(`[launcher] runtime pid=${child.pid}\n`)

child.stdout.on('data', (chunk) => append(chunk))
child.stderr.on('data', (chunk) => append(chunk))
child.on('error', (error) => append(`[launcher] spawn failed: ${error?.message ?? error}\n`))
child.on('exit', (code, signal) => {
  append(`[launcher] runtime exited (code=${code} signal=${signal}); launcher exiting\n`)
  process.exit(0)
})

const stop = () => {
  try {
    child.kill()
  } catch {
    /* already gone */
  }
  process.exit(0)
}
process.on('SIGINT', stop)
process.on('SIGTERM', stop)

// Anchor the event loop. The child is the work; this process exists to hold its
// stdin open and to outlive the command that started it.
setInterval(() => {}, 1 << 30)
