/**
 * dsh-native-env-relay / main — the process entry point.
 *
 * Deliberately thin: it starts the relay, reports the bound address, and shuts
 * down cleanly on a signal. Everything that decides behaviour lives in
 * `server.js` / `config.js` / `lib/registry.js`, so a test can exercise the whole
 * relay through `createRelay()` without spawning a process.
 *
 * @module dsh-native-env-relay/main
 */

import process from 'node:process'

import { createRelay } from './server.js'

const relay = createRelay()

relay
  .listen()
  .then((address) => {
    const scheme = relay.config.tls === undefined ? 'ws' : 'wss'
    // The operator's one actionable line: the base URL their DSH host should be
    // configured with. It carries no invite id and no secret.
    process.stdout.write(
      `dsh-native-env relay listening on ${String(address.address)}:${String(address.port)} — channel base ${scheme}://<public-host>:${String(address.port)}/v2/relay\n`,
    )
  })
  .catch((error) => {
    process.stderr.write(`dsh-native-env relay failed to start: ${String(error?.message ?? error)}\n`)
    process.exit(1)
  })

/** Stop accepting, drop every invite, exit. */
const shutdown = () => {
  relay
    .close()
    .catch(() => {
      /* nothing useful to do while exiting */
    })
    .finally(() => process.exit(0))
}

process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
