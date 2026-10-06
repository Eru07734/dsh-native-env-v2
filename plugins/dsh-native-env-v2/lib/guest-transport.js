/**
 * dsh-native-env / guest-transport — how the REMOTE half reaches the host.
 *
 * Two transports, one wire:
 *
 *   - `tcp` — the guest DIALS OUT to the host's listener. This is the only shape
 *     that works for the Windows guest: it sits behind NAT, and an inbound rule
 *     would need administrator rights on the guest (the net-bridge's keeper makes
 *     the same choice for the same reason). The connection is re-established with
 *     exponential backoff and the handshake is re-proved on every attempt, so a
 *     host restart costs a reconnect rather than a restart of the guest runtime.
 *
 *   - `stdio` — the host SPAWNS this runtime over ssh and speaks the wire on its
 *     stdin/stdout. Nothing dials out, the host owns the lifetime, and no port or
 *     firewall rule is involved. stdout therefore belongs to the protocol
 *     EXCLUSIVELY: every diagnostic goes to stderr, and a stray non-JSON line
 *     from anything else in the tree is counted and logged rather than allowed to
 *     desynchronize framing.
 *
 * @module dsh-native-env/guest-transport
 */

import { createConnection } from 'node:net'
import process from 'node:process'

import { CHANNEL_ENV, authenticateAsPeer } from './handshake.js'
import { LineWire } from './wire.js'

/**
 * Resolve after `ms`.
 *
 * Deliberately NOT unref'd. Between two connect attempts this timer is the only
 * thing pending, so unref'ing it lets Node's event loop drain and the process
 * exit silently with code 0 the moment a connect fails — which is exactly what a
 * guest does when it starts before the host's listener is up, or after the host
 * restarts. Found live: the deployed guest runtime vanished within a second of
 * starting, wrote nothing, and reported exit 0, because ECONNREFUSED was followed
 * by an unref'd backoff and there was nothing left to keep the loop alive.
 */
function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}

/**
 * Serve the env wire on this process's stdin/stdout.
 *
 * @param options.onRequest - `(method, params)` handler for incoming requests.
 * @param options.log - `(message) => void`, already stderr-bound by the caller.
 * @returns `{ state, stop }`.
 */
export function serveStdio(options) {
  const { onRequest, onEnd, log } = options
  const state = {
    transport: 'stdio',
    connected: true,
    connectedSince: Date.now(),
    attempts: 1,
    failures: 0,
    lastError: undefined,
    malformed: 0,
  }

  const wire = new LineWire(process.stdin, process.stdout, {
    onMalformed: (line) => {
      state.malformed += 1
      // A non-JSON line on stdout means something else in the tree is writing to
      // the protocol channel. Say so once per occurrence, on stderr, with enough
      // of the line to identify the offender — this is the stdio transport's one
      // real failure mode and it is otherwise invisible.
      log(`env-guest: ignoring a non-JSON line on the protocol channel (${line.length} bytes): ${line.slice(0, 200)}`)
    },
    maxMessageBytes: options.maxMessageBytes,
  })
  wire.onDisconnect = (error) => {
    state.connected = false
    log(`env-guest: protocol output closed (${String(error?.message ?? error)})`)
    onEnd?.()
  }
  wire.onRequest(onRequest)
  wire.start()
  log('env-guest: serving the env wire on stdin/stdout')

  // Nothing else binds this process's lifetime. Under the `sdk` profile the SDK
  // server owns stdin EOF; here the env wire does, so when the host's ssh channel
  // goes away the runtime must not linger on the remote machine.
  const onStdinEnd = () => {
    if (!state.connected) return
    state.connected = false
    log('env-guest: stdin closed (the host went away)')
    onEnd?.()
  }
  process.stdin.on('end', onStdinEnd)
  process.stdin.on('close', onStdinEnd)

  return {
    state,
    get current() {
      return wire
    },
    stop() {
      state.connected = false
      process.stdin.off('end', onStdinEnd)
      process.stdin.off('close', onStdinEnd)
      try {
        wire.close()
      } catch {
        /* already closed */
      }
    },
  }
}

/**
 * Dial the host's env listener and keep the connection up.
 *
 * Returns immediately; the connect/handshake/retry loop runs in the background so
 * plugin application never blocks boot on a host that is not up yet.
 *
 * @param options.host / options.port - the host listener.
 * @param options.token - the shared secret.
 * @param options.peer - this machine's stable peer name.
 * @param options.handshakeTimeoutMs - per-exchange deadline.
 * @param options.minBackoffMs / options.maxBackoffMs - retry bounds.
 * @param options.onRequest - `(method, params)` handler for incoming requests.
 * @param options.log - `(message) => void`.
 * @returns `{ state, current, stop, started }`.
 */
export function dialTcp(options) {
  const {
    host,
    port,
    token,
    peer,
    handshakeTimeoutMs = 5000,
    minBackoffMs = 1000,
    maxBackoffMs = 30000,
    onRequest,
    log,
  } = options

  const state = {
    transport: 'tcp',
    host,
    port,
    connected: false,
    connectedSince: undefined,
    attempts: 0,
    failures: 0,
    lastError: undefined,
    malformed: 0,
  }

  let stopped = false
  let socket
  let wire

  /** One connect + handshake attempt. Resolves true when the wire is authenticated. */
  const connectOnce = () =>
    new Promise((resolve) => {
      state.attempts += 1
      const candidate = createConnection({ host, port })
      candidate.setNoDelay(true)

      const detach = () => {
        candidate.removeListener('error', onError)
        candidate.removeListener('connect', onConnect)
      }
      const onError = (error) => {
        detach()
        candidate.destroy()
        state.lastError = String(error?.message ?? error)
        resolve(false)
      }
      const onConnect = () => {
        detach()
        socket = candidate
        wire = new LineWire(candidate, candidate, {
          onMalformed: (line) => {
            state.malformed += 1
            log(`env-guest: ignoring a non-JSON frame from the host (${line.length} bytes)`)
          },
          maxMessageBytes: options.maxMessageBytes,
        })
        wire.onRequest(onRequest)
        wire.start()

        // The socket can die mid-handshake; `close` settles this attempt so the
        // retry loop is never left waiting on a connection that is already gone.
        candidate.once('close', () => {
          state.connected = false
          state.connectedSince = undefined
        })

        authenticateAsPeer(wire, { token, peer, channel: CHANNEL_ENV, timeoutMs: handshakeTimeoutMs }).then(
          (result) => {
            state.connected = true
            state.connectedSince = Date.now()
            state.failures = 0
            state.lastError = undefined
            log(`env-guest: authenticated with ${host}:${port} as peer "${result.peer}" (attempt #${state.attempts})`)
            resolve(true)
          },
          (error) => {
            state.failures += 1
            state.lastError = String(error?.message ?? error)
            try {
              wire.close()
            } catch {
              /* already closed */
            }
            candidate.destroy()
            resolve(false)
          },
        )
      }

      candidate.once('error', onError)
      candidate.once('connect', onConnect)
    })

  const run = async () => {
    let backoff = minBackoffMs
    while (!stopped) {
      const ok = await connectOnce()
      if (stopped) break
      if (!ok) {
        log(`env-guest: connect/auth failed (${state.lastError}); retrying in ${backoff} ms`)
        await sleep(backoff)
        backoff = Math.min(backoff * 2, maxBackoffMs)
        continue
      }
      backoff = minBackoffMs
      // Hold until this connection ends, then loop and reconnect.
      await new Promise((resolve) => {
        if (socket === undefined) {
          resolve()
          return
        }
        socket.once('close', resolve)
      })
      if (stopped) break
      state.connected = false
      state.connectedSince = undefined
      log('env-guest: the host connection closed; the runtime stays up and will reconnect')
    }
  }

  const started = run()
  started.catch?.((error) => log(`env-guest: the retry loop ended unexpectedly: ${error}`))

  return {
    state,
    get current() {
      return wire
    },
    stop() {
      stopped = true
      try {
        wire?.close()
      } catch {
        /* already closed */
      }
      try {
        socket?.destroy()
      } catch {
        /* already gone */
      }
    },
    started,
  }
}
