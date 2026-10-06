/**
 * dsh-native-env / hub — the host's listener and peer registry.
 *
 * The hub owns the TCP listener, proves the shared token on every dial-in, and
 * hands an authenticated wire to the `EnvClient` that owns that peer name. Peer
 * rows whose transport is `ssh` are spawned instead and never reach this
 * listener.
 *
 * Why a SEPARATE PORT rather than the net-bridge's: that hub's `peer.attach()`
 * holds exactly one socket per peer name, so an env dial-in under the same name
 * would displace the live keeper connection. A second listener costs nothing —
 * the host's firewall rule is program-scoped ("Node.js JavaScript Runtime",
 * inbound allow), so no new rule is needed — and the `channel` tag on the
 * handshake makes a frame meant for the other listener refuse cleanly instead of
 * being half-understood.
 *
 * Binding failures are recorded, never thrown: a host with a busy port must still
 * boot, and `env_status` is where the operator finds out why.
 *
 * @module dsh-native-env/hub
 */

import { createServer } from 'node:net'

import { EnvClient } from './client.js'
import {
  AUTH_METHOD,
  BRIDGE_VERSION,
  CHANNEL_ENV,
  HELLO_METHOD,
  hostProof,
  newNonce,
  parseHello,
  peerProof,
  sameProof,
} from './handshake.js'
import { isAllowedPeer, normalizeAddress } from './netaddr.js'
import { LineWire } from './wire.js'

/** The host-side listener and its peer clients. */
export class EnvHub {
  /**
   * @param options.config - the resolved plugin config.
   * @param options.logger - optional log sink.
   * @param options.onToolsChanged - forwarded to every client.
   */
  constructor(options) {
    this.config = options.config
    this.logger = options.logger
    this.onToolsChanged = options.onToolsChanged
    this.clients = new Map()
    for (const peerConfig of this.config.peers) {
      this.clients.set(peerConfig.name, new EnvClient({ config: { ...peerConfig, maxMessageBytes: peerConfig.maxMessageBytes ?? this.config.maxMessageBytes, handshakeTimeoutMs: peerConfig.handshakeTimeoutMs ?? this.config.handshakeTimeoutMs }, logger: this.logger, onToolsChanged: this.onToolsChanged }))
    }
    this.servers = []
    this.status = { listening: [], failures: [], allowPeers: this.config.allowPeers }
  }

  /** @returns the client for one peer name, or `undefined`. */
  get(name) {
    return this.clients.get(name)
  }

  /** @returns every configured peer client, in config order. */
  list() {
    return [...this.clients.values()]
  }

  /**
   * Register a peer that was not declared in the configuration.
   *
   * This is what the pairing transport needs: a peer appears because another
   * machine authenticated to this host, not because an operator wrote a row. The
   * caller attaches a wire to the returned client; everything above (the commands,
   * `env_status`, the per-session shadows) sees an ordinary client either way,
   * which is why the pairing transport needed no change in `binding.js` at all.
   *
   * An existing client for the same name is returned unchanged, so a reconnecting
   * guest lands on the client its session already entered instead of a fresh one —
   * a fresh one would leave that session's shadow pointing at a dead peer.
   *
   * @param peerConfig - the resolved peer row (`{ name, label, transport, ... }`).
   * @returns the client.
   */
  adopt(peerConfig) {
    const existing = this.clients.get(peerConfig.name)
    if (existing !== undefined) {
      if (peerConfig.label !== undefined) existing.config.label = peerConfig.label
      return existing
    }
    const client = new EnvClient({ config: { ...peerConfig, maxMessageBytes: peerConfig.maxMessageBytes ?? this.config.maxMessageBytes, handshakeTimeoutMs: peerConfig.handshakeTimeoutMs ?? this.config.handshakeTimeoutMs }, logger: this.logger, onToolsChanged: this.onToolsChanged })
    this.clients.set(peerConfig.name, client)
    this.logger?.info?.(`native-env: adopted peer ${peerConfig.name} (${peerConfig.transport})`)
    return client
  }

  /**
   * Remove one dynamically adopted peer.
   *
   * Only ever called for a peer the operator revoked: a peer that merely went
   * offline is kept, so its place in a session survives the outage.
   *
   * @param name - the peer name.
   * @returns true when a client was removed.
   */
  release(name) {
    const client = this.clients.get(name)
    if (client === undefined) return false
    client.stop()
    this.clients.delete(name)
    this.logger?.info?.(`native-env: released peer ${name}`)
    return true
  }

  /**
   * Spawn the process peers and bind the listener. Never throws.
   * @returns the listener status document.
   */
  async start() {
    for (const client of this.clients.values()) {
      try {
        client.start()
      } catch (error) {
        this.status.failures.push({ address: client.name, reason: String(error?.message ?? error) })
      }
    }

    const dialInPeers = [...this.clients.values()].filter((client) => !client.isSpawned)
    if (dialInPeers.length === 0) return this.status
    if (this.config.token === undefined) {
      this.status.failures.push({ address: '*', reason: 'no token configured, so no peer could be authenticated' })
      return this.status
    }
    if (this.config.listen.length === 0) {
      this.status.failures.push({ address: '*', reason: 'no listen addresses configured' })
      return this.status
    }

    for (const address of this.config.listen) {
      const server = createServer((socket) => this.accept(socket))
      try {
        await new Promise((resolve, reject) => {
          const onError = (error) => reject(error)
          server.once('error', onError)
          server.listen({ host: address, port: this.config.port }, () => {
            server.removeListener('error', onError)
            resolve()
          })
        })
        this.servers.push(server)
        this.status.listening.push({ address, port: this.config.port })
      } catch (error) {
        this.status.failures.push({ address, reason: String(error?.message ?? error) })
        try {
          server.close()
        } catch {
          /* never bound */
        }
      }
    }
    return this.status
  }

  /**
   * Admit one dial-in and run the host half of the handshake.
   * @param socket - the accepted socket.
   */
  accept(socket) {
    const address = normalizeAddress(socket.remoteAddress ?? '')
    const remoteAddress = `${address}:${socket.remotePort}`

    if (!isAllowedPeer(address, this.config.allowPeers)) {
      this.logger?.warn?.(`native-env: refusing ${remoteAddress}: not in allowPeers`)
      socket.destroy()
      return
    }

    socket.setNoDelay(true)
    const wire = new LineWire(socket, socket, {
      onMalformed: (line) => this.logger?.warn?.(`native-env: ignoring a malformed frame from ${remoteAddress} (${line.length} bytes)`),
      maxMessageBytes: this.config.maxMessageBytes,
    })

    let stage = 'hello'
    let clientNonce
    let serverNonce
    let peerName

    wire.onRequest(async (method, params) => {
      if (stage === 'hello') {
        if (method !== HELLO_METHOD) throw new Error(`env-bridge: handshake required (expected ${HELLO_METHOD})`)
        const hello = parseHello(params, CHANNEL_ENV)
        if (!this.clients.has(hello.peer)) {
          throw new Error(
            `env-bridge: unknown peer ${JSON.stringify(hello.peer)}; known peers: ${[...this.clients.keys()].join(', ') || '(none)'}`,
          )
        }
        peerName = hello.peer
        clientNonce = hello.nonce
        serverNonce = newNonce()
        stage = 'auth'
        return {
          ok: true,
          version: BRIDGE_VERSION,
          nonce: serverNonce,
          hmac: hostProof(this.config.token, clientNonce, serverNonce),
          peer: peerName,
          channel: hello.channel,
        }
      }

      if (method !== AUTH_METHOD) throw new Error(`env-bridge: handshake required (expected ${AUTH_METHOD})`)
      if (!sameProof(params.hmac, peerProof(this.config.token, clientNonce, serverNonce))) {
        this.logger?.warn?.(`native-env: ${remoteAddress} failed to prove the shared token`)
        socket.destroy()
        throw new Error('env-bridge: the peer failed to prove the shared token')
      }
      stage = 'ready'
      this.clients.get(peerName).attach({ wire, remoteAddress })
      return { ok: true, peer: peerName }
    })
    wire.start()

    socket.on('error', () => socket.destroy())
    socket.on('close', () => {
      const client = peerName === undefined ? undefined : this.clients.get(peerName)
      if (client !== undefined && client.wire === wire) client.detach('socket closed')
    })
  }

  /** Close every listener and stop every client. */
  async stop() {
    for (const server of this.servers.splice(0)) {
      try {
        await new Promise((resolve) => server.close(resolve))
      } catch {
        /* already closed */
      }
    }
    for (const client of this.clients.values()) client.stop()
  }
}
