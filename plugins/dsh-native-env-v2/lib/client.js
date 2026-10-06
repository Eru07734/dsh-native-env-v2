/**
 * dsh-native-env / client — the host's view of ONE remote peer.
 *
 * One `EnvClient` per configured peer, whether the peer dials in (tcp), is spawned
 * by us (ssh), or arrived through an invite (relay). Everything above this file —
 * the session binding, the commands, the model-facing tools — talks to a peer only
 * through `list()` and `call()`, so none of them has to know which transport is
 * underneath. That is why the pairing transport needed no change here at all: it
 * hands `attach()` a wire, exactly as the other two do.
 *
 * Two behaviours are deliberate:
 *
 *   - **A call on an offline peer THROWS.** It never falls back to the local
 *     tool. A silent fallback would run a command on the wrong machine, which is
 *     the one failure mode a takeover must not have.
 *   - **The host serves no requests on this wire.** The guest asks and we answer;
 *     a stray request is refused loudly rather than left to hang.
 *
 * @module dsh-native-env/client
 */

import { spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'

import { METHODS, V2_METHODS } from './env-protocol.js'
import { buildHello, isUnknownMethod, validateHello } from './protocol-v2.js'
import { LineWire } from './wire.js'

/** The peer is not connected, so nothing can be sent to it. */
export class EnvOfflineError extends Error {
  /**
   * @param peer - the peer name.
   * @param reason - why it is offline, when known.
   */
  constructor(peer, reason) {
    super(`dsh-native-env: peer "${peer}" is not connected${reason === undefined ? '' : ` (${reason})`}`)
    this.name = 'EnvOfflineError'
    this.peer = peer
  }
}

/** One remote peer. */
export class EnvClient {
  /**
   * @param options.config - the resolved peer row.
   * @param options.logger - optional log sink.
   * @param options.onToolsChanged - called with this client after its tool list
   *   changes, either from an explicit `list()` or from an `env/tools-changed`
   *   notification.
   */
  constructor(options) {
    this.config = options.config
    this.name = options.config.name
    this.logger = options.logger
    this.onToolsChanged = options.onToolsChanged

    this.wire = undefined
    this.child = undefined
    this.connected = false
    this.connectedSince = undefined
    this.remoteAddress = undefined
    this.attempts = 0
    this.lastError = undefined
    this.disconnectReason = undefined
    this.protocolVersion = 1
    this.metadata = undefined
    this.revision = 0
    this.readyPromise = undefined
    this.pendingNotification = undefined

    /** The remote's visible tools, as last reported. */
    this.tools = []
    /** The remote anchor agent, as last reported (or `{ id: null, unavailable }`). */
    this.anchor = null
    this.platform = undefined
    this.cwd = undefined

    this.stopped = false
    this.backoffMs = options.config.minBackoffMs ?? 1000
    this.timer = undefined
  }

  /**
   * @returns true when this peer's transport is a spawned process.
   *
   * `relay` peers are NOT spawned: they dial in through a relay the same way a tcp
   * peer dials in directly, so `start()` correctly does nothing for them and waits
   * for the pairing service to attach a wire.
   */
  get isSpawned() {
    return this.config.transport === 'ssh'
  }

  /**
   * Record one `env/list` payload.
   *
   * `notify` exists to break a cycle that is otherwise guaranteed: a refresh is
   * driven by `onToolsChanged`, and a refresh calls `list()`. Notifying from the
   * explicit path would make `list() → acceptList → onToolsChanged → refresh →
   * list()` recurse forever. Only the peer's own `env/tools-changed`
   * notification may trigger a refresh.
   *
   * @param payload - the `env/list` payload.
   * @param notify - whether to report the change to the owner.
   */
  acceptList(payload, notify = true) {
    if (payload === null || typeof payload !== 'object') return
    this.tools = Array.isArray(payload.tools) ? payload.tools : []
    this.anchor = payload.anchor ?? null
    this.platform = payload.platform
    this.cwd = payload.cwd
    if (Number.isInteger(payload.revision) && payload.revision >= 0) this.revision = payload.revision
    if (payload.metadata !== undefined) this.metadata = payload.metadata
    if (notify) this.onToolsChanged?.(this)
  }

  /**
   * Take ownership of an already-authenticated wire.
   * @param options.wire - the started wire.
   * @param options.remoteAddress - where it came from, for the status document.
   */
  attach({ wire, remoteAddress }) {
    if (this.wire !== undefined) this.detach('replaced by a newer connection')
    this.wire = wire
    this.connected = true
    this.connectedSince = Date.now()
    this.remoteAddress = remoteAddress
    this.attempts += 1
    this.lastError = undefined
    this.disconnectReason = undefined
    this.protocolVersion = 1
    this.metadata = undefined
    this.revision = 0
    this.backoffMs = this.config.minBackoffMs ?? 1000

    wire.onRequest(async (method) => {
      throw new Error(`dsh-native-env: the host does not serve ${method} on the env wire`)
    })
    const previousDisconnect = wire.onDisconnect
    wire.onDisconnect = (error) => {
      try {
        previousDisconnect?.(error)
      } catch {
        /* contained */
      }
      if (this.wire === wire) this.detach(`remote disconnected: ${String(error?.message ?? error)}`)
    }
    wire.onNotification((method, params) => {
      if (method !== METHODS.toolsChanged && method !== V2_METHODS.toolsChanged) return
      // A peer can emit tools-changed while env2/list is still negotiating.
      // Hold it until the initial directory response arrives so an older
      // in-flight list cannot overwrite a newer revision.
      if (this.readyPromise !== undefined) {
        this.pendingNotification = params
        return
      }
      this.acceptList(params)
    })
    wire.start()
    this.readyPromise = this.negotiate(wire).then((payload) => {
      const pending = this.pendingNotification
      this.pendingNotification = undefined
      if (pending !== undefined) this.acceptList(pending)
      return payload
    })
    this.readyPromise.catch((error) => {
      if (this.wire === wire) this.detach(`protocol negotiation failed: ${String(error?.message ?? error)}`)
    })
    this.logger?.info?.(`native-env: peer ${this.name} connected (${remoteAddress})`)
  }

  /** Negotiate env2 after the legacy bridge/auth transport is up. */
  async negotiate(wire) {
    const hello = buildHello({
      peer: this.name,
      label: this.config.label,
      runtimeVersion: process.env.DSH_VERSION,
      capabilities: ['env2', 'structured-content', 'cancel', 'tool-revisions', 'fail-closed'],
      maxMessageBytes: this.config.maxMessageBytes,
    })
    try {
      const remote = validateHello(await wire.request(V2_METHODS.hello, hello, AbortSignal.timeout(this.config.handshakeTimeoutMs ?? 10000)))
      this.protocolVersion = 2
      this.metadata = remote
      wire.maxMessageBytes = Math.min(wire.maxMessageBytes, remote.maxMessageBytes)
      const payload = await wire.request(V2_METHODS.list, {}, AbortSignal.timeout(this.config.listTimeoutMs ?? 30000))
      this.acceptList(payload, false)
      return payload
    } catch (error) {
      if (!isUnknownMethod(error)) throw error
      this.protocolVersion = 1
      this.metadata = undefined
      const payload = await wire.request(METHODS.list, {}, AbortSignal.timeout(this.config.listTimeoutMs ?? 30000))
      this.acceptList(payload, false)
      return payload
    }
  }

  currentMethods() {
    return this.protocolVersion === 2 ? V2_METHODS : METHODS
  }

  /**
   * Drop the current wire.
   * @param reason - recorded as `disconnectReason` and used to reject pending calls.
   */
  detach(reason) {
    const wire = this.wire
    this.wire = undefined
    this.connected = false
    this.connectedSince = undefined
    this.disconnectReason = reason
    this.readyPromise = undefined
    this.pendingNotification = undefined
    if (wire !== undefined) {
      try {
        wire.close(new Error(`dsh-native-env: ${reason}`))
      } catch {
        /* already closed */
      }
    }
    // Let the host remove per-session shadows immediately. Reconnection only
    // restores transport and the directory; the session must explicitly enter
    // again, so stale remote tools can never silently fall back locally.
    this.onToolsChanged?.(this)
  }

  /** @returns the wire, or throws {@link EnvOfflineError}. */
  requireWire() {
    if (this.wire === undefined || !this.connected) throw new EnvOfflineError(this.name, this.disconnectReason)
    return this.wire
  }

  /**
   * Ask the peer which tools it exposes, and to whom.
   * @returns the raw `env/list` payload.
   */
  async list() {
    const wire = this.requireWire()
    if (this.readyPromise !== undefined) await this.readyPromise
    const payload = await wire.request(this.currentMethods().list, {}, AbortSignal.timeout(this.config.listTimeoutMs ?? 30000))
    this.acceptList(payload, false)
    return payload
  }

  /**
   * Run one tool on the peer.
   *
   * The caller's signal is honoured twice on purpose: it rejects this side's
   * pending request, and it asks the peer to abort the work. Without the second
   * half a cancelled call would keep running on the remote machine.
   *
   * @param name - the remote tool name.
   * @param args - the arguments, already validated against the remote's schema.
   * @param signal - the caller's cancellation signal.
   * @returns the `env/call` payload.
   */
  async call(name, args, signal) {
    const wire = this.requireWire()
    if (this.readyPromise !== undefined) await this.readyPromise
    const callId = `c_${randomUUID().replaceAll('-', '')}`
    const onAbort = () => this.sendCancel(callId)
    if (signal !== undefined) {
      if (signal.aborted) throw signal.reason instanceof Error ? signal.reason : new Error('aborted before dispatch')
      signal.addEventListener('abort', onAbort, { once: true })
    }
    try {
      return await wire.request(this.currentMethods().call, { callId, name, arguments: args ?? {} }, signal)
    } finally {
      signal?.removeEventListener('abort', onAbort)
    }
  }

  /** Ask the peer to abort one in-flight call. Best effort, never awaited. */
  sendCancel(callId) {
    const wire = this.wire
    if (wire === undefined) return
    try {
      wire.request(this.currentMethods().cancel, { callId }, AbortSignal.timeout(10000)).catch(() => {
        /* the call already settled, or the peer went away */
      })
    } catch {
      /* the wire closed between the check and the send */
    }
  }

  /** A status document for `env_status` and the `/enter` receipt. */
  async status() {
    const base = {
      name: this.name,
      label: this.config.label,
      transport: this.config.transport,
      connected: this.connected,
      connectedSince: this.connectedSince,
      remoteAddress: this.remoteAddress,
      attempts: this.attempts,
      lastError: this.lastError,
      disconnectReason: this.disconnectReason,
      anchor: this.anchor,
      platform: this.platform,
      cwd: this.cwd,
      toolCount: this.tools.length,
      tools: this.tools.map((tool) => tool.name),
    }
    if (!this.connected) return base
    try {
      if (this.readyPromise !== undefined) await this.readyPromise
      return { ...base, protocolVersion: this.protocolVersion, metadata: this.metadata, guest: await this.wire.request(this.currentMethods().status, {}, AbortSignal.timeout(10000)) }
    } catch (error) {
      return { ...base, guest: { error: String(error?.message ?? error) } }
    }
  }

  /** Start the spawned transport, if this peer has one. Dial-in peers wait. */
  start() {
    if (!this.isSpawned) return
    this.spawnOnce()
  }

  /** Spawn the peer's command and keep it up. */
  spawnOnce() {
    if (this.stopped) return
    const { command, args, cwd } = this.config
    let child
    try {
      child = spawn(command, args, { cwd, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true })
    } catch (error) {
      this.lastError = String(error?.message ?? error)
      this.scheduleRespawn(`spawn threw: ${this.lastError}`)
      return
    }
    this.child = child

    const wire = new LineWire(child.stdout, child.stdin, {
      onMalformed: (line) =>
        this.logger?.warn?.(`native-env[${this.name}]: ignoring a non-JSON line from the spawned peer (${line.length} bytes)`),
      maxMessageBytes: this.config.maxMessageBytes,
    })
    // No HMAC handshake here: the channel is an ssh stdio pair, already
    // authenticated and encrypted by ssh itself. The tcp transport is the one
    // that has to prove the token.
    this.attach({ wire, remoteAddress: `spawned:${command}` })

    child.stderr?.on('data', (chunk) => {
      const text = chunk.toString('utf8').trim()
      if (text.length > 0) this.logger?.warn?.(`native-env[${this.name}] peer stderr: ${text.split('\n').slice(-3).join(' | ')}`)
    })
    child.on('error', (error) => {
      this.lastError = String(error?.message ?? error)
      this.detach(`spawn failed: ${this.lastError}`)
    })
    child.on('exit', (code, signal) => {
      this.child = undefined
      if (this.wire !== undefined) this.detach(`peer exited (code=${code} signal=${signal})`)
      this.scheduleRespawn(`peer exited (code=${code} signal=${signal})`)
    })
  }

  /** Re-spawn after a backoff, unless this client is stopped. */
  scheduleRespawn(reason) {
    if (this.stopped) return
    const wait = this.backoffMs
    this.backoffMs = Math.min(this.backoffMs * 2, this.config.maxBackoffMs ?? 30000)
    this.logger?.warn?.(`native-env[${this.name}]: ${reason}; respawning in ${wait} ms`)
    this.timer = setTimeout(() => this.spawnOnce(), wait)
    this.timer.unref?.()
  }

  /** Stop for good: no respawn, no reconnect. */
  stop() {
    this.stopped = true
    clearTimeout(this.timer)
    this.timer = undefined
    this.detach('stopped')
    const child = this.child
    this.child = undefined
    try {
      child?.kill()
    } catch {
      /* already gone */
    }
  }
}
