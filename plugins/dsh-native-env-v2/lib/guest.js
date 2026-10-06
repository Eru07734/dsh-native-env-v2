/**
 * dsh-native-env / guest — the REMOTE half of the plugin.
 *
 * Mounted inside the remote machine's OWN DSH runtime, this file is what makes a
 * takeover mean "run it over there" rather than "ask the agent over there to do
 * it". It serves three questions over the env wire:
 *
 *   - `env/list`   → which tools this runtime exposes, and to WHOM;
 *   - `env/call`   → run one of them;
 *   - `env/cancel` → abandon one in flight.
 *
 * The design decision that matters is the ANCHOR AGENT. `env/call` does not call
 * a tool definition directly; it goes through `ctx.tools.execute({ …, agent })`
 * with a real agent this plugin creates once. That single choice buys three
 * things that are otherwise unavailable:
 *
 *   1. `schemas(anchor)` is the scope's COMPLETE derived view — the global layer
 *      plus everything the remote's own plugins register onto agents, with the
 *      remote's `restrict()` already applied. Listing the global layer alone
 *      would silently hide every per-agent tool a plugin contributes.
 *   2. `execute({ agent })` runs the remote's REAL pipeline, so its global
 *      guards, `tools/pre-execute` gates, `post-execute` wrappers and
 *      `finalizeContent` all apply. Agent-scoped guards only match when the call
 *      carries an agent, and those are keyed by `exec.agent`.
 *   3. `sessionCwd()` reads `exec.agent.session.header.cwd`, so relative paths
 *      resolve against the anchor's `meta.cwd` — the remote working directory —
 *      with no path translation anywhere in the design.
 *
 * If the anchor cannot be created (no agent factory, or an unresolvable default
 * route), the plugin DEGRADES to the global view and reports
 * `anchor.unavailable` in `env/list`. The degradation is never silent: a caller
 * that gets a smaller tool list must be able to tell why.
 *
 * @module dsh-native-env/guest
 */

import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import process from 'node:process'

import { METHODS, V2_METHODS, normalizeContent, parseCallParams, parseCancelParams } from './env-protocol.js'
import { buildHello, validateHello } from './protocol-v2.js'
import { dialTcp, serveStdio } from './guest-transport.js'
import { PairingGuest } from './pairing-guest.js'
import { registerHostApi, SERVER_API_PREFIX } from './host-api.js'
import { SecretStore, StateStore, resolveDshHome } from './state-store.js'
import { renderTermsText } from './terms.js'
import { LineWire } from './wire.js'

/** Stable Cordis plugin name. */
export const name = 'native-env-guest-v2'

/** `tools` answers the calls; `agents` mints the anchor they run as. */
export const inject = ['tools', 'agents']

/** Result cap when the config names none: 256 KiB of JSON. */
const DEFAULT_MAX_RESULT_BYTES = 262144

/**
 * Normalize the row config.
 *
 * The default transport is chosen, not fixed, and the rule is worth stating: a row
 * that supplies a TOKEN is asking for the legacy dial-in transport, and a row that
 * supplies neither a token nor a transport is asking for the pairing transport.
 * Defaulting everything to `tcp` (the previous behaviour) would leave a fresh
 * install trying to dial a host it has never heard of.
 *
 * @param raw - the row config.
 * @returns the resolved config.
 */
function resolveConfig(raw) {
  const config = raw ?? {}
  const declared = config.transport === 'stdio' || config.transport === 'tcp' || config.transport === 'relay' ? config.transport : undefined
  const tokenFile = typeof config.tokenFile === 'string' ? config.tokenFile : undefined
  const tokenEnv = typeof config.tokenEnv === 'string' ? config.tokenEnv : undefined
  const transport = declared ?? (tokenFile !== undefined || tokenEnv !== undefined ? 'tcp' : 'relay')
  return {
    transport,
    host: typeof config.host === 'string' ? config.host : '127.0.0.1',
    port: Number.isSafeInteger(config.port) ? config.port : 8912,
    peer: typeof config.peer === 'string' && config.peer.length > 0 ? config.peer : 'guest',
    tokenFile,
    tokenEnv,
    handshakeTimeoutMs: Number.isSafeInteger(config.handshakeTimeoutMs) ? config.handshakeTimeoutMs : 5000,
    cwd: typeof config.cwd === 'string' && config.cwd.length > 0 ? config.cwd : undefined,
    agentPreset: typeof config.agentPreset === 'string' && config.agentPreset.length > 0 ? config.agentPreset : undefined,
    route: config.route ?? undefined,
    maxResultBytes: Number.isSafeInteger(config.maxResultBytes) && config.maxResultBytes > 0
      ? config.maxResultBytes
      : DEFAULT_MAX_RESULT_BYTES,
    maxMessageBytes: Number.isSafeInteger(config.maxMessageBytes) && config.maxMessageBytes > 0 ? config.maxMessageBytes : 4 * 1024 * 1024,
    // ── pairing ──────────────────────────────────────────────────────────────
    /** How this machine introduces itself to the host. */
    label: typeof config.label === 'string' && config.label.length > 0 ? config.label : undefined,
    /** Reconnect on the same invite while it lasts. */
    autoReconnect: config.autoReconnect !== false,
    /** Require the disclaimer before a join. */
    requireTerms: config.requireTerms !== false,
    /** The deadline for one pairing handshake. */
    acceptTimeoutMs: Number.isSafeInteger(config.acceptTimeoutMs) ? config.acceptTimeoutMs : 20000,
    /** An invite to attach to at startup, for a non-interactive deployment. */
    invite: typeof config.invite === 'string' && config.invite.length > 0 ? config.invite : undefined,
    /**
     * The relay(s) this machine may be paired through.
     *
     * Required for a TYPED pairing and unnecessary for a QR one: a nine-digit device
     * code cannot name a relay, so typing a code only works when this machine already
     * knows which relay to ask. The first entry is used.
     */
    relayUrls: Array.isArray(config.relayUrls) ? config.relayUrls.filter((entry) => typeof entry === 'string' && entry.length > 0) : [],
  }
}

/**
 * Read the shared token. It never travels on a command line or into a log.
 * @param config - the resolved config.
 * @returns the trimmed token.
 * @throws when neither source yields one.
 */
function readToken(config) {
  if (config.tokenEnv !== undefined) {
    const value = process.env[config.tokenEnv]
    if (typeof value === 'string' && value.length > 0) return value.trim()
  }
  if (config.tokenFile !== undefined) return readFileSync(config.tokenFile, 'utf8').trim()
  throw new Error('no token: pass tokenFile or tokenEnv')
}

/**
 * Keep a tool result inside the wire's byte budget.
 *
 * Whole blocks are kept while they fit, and a text note is always appended, so a
 * truncated result says so instead of looking like a short one. The value is
 * measured as the JSON actually serialized, because that is what crosses.
 *
 * @param content - the remote tool's content blocks.
 * @param maxBytes - the inclusive cap.
 * @returns `{ blocks, truncated, bytes }`.
 */
function capContent(content, maxBytes) {
  const blocks = normalizeContent(content)
  const bytes = Buffer.byteLength(JSON.stringify(blocks), 'utf8')
  if (bytes <= maxBytes) return { blocks, truncated: false, bytes }

  const kept = []
  let used = 0
  for (const block of blocks) {
    const size = Buffer.byteLength(JSON.stringify(block), 'utf8')
    if (used + size > maxBytes) break
    kept.push(block)
    used += size
  }
  kept.push({
    type: 'text',
    text:
      `[dsh-native-env] result truncated: ${bytes} bytes exceeded the ${maxBytes}-byte cap; ` +
      `kept ${kept.length} of ${blocks.length} block(s). Narrow the request or raise maxResultBytes on the guest row.`,
  })
  return { blocks: kept, truncated: true, bytes }
}

/**
 * Mount the remote half.
 * @param ctx - the plugin context carrying `tools` and `agents`.
 * @param config - the row config (see the plan's guest row).
 */
export function apply(ctx, config) {
  const cfg = resolveConfig(config)
  // stderr only: under the stdio transport, stdout is the protocol channel.
  const log = (message) => {
    try {
      process.stderr.write(`[native-env-guest] ${message}\n`)
    } catch {
      /* a closed stderr must not take the runtime down */
    }
  }

  // A UNIQUE anchor id per runtime process, and deliberately NOT a stable one.
  //
  // The remote persists every session it creates and seeds its in-memory session
  // store from that persistence at boot, so a fixed id makes the SECOND runtime
  // start fail with `session "…" already exists` — which degrades the entire
  // takeover to the global tool view and silently loses every agent-scoped tool.
  // Found live: run 1 created the anchor, run 2 reported `anchor.unavailable`.
  // The keeper restarts the guest runtime up to five times, so this is the normal
  // path, not an edge case.
  //
  // Resuming the previous id instead would be worse in a different way: the
  // resumed session keeps the PREVIOUS run's `meta.cwd`, so an operator's cwd
  // change would be silently ignored. A fresh anchor always reflects the current
  // config. The cost is one throwaway session (~300 bytes, never prompted) per
  // runtime start, which is why the id is prefixed: `dsh-native-env:*` is
  // greppable if the remote's log ever needs pruning.
  const anchorSessionId = `dsh-native-env-v2:${cfg.peer}:${process.pid}-${randomBytes(3).toString('hex')}`
  const anchor = { handle: undefined, promise: undefined, status: 'idle', reason: undefined }

  /** What `env/list` reports about the anchor, including why it is missing. */
  const anchorInfo = () =>
    anchor.status === 'ready'
      ? { id: String(anchor.handle.agent.id), cwd: anchor.handle.agent.session.header.cwd, preset: cfg.agentPreset ?? null }
      : { id: null, cwd: cfg.cwd ?? null, preset: cfg.agentPreset ?? null, unavailable: anchor.reason ?? 'not created yet' }

  /**
   * Create the anchor agent once, on first use.
   * @returns the agent, or `undefined` when it could not be created (degraded mode).
   */
  async function ensureAnchor() {
    if (anchor.handle !== undefined) return anchor.handle.agent
    if (anchor.status === 'failed') return undefined
    anchor.promise ??= ctx.agents
      .create({
        sessionId: anchorSessionId,
        meta: {
          ...(cfg.cwd !== undefined ? { cwd: cfg.cwd } : {}),
          ...(cfg.agentPreset !== undefined ? { agentPreset: cfg.agentPreset } : {}),
        },
        ...(cfg.route !== undefined ? { agentOptions: cfg.route } : {}),
      })
      .then(
        (handle) => {
          anchor.handle = handle
          anchor.status = 'ready'
          log(`anchor agent ready: ${handle.agent.id} (cwd ${handle.agent.session.header.cwd})`)
          return handle.agent
        },
        (error) => {
          anchor.status = 'failed'
          anchor.reason = String(error?.message ?? error)
          log(`anchor agent unavailable: ${anchor.reason} — degrading to the global tool view`)
          return undefined
        },
      )
    return anchor.promise
  }

  const inflight = new Map()
  let revision = 0
  let activeProtocol = 1

  /** The remote working directory as the tools will see it. */
  const cwdOf = (agent) => agent?.session.header.cwd ?? cfg.cwd ?? process.cwd()

  async function listTools() {
    const agent = await ensureAnchor()
    const cwd = cwdOf(agent)
    const metadata = buildHello({
      peer: cfg.peer,
      label: cfg.label,
      platform: process.platform,
      cwd,
      runtimeVersion: process.env.DSH_VERSION,
      revision,
      maxMessageBytes: cfg.maxMessageBytes,
    })
    return {
      peer: cfg.peer,
      platform: process.platform,
      cwd,
      anchor: anchorInfo(),
      protocol: activeProtocol,
      revision,
      metadata,
      tools: ctx.tools.schemas(agent).map((schema) => ({
        name: schema.name,
        description: schema.description,
        parameters: schema.parameters,
      })),
    }
  }

  async function callTool(params) {
    const { callId, name, arguments: args } = parseCallParams(params)
    const controller = new AbortController()
    inflight.set(callId, controller)
    const startedAt = Date.now()
    try {
      const agent = await ensureAnchor()
      const result = await ctx.tools.execute({
        name,
        arguments: args,
        signal: controller.signal,
        ...(agent !== undefined ? { agent } : {}),
      })
      const capped = capContent(result.content, cfg.maxResultBytes)
      return {
        callId,
        name,
        isError: result.isError === true,
        content: capped.blocks,
        truncated: capped.truncated,
        bytes: capped.bytes,
        durationMs: Date.now() - startedAt,
      }
    } catch (error) {
      // A thrown call is reported as an error RESULT, not a wire error: the host
      // must be able to tell "the remote tool failed" from "the env wire broke".
      return {
        callId,
        name,
        isError: true,
        durationMs: Date.now() - startedAt,
        content: [{ type: 'text', text: String(error?.message ?? error) }],
      }
    } finally {
      inflight.delete(callId)
    }
  }

  function cancelCall(params) {
    const { callId } = parseCancelParams(params)
    const controller = inflight.get(callId)
    if (controller === undefined) return { ok: false, callId, reason: 'no such in-flight call' }
    controller.abort(new Error('cancelled by the host'))
    return { ok: true, callId }
  }

  async function status() {
    const agent = await ensureAnchor()
    const cwd = cwdOf(agent)
    return {
      peer: cfg.peer,
      platform: process.platform,
      cwd,
      protocol: activeProtocol,
      revision,
      metadata: buildHello({ peer: cfg.peer, label: cfg.label, platform: process.platform, cwd, revision, maxMessageBytes: cfg.maxMessageBytes }),
      anchor: anchorInfo(),
      inflight: inflight.size,
      connection: transport?.state,
    }
  }

  /** Dispatch one incoming request. An unknown method must fail loudly. */
  async function handleRequest(method, params) {
    switch (method) {
      case V2_METHODS.hello:
        validateHello(params)
        activeProtocol = 2
        if (transport?.current !== undefined) transport.current.maxMessageBytes = Math.min(transport.current.maxMessageBytes, params.maxMessageBytes)
        return buildHello({
          peer: cfg.peer,
          label: cfg.label,
          platform: process.platform,
          cwd: cwdOf(await ensureAnchor()),
          runtimeVersion: process.env.DSH_VERSION,
          revision,
          maxMessageBytes: cfg.maxMessageBytes,
        })
      case V2_METHODS.list:
        activeProtocol = 2
        return listTools()
      case V2_METHODS.call:
        activeProtocol = 2
        return callTool(params)
      case V2_METHODS.cancel:
        activeProtocol = 2
        return cancelCall(params)
      case V2_METHODS.status:
        activeProtocol = 2
        return status()
      case METHODS.list:
        return listTools()
      case METHODS.call:
        return callTool(params)
      case METHODS.cancel:
        return cancelCall(params)
      case METHODS.status:
        return status()
      default:
        throw new Error(`dsh-native-env: unknown env method ${JSON.stringify(method)}`)
    }
  }

  let transport

  // Push a refresh when the remote's visible tool set changes. This is what makes
  // a plugin mounted AFTER a takeover show up without a re-enter, and it also
  // closes the race where `agents.create` resolves before the `agent/created`
  // listeners of other plugins have finished installing their scoped tools.
  let notifyTimer
  ctx.on('tools/change', () => {
    revision += 1
    clearTimeout(notifyTimer)
    notifyTimer = setTimeout(() => {
      const wire = transport?.current
      if (wire === undefined) return
      listTools().then(
        (payload) => {
          try {
            wire.notify(activeProtocol === 2 ? V2_METHODS.toolsChanged : METHODS.toolsChanged, payload)
          } catch {
            /* the connection went away between the check and the send */
          }
        },
        () => {
          /* a failed refresh must not disturb the runtime */
        },
      )
    }, 250)
    notifyTimer.unref?.()
  })

  if (cfg.transport === 'stdio') {
    transport = serveStdio({
      onRequest: handleRequest,
      maxMessageBytes: cfg.maxMessageBytes,
      log,
      // The host owns this process's lifetime over the ssh channel; when that
      // channel closes, exit rather than linger on the remote machine.
      onEnd: () => process.exit(0),
    })
  } else if (cfg.transport === 'tcp') {
    let token
    try {
      token = readToken(cfg)
      if (token.length === 0) throw new Error('the token is empty')
    } catch (error) {
      log(`not starting: ${String(error?.message ?? error)}`)
      return
    }
    transport = dialTcp({
      host: cfg.host,
      port: cfg.port,
      token,
      peer: cfg.peer,
      handshakeTimeoutMs: cfg.handshakeTimeoutMs,
      maxMessageBytes: cfg.maxMessageBytes,
      onRequest: handleRequest,
      log,
    })
  } else {
    transport = startPairingTransport({ ctx, cfg, log, handleRequest })
  }

  log(`starting: transport=${cfg.transport} peer=${cfg.peer} cwd=${cfg.cwd ?? '(runtime default)'}`)

  // ── human commands ─────────────────────────────────────────────────────────
  //
  // The guest is normally reached over ssh or a relay, so its commands are the
  // PRIMARY interface a user has on that machine — this is where a pasted invite
  // token goes. They are registered only when the profile mounts `commands`, which
  // the `env` profile used by the ssh transport deliberately does not (its stdout
  // belongs to the protocol).
  registerGuestCommands({ ctx, cfg, transport, log })

  ctx.effect(
    () => () => {
      clearTimeout(notifyTimer)
      transport.stop()
      const handle = anchor.handle
      anchor.handle = undefined
      if (handle !== undefined) {
        Promise.resolve()
          .then(() => handle.dispose())
          .catch((error) => log(`failed to dispose the anchor agent: ${String(error?.message ?? error)}`))
      }
    },
    'native-env-guest-v2:lifecycle',
  )
}

/**
 * Build the pairing transport.
 *
 * The returned object presents the SAME small surface the tcp and stdio
 * transports do (`state`, `current`, `stop`), because the notification path above
 * (`transport?.current`) must keep working without knowing which one is in use.
 * The wire is created per connection: a reconnected guest gets a fresh wire, and
 * the previous one is closed so its in-flight calls are rejected rather than left
 * hanging.
 *
 * @param options.ctx - the plugin context.
 * @param options.cfg - the resolved config.
 * @param options.log - the stderr logger.
 * @param options.handleRequest - the env request handler.
 * @returns the transport shim.
 */
function startPairingTransport(options) {
  const { cfg, log, handleRequest } = options
  const state = { transport: 'relay', connected: false, connectedSince: undefined, attempts: 0, lastError: undefined, peer: undefined }
  let current
  let guest
  let stopped = false

  const attach = ({ peer, stream }) => {
    if (stopped) {
      stream.destroy()
      return
    }
    // A reconnect replaces the wire; closing the old one fails its pending calls
    // immediately instead of leaving them to time out.
    if (current !== undefined) {
      try {
        current.close(new Error('the pairing connection was replaced'))
      } catch {
        /* already closed */
      }
    }
    const wire = new LineWire(stream, stream, { maxMessageBytes: cfg.maxMessageBytes })
    wire.onRequest(handleRequest)
    wire.start()
    current = wire
    state.connected = true
    state.connectedSince = Date.now()
    state.peer = peer
    state.lastError = undefined
    log(`paired with host ${peer.fingerprint} (${peer.platform || 'unknown'})`)
  }

  const detach = (reason) => {
    state.connected = false
    state.connectedSince = undefined
    const wire = current
    current = undefined
    if (wire !== undefined) {
      try {
        wire.close(new Error(reason))
      } catch {
        /* already closed */
      }
    }
  }

  const secrets = new SecretStore({ credentials: options.ctx.get?.('credentials'), namespace: 'native-env-v2', logger: { warn: log, info: log } })
  const stateStore = new StateStore({ file: join(resolveDshHome(), 'native-env-v2-state.json'), logger: { warn: log, info: log } })

  PairingGuest.load({
    config: cfg,
    logger: { info: (message) => log(message), warn: (message) => log(`warning: ${message}`) },
    secrets,
    state: stateStore,
    label: cfg.label,
  }).then(
    async (service) => {
      if (stopped) {
        await service.stop()
        return
      }
      guest = service
      service.on('paired', attach)
      service.on('unpaired', ({ reason }) => detach(reason))
      service.on('failed', ({ message }) => {
        state.lastError = message
        state.attempts = service.attempts
        log(`pairing attempt failed: ${message}`)
      })
      // Wait for Web services and bind route lifetime to this component. The
      // controller keeps the legacy prefix; the server owns /server independently.
      options.ctx.inject(['connection'], (webCtx) => {
        if (stopped) return
        let disposers
        try {
          disposers = registerHostApi({
            ctx: webCtx,
            prefix: SERVER_API_PREFIX,
            logger: { info: (message) => log(message), warn: (message) => log(`warning: ${message}`) },
            facade: {
              state: async () => ({ mode: 'guest', guest: service.status(), relays: cfg.relayUrls }),
              termsStatus: () => service.termsStatus(),
              acceptTerms: () => service.acceptTerms(),
              join: (uri) => service.join(uri),
              joinWithCode: (request) => service.joinWithCode(request),
            },
          })
        } catch (error) {
          state.lastError = String(error?.message ?? error)
          log(`server Web API unavailable: ${state.lastError}`)
          return
        }
        webCtx.effect(() => () => {
          for (const dispose of disposers) dispose()
        }, 'native-env-v2:server-web-api')
      })
      // Resume a previously joined invite, so a guest runtime restart does not
      // require the operator to paste the token again while it is still valid.
      const restored = await service.restore()
      if (stopped) return
      if (restored !== undefined) {
        log('resuming the previously joined invite')
        await service.join(restored, { remember: false }).catch((error) => log(`could not resume the invite: ${String(error?.message ?? error)}`))
        return
      }
      if (cfg.invite !== undefined) {
        // A non-interactive deployment can be handed the invite in its config. It
        // is a credential, so this is documented as the less preferred route.
        await service.join(cfg.invite).catch((error) => log(`could not join the configured invite: ${String(error?.message ?? error)}`))
        return
      }
      log('waiting for an invite; run /env connect <invite-uri> on this machine to pair')
    },
  ).catch((error) => {
    state.lastError = String(error?.message ?? error)
    stopped = true
    detach('server initialization failed')
    log(`pairing could not start: ${state.lastError}`)
    void Promise.resolve().then(() => guest?.stop()).catch(() => {})
  })

  return {
    state,
    get current() {
      return current
    },
    stop() {
      stopped = true
      detach('the plugin was unmounted')
      void Promise.resolve().then(() => guest?.stop()).catch((error) => log(`pairing could not stop: ${String(error?.message ?? error)}`))
    },
    /** The pairing service, once it is up. */
    get service() {
      return guest
    },
  }
}

/**
 * Register the guest's human commands.
 *
 * Registered defensively: the `env` profile that the ssh transport runs is
 * `dsh-base` plus this plugin, and `commands` may not be mounted there. Without
 * the service the guest still works; it simply has no way to be told an invite
 * except through the config or the restored credential.
 *
 * @param options.ctx - the plugin context.
 * @param options.cfg - the resolved config.
 * @param options.transport - the transport shim.
 * @param options.log - the stderr logger.
 */
function registerGuestCommands(options) {
  const { ctx, cfg, transport, log } = options
  const commands = ctx.get?.('commands')
  if (commands === undefined) return

  const service = () => transport.service

  const register = (primary, fallback, definition) => {
    try {
      commands.register({ ...definition, name: primary })
    } catch {
      try {
        commands.register({ ...definition, name: fallback })
      } catch (error) {
        log(`could not register /${primary}: ${String(error?.message ?? error)}`)
      }
    }
  }

  register('env', 'native-env-guest-v2', {
    description: 'Pairing: /env connect <invite-uri> | <device-code> <password>, /env status, /env disconnect, /env terms [accept]',
    input: { hint: 'connect <invite-uri> | connect <device-code> <password> | status | disconnect | terms [accept]' },
    handler: async (invocation) => {
      const raw = invocation.rawInput.trim()
      const [subcommand, ...rest] = raw.split(/\s+/).filter((part) => part.length > 0)
      try {
        const guest = service()
        if (guest === undefined) return { kind: 'error', text: 'the pairing service is not ready yet; try again in a moment' }
        switch (subcommand) {
          case 'connect': {
            const rest2 = rest.join(' ').trim()
            if (rest2.length === 0) {
              return {
                kind: 'error',
                text: [
                  'usage: /env connect <invite-uri>',
                  '       /env connect <device-code> <password>',
                  '',
                  'The URI form comes from the host\'s QR code / token. The code form is the device code and',
                  'temporary password shown on the host — and it needs `relayUrls` set on THIS machine, because',
                  'a nine-digit code cannot name a relay.',
                ].join('\n'),
              }
            }
            // Two values means a typed card; anything else is treated as a URI. Splitting
            // on whitespace rather than counting arguments keeps `123 456 789 pw` working,
            // since the grouped code contains spaces of its own.
            const tokens = rest.filter((part) => part.length > 0)
            const isUri = rest2.startsWith('dsh+env://')
            if (!isUri && tokens.length >= 2) {
              const joined = await guest.joinWithCode({ deviceCode: tokens[0], password: tokens.slice(1).join('') })
              return {
                kind: 'success',
                text: `pairing as device ${joined.status.invite.deviceCode}; connecting…\nCompare the short code ${joined.status.sas ?? '(pending)'} with the host once connected.`,
              }
            }
            const result = await guest.join(rest2)
            return {
              kind: 'success',
              text: `joined invite ${result.status.invite.inviteIdPrefix} on ${result.status.invite.relay}; connecting…`,
            }
          }
          case undefined:
          case 'status': {
            const status = guest.status()
            return {
              kind: 'success',
              text: [
                `fingerprint: ${status.fingerprint}`,
                `connected: ${status.connected ? 'yes' : 'no'}${status.connectedSince === undefined ? '' : ` since ${new Date(status.connectedSince).toISOString()}`}`,
                `peer: ${status.peer === undefined ? '(none)' : `${status.peer.fingerprint}${status.peer.label === undefined ? '' : ` — ${status.peer.label}`}`}`,
                // The one line a human must act on for a typed pairing.
                `short code: ${status.sas ?? '(none yet)'}${status.connected ? (status.pinned ? ' (host identity pinned by the invite)' : ' — COMPARE this with the host; a typed pairing cannot verify the host for you') : ''}`,
                `pairing: ${status.invite === null ? '(none)' : (status.invite.mode === 'code' ? `device ${status.invite.deviceCode}` : `invite ${status.invite.inviteIdPrefix}`) + ` on ${status.invite.relay}, expires ${new Date(status.invite.expiresAt).toISOString()}`}`,
                `attempts: ${String(status.attempts)}`,
                `last error: ${status.lastError ?? '(none)'}`,
                `disclaimer: ${status.terms.accepted ? 'accepted' : `NOT accepted (${status.terms.reason})`}`,
              ].join('\n'),
            }
          }
          case 'disconnect': {
            // `forget: true` is the difference between "stop reconnecting" (what a
            // plugin unmount does) and "I am done with this host", which is what a
            // human typing /env disconnect means.
            await guest.stop({ forget: true })
            return { kind: 'success', text: 'disconnected and the stored invite was forgotten' }
          }
          case 'terms': {
            if (rest[0] === 'accept') {
              const record = guest.acceptTerms()
              return { kind: 'success', text: `disclaimer version ${String(record.termsVersion)} accepted at ${new Date(record.acceptedAt).toISOString()}` }
            }
            const status = guest.termsStatus()
            return {
              kind: 'success',
              text: [
                renderTermsText({ locale: rest[0] === 'zh' ? 'zh' : '' }),
                '',
                status.accepted ? 'Already accepted on this machine.' : `NOT accepted: ${status.reason}. Accept it with /env terms accept.`,
              ].join('\n'),
            }
          }
          default:
            return { kind: 'error', text: `unknown /env subcommand ${JSON.stringify(subcommand)}; try connect, status, disconnect or terms` }
        }
      } catch (error) {
        return { kind: 'error', text: String(error?.message ?? error) }
      }
    },
  })

  log(`guest transport=${cfg.transport}; /env connect is available`)
}
