/**
 * dsh-native-env / host — the plugin entry point.
 *
 * Mounted in the LOCAL profile. It owns the peer clients, the two human commands
 * (`/enter`, `/exit`), the model-facing tools (`env_enter`, `env_exit`,
 * `env_status`, `env_invite`), the registry of live takeovers — one `SessionBinding`
 * per agent that has entered a peer — and, since this revision, the PAIRING
 * service that replaces the hand-written `peers:` block.
 *
 * Nothing here shadows a tool by itself: that happens in `binding.js`, and only
 * when a human runs `/enter` or the model calls `env_enter`. Entering is an
 * explicit act because a takeover moves the session's filesystem and shell onto
 * another machine, and the local approval and sandbox policy stop applying to the
 * tools it moves.
 *
 * Two transports coexist:
 *
 *   - **`pairing`** (the default): peers appear at runtime because another machine
 *     authenticated with an invite. No address, port, peer name or token file is
 *     configured; a peer row is created the moment a guest arrives.
 *   - **`legacy`**: the `peers:` / `listen` / `tokenFile` shape, kept working
 *     unchanged for deployments that already have it (an SSH spawn, a LAN dial-in).
 *
 * Both converge on the same `EnvClient`, so a session cannot tell which one it is
 * talking to — which is why `binding.js` needed no change for pairing at all.
 *
 * Mount it in a profile patch:
 *
 *   - insert:
 *       - id: native-env
 *         name: 'C:/dsh-plugins/dsh-native-env-v2'
 *         config:
 *           mode: pairing
 *           relayUrls: ['wss://relay.example.test/v2/relay']
 *
 * Defaults are inert on purpose: no relay means no invite can be created, no
 * `peers` means nothing is exposed, and no invite means no pairing connection is
 * ever accepted.
 *
 * @module dsh-native-env/host
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { SessionBinding } from './binding.js'
import { EnvHub } from './hub.js'
import { PairingHost } from './pairing-host.js'
import { SecretStore, StateStore, resolveDshHome } from './state-store.js'
import { registerHostApi } from './host-api.js'
import { renderTermsText } from './terms.js'
import { defineTool } from './tool-def.js'
import { LineWire } from './wire.js'
import { inspectLegacy } from './migration.js'

/** Stable Cordis plugin name. */
export const name = 'native-env-v2'

/** The registry is required; `commands` and `connection` are used when present. */
export const inject = ['tools']
export const provide = ['nativeEnvV2Controller']

/**
 * The row's configuration schema.
 *
 * `additionalProperties` is deliberately open. The loader validates a row's
 * `config` against this schema, so a closed schema would make every EXISTING
 * deployment — whose row carries `peers`, `listen`, `allowPeers`, `tokenFile` —
 * fail to activate on upgrade. Every property that is known is typed here for the
 * configuration UI; unknown ones are passed through to the legacy resolver.
 */
export const Config = {
  type: 'object',
  additionalProperties: true,
  properties: {
    enabled: { type: 'boolean', description: 'Enable the Native Env host and its tools without removing pairing data.' },
    mode: { type: 'string', enum: ['pairing', 'legacy'], description: 'pairing (invite-based, the default) or legacy (static peers)' },
    relayUrls: {
      type: 'array',
      items: { type: 'string' },
      description: 'ws:// or wss:// relay channel bases; the first is used for new invites',
    },
    inviteTtlMs: { type: 'integer', description: 'how long a created invite stays usable' },
    requireTerms: { type: 'boolean', description: 'require the disclaimer to be accepted before pairing' },
    label: { type: 'string', description: 'how this machine introduces itself to a peer' },
    maxPeers: { type: 'integer', description: 'how many paired peers may be connected at once' },
    acceptTimeoutMs: { type: 'integer', description: 'how long one pairing handshake may take' },
    relayTimeoutMs: { type: 'integer', description: 'deadline for one relay exchange' },
    listen: { type: 'array', items: { type: 'string' } },
    port: { type: 'integer' },
    allowPeers: { type: 'array', items: { type: 'string' } },
    tokenFile: { type: 'string' },
    tokenEnv: { type: 'string' },
    callTimeoutMs: { type: 'integer' },
    maxMessageBytes: { type: 'integer', description: 'maximum serialized RPC message size' },
    handshakeTimeoutMs: { type: 'integer' },
    migration: { type: 'boolean', description: 'show legacy dsh-native-env migration information in status' },
    fullAccess: { type: 'boolean', description: 'allow every serializable remote tool except the control tools required to leave this environment' },
    exclude: { type: 'array' },
    peers: { type: 'array' },
  },
  /**
   * Standard Schema v1 surface.
   *
   * Cordis 4 validates a row's `config` through `Config['~standard'].validate(value)`
   * (`resolveConfig` in `@deepseek-ai/cordis`), so a bare JSON Schema made the row
   * fail to activate with `Cannot read properties of undefined (reading 'validate')`.
   * The JSON Schema above stays as the human/UI description; this adapter is what
   * the loader actually calls. `additionalProperties` stays open on purpose — the
   * legacy shape (`peers`, `listen`, `allowPeers`, `tokenFile`) must pass through
   * untouched, and `resolveConfig`/`resolvePeer` below already normalize every field.
   */
  '~standard': {
    version: 1,
    vendor: 'dsh-native-env-v2',
    validate(value) {
      if (value === undefined || value === null) return { value: {} }
      if (typeof value !== 'object' || Array.isArray(value)) {
        return { issues: [{ message: 'native-env config must be an object' }] }
      }
      return { value }
    },
  },
}

/** Render a value as one text block. */
const asText = (value) => [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }]

/** One permissive object schema: these outputs are status documents, not contracts. */
const STATUS_SCHEMA = { type: 'object' }

/** The default relay-free lifetime of an invite. */
const DEFAULT_INVITE_TTL_MS = 10 * 60 * 1000

/**
 * Normalize one legacy peer row.
 * @param raw - the row config.
 * @returns the resolved peer config.
 */
function resolvePeer(raw) {
  const config = raw ?? {}
  const transport = config.transport === 'ssh' ? 'ssh' : 'tcp'
  return {
    name: String(config.name ?? ''),
    label: typeof config.label === 'string' ? config.label : undefined,
    transport,
    command: typeof config.command === 'string' ? config.command : 'ssh',
    args: Array.isArray(config.args) ? config.args.map(String) : [],
    cwd: typeof config.cwd === 'string' ? config.cwd : undefined,
    listTimeoutMs: Number.isSafeInteger(config.listTimeoutMs) ? config.listTimeoutMs : 30000,
    minBackoffMs: Number.isSafeInteger(config.minBackoffMs) ? config.minBackoffMs : 1000,
    maxBackoffMs: Number.isSafeInteger(config.maxBackoffMs) ? config.maxBackoffMs : 30000,
    maxMessageBytes: Number.isSafeInteger(config.maxMessageBytes) ? config.maxMessageBytes : 4 * 1024 * 1024,
    handshakeTimeoutMs: Number.isSafeInteger(config.handshakeTimeoutMs) ? config.handshakeTimeoutMs : 10000,
  }
}

/**
 * Normalize the plugin config.
 *
 * `mode` defaults to `pairing` unless the row declares legacy peers, because a
 * deployment that already has `peers` is asking for the old behaviour and would
 * otherwise have its peers ignored — a silent regression, which is the worst kind.
 *
 * @param raw - the row config.
 * @returns the resolved config.
 */
function resolveConfig(raw) {
  const config = raw ?? {}
  const legacyPeers = Array.isArray(config.peers) ? config.peers.map(resolvePeer).filter((peer) => peer.name.length > 0) : []
  const declaredMode = config.mode === 'legacy' || config.mode === 'pairing' ? config.mode : undefined
  const mode = declaredMode ?? (legacyPeers.length > 0 ? 'legacy' : 'pairing')
  const enabledFile = join(process.env.DSH_HOME ?? resolveDshHome(), 'native-env-v2.enabled')
  let persistedEnabled
  try { persistedEnabled = readFileSync(enabledFile, 'utf8').trim() } catch {}
  return {
    enabled: persistedEnabled === '0' ? false : persistedEnabled === '1' ? true : config.enabled !== false,
    mode,
    relayUrls: Array.isArray(config.relayUrls) ? config.relayUrls.filter((entry) => typeof entry === 'string' && entry.length > 0) : [],
    inviteTtlMs: Number.isSafeInteger(config.inviteTtlMs) ? config.inviteTtlMs : DEFAULT_INVITE_TTL_MS,
    requireTerms: config.requireTerms !== false,
    label: typeof config.label === 'string' && config.label.length > 0 ? config.label : undefined,
    maxPeers: Number.isSafeInteger(config.maxPeers) ? config.maxPeers : 8,
    acceptTimeoutMs: Number.isSafeInteger(config.acceptTimeoutMs) ? config.acceptTimeoutMs : 5 * 60 * 1000,
    relayTimeoutMs: Number.isSafeInteger(config.relayTimeoutMs) ? config.relayTimeoutMs : 15000,
    listen: Array.isArray(config.listen) ? config.listen.filter((entry) => typeof entry === 'string') : [],
    port: Number.isSafeInteger(config.port) ? config.port : 8912,
    allowPeers: Array.isArray(config.allowPeers) ? config.allowPeers.map(String) : ['127.0.0.1/32'],
    tokenFile: typeof config.tokenFile === 'string' ? config.tokenFile : undefined,
    tokenEnv: typeof config.tokenEnv === 'string' ? config.tokenEnv : undefined,
    callTimeoutMs: Number.isSafeInteger(config.callTimeoutMs) ? config.callTimeoutMs : 120000,
    maxMessageBytes: Number.isSafeInteger(config.maxMessageBytes) ? config.maxMessageBytes : 4 * 1024 * 1024,
    exclude: Array.isArray(config.exclude) ? config.exclude : [],
    peers: legacyPeers,
    migration: config.migration !== false,
    fullAccess: config.fullAccess === true,
    token: undefined,
  }
}

/**
 * Read the legacy shared token. It never reaches a config file or a log line.
 * @param config - the resolved config.
 * @returns the trimmed token, or `undefined` when none is configured.
 */
function readToken(config) {
  try {
    if (config.tokenEnv !== undefined) {
      const value = process.env[config.tokenEnv]
      if (typeof value === 'string' && value.length > 0) return value.trim()
    }
    if (config.tokenFile !== undefined) return readFileSync(config.tokenFile, 'utf8').trim()
  } catch (error) {
    return { error: String(error?.message ?? error) }
  }
  return undefined
}

/** Render the `/enter` receipt for a human or for the model. */
function formatReceipt(receipt, verb) {
  const lines = []
  lines.push(`${verb} ${receipt.peer}${receipt.label === undefined ? '' : ` (${receipt.label})`} — ${receipt.shadowedCount} tool(s) now run remotely.`)
  if (receipt.cwd !== undefined) lines.push(`remote cwd: ${receipt.cwd}${receipt.platform === undefined ? '' : ` [${receipt.platform}]`}`)
  if (receipt.anchor?.id != null) lines.push(`remote anchor agent: ${receipt.anchor.id}`)
  if (receipt.anchor?.unavailable !== undefined) {
    lines.push(`WARNING: the remote anchor agent is unavailable (${receipt.anchor.unavailable}); the takeover is running`)
    lines.push('         in DEGRADED mode, so per-agent remote tools and guards do not apply.')
  }
  lines.push(`shadowed: ${receipt.shadowed.join(', ') || '(none)'}`)
  if (receipt.skippedCount > 0) {
    lines.push(`stayed local (${receipt.skippedCount}):`)
    for (const entry of receipt.skipped) lines.push(`  - ${entry.name}: ${entry.reason}`)
  }
  if (receipt.promptSection === false) lines.push('note: the remote-environment prompt section could not be installed.')
  if (receipt.notice !== undefined) lines.push(receipt.notice)
  return lines.join('\n')
}

/**
 * Mount the host half.
 * @param ctx - the plugin context.
 * @param config - the row config.
 */
export function apply(ctx, config) {
  const cfg = resolveConfig(config)
  const configuredRelayUrls = [...cfg.relayUrls]
  const publicState = { enabled: false, phase: 'off', relay: null, error: null, startedAt: null }
  if (!cfg.enabled) ctx.logger?.info?.('native-env: disabled flag recorded; UI remains available to re-enable it')
  const logger = {
    info: (message) => ctx.logger?.info?.(`native-env: ${message}`),
    warn: (message) => ctx.logger?.warn?.(`native-env: ${message}`),
  }

  const token = readToken(cfg)
  if (typeof token === 'object' && token !== null) {
    logger.warn(`cannot read the shared token (${token.error}); no dial-in peer can be authenticated`)
  } else {
    cfg.token = token
  }

  /** agent -> SessionBinding */
  const bindings = new Map()

  /** Reinstall active session shadows after an access-policy change. */
  async function refreshBindings() {
    const active = [...bindings.values()]
    // Revoke queued calls immediately, before the first network round trip.
    for (const binding of active) binding.config.fullAccess = cfg.fullAccess === true
    await Promise.all(active.map(async (binding) => {
      try {
        await binding.refresh()
      } catch (error) {
        logger.warn(`refreshing ${binding.peer} after policy change failed: ${String(error?.message ?? error)}`)
      }
    }))
  }

  /** Runtime controls used by the optional public/full-access components. */
  const controller = {
    getFullAccess: () => cfg.fullAccess === true,
    async setFullAccess(enabled) {
      const next = enabled === true
      if (cfg.fullAccess === next) return next
      cfg.fullAccess = next
      await refreshBindings()
      logger.info(`full-access policy ${next ? 'enabled' : 'disabled'}; active sessions were refreshed`)
      return next
    },
    setPublicState(patch = {}) {
      Object.assign(publicState, patch)
      return { ...publicState }
    },
    setPublicRelay(url, details = {}) {
      if (typeof url !== 'string' || url.length === 0) throw new Error('native-env: public relay URL must be a non-empty string')
      cfg.relayUrls = [url]
      if (Number.isInteger(details.localPort) && details.localPort > 0 && details.localPort <= 65535) {
        cfg.publicRelay = { advertised: url, local: `ws://127.0.0.1:${details.localPort}/v2/relay` }
      }
      Object.assign(publicState, { enabled: true, phase: 'ready', relay: url, error: null, startedAt: publicState.startedAt ?? Date.now(), ...details })
      logger.info(`public relay ready at ${url}`)
      return { ...publicState }
    },
    clearPublicRelay(details = {}) {
      const previous = publicState.relay
      if (previous && pairing) {
        for (const slot of [...pairing.slots.values()]) {
          if (slot.invite.relay === previous) pairing.revoke(slot.invite.inviteId)
        }
      }
      cfg.relayUrls = [...configuredRelayUrls]
      delete cfg.publicRelay
      Object.assign(publicState, { enabled: false, phase: 'off', relay: null, publicUrl: null, localPort: null, error: null, startedAt: null, ...details })
      logger.info('public relay disabled; configured private relay URLs restored')
      return { ...publicState }
    },
    publicState: () => ({ ...publicState }),
  }
  // The optional rows are loaded by the same Cordis root. They inject this
  // service only when their own bundle switch is on, so installing them does not
  // change the default controller behaviour.
  ctx.provide('nativeEnvV2Controller', controller)

  const hub = new EnvHub({
    config: cfg,
    logger,
    onToolsChanged: (client) => {
      // Only ever reached from the peer's own `env/tools-changed` notification;
      // `EnvClient.list()` deliberately does not notify, or this would recurse.
      for (const binding of bindings.values()) {
        if (binding.client !== client) continue
        if (!client.connected) {
          for (const [agent, stale] of bindings) {
            if (stale !== binding) continue
            bindings.delete(agent)
            stale.dispose()
          }
          logger.warn(`peer ${client.name} went offline; removed remote shadows and requires env_enter after reconnect`)
          continue
        }
        binding.refresh().catch((error) => logger.warn(`refreshing ${client.name} failed: ${String(error?.message ?? error)}`))
      }
    },
  })

  /** Resolve a peer by name, or the only configured one. */
  function resolvePeerOrThrow(requested) {
    if (typeof requested === 'string' && requested.length > 0) {
      const client = hub.get(requested)
      if (client === undefined) {
        throw new Error(`native-env: unknown peer "${requested}"; known peers: ${hub.list().map((c) => c.name).join(', ') || '(none)'}`)
      }
      return client
    }
    const peers = hub.list()
    if (peers.length === 1) return peers[0]
    throw new Error(`native-env: "peer" is required when several peers are configured; known peers: ${peers.map((c) => c.name).join(', ')}`)
  }

  /** Enter a peer for one agent. Idempotent for the same peer. */
  async function enter(agent, requested) {
    const client = resolvePeerOrThrow(requested)
    if (!client.connected) {
      throw new Error(
        `native-env: peer "${client.name}" is not connected` +
          (client.disconnectReason === undefined ? '' : ` (${client.disconnectReason})`) +
          '; nothing was changed — this session is still running locally',
      )
    }

    const existing = bindings.get(agent)
    if (existing !== undefined && existing.client === client) return existing.refresh()

    const binding = new SessionBinding({
      agent,
      client,
      config: { callTimeoutMs: cfg.callTimeoutMs, exclude: cfg.exclude, fullAccess: cfg.fullAccess === true },
      logger,
    })
    try {
      const receipt = await binding.install()
      if (existing !== undefined) existing.dispose()
      bindings.set(agent, binding)
      logger.info(`${client.name}: ${receipt.shadowedCount} tool(s) shadowed for one session`)
      return receipt
    } catch (error) {
      binding.dispose()
      throw error
    }
  }

  /** Leave the remote environment for one agent. */
  function exit(agent) {
    const binding = bindings.get(agent)
    if (binding === undefined) return { peer: null, shadowed: [], shadowedCount: 0, skipped: [], skippedCount: 0, released: true }
    bindings.delete(agent)
    const receipt = binding.receipt()
    binding.dispose()
    logger.info(`${binding.peer}: takeover released; local tools restored`)
    return { ...receipt, released: true }
  }

  // ── pairing ────────────────────────────────────────────────────────────────

  const state = new StateStore({ file: join(resolveDshHome(), 'native-env-v2-state.json'), logger })
  const secrets = new SecretStore({ credentials: ctx.get?.('credentials'), namespace: 'native-env-v2', logger })
  /** @type {PairingHost | undefined} */
  let pairing

  if (cfg.mode === 'pairing') {
    const identityRecord = { config: cfg, logger, secrets, state, label: cfg.label ?? 'dsh host' }
    PairingHost.load(identityRecord)
      .then((host) => {
        pairing = host
        host.on('peer-adopted', ({ peerName, peer, invite, stream }) => {
          // The pairing transport produces a stream; everything downstream is the
          // ordinary env wire, which is the whole reason no other file changed.
          const client = hub.adopt({
            name: peerName,
            label: peer.label === undefined || peer.label.length === 0 ? `${peerName} (${peer.platform || 'unknown'})` : peer.label,
            transport: 'relay',
            minBackoffMs: 1000,
            maxBackoffMs: 30000,
            listTimeoutMs: 30000,
          })
          // Carried on the client so `env_status` and the Web UI can show the value a
          // human compares. For a TYPED pairing it is the only thing that can reveal a
          // relay in the middle, and hiding it would leave the mode with no check at
          // all.
          client.pairingSas = peer.sas
          client.pairingPinned = peer.pinned === true
          client.attach({ wire: new LineWire(stream, stream, { maxMessageBytes: client.config.maxMessageBytes }), remoteAddress: `relay:${invite.inviteId.slice(0, 8)}` })
          logger.info(
            peer.pinned === true
              ? `paired peer ${peerName} is connected (host identity pinned by the invite)`
              : `paired peer ${peerName} is connected by device code — short code ${String(peer.sas)}; compare it with the guest before trusting this pairing`,
          )
        })
        host.on('peer-lost', ({ peerName }) => {
          const client = hub.get(peerName)
          // Fail closed: disconnect removes per-session shadows. A reconnect
          // restores only transport and the directory; env_enter is required again.
          client?.detach('the pairing connection closed')
        })
        logger.info(`pairing ready; this host's fingerprint is ${host.fingerprint}`)
      })
      .catch((error) => logger.warn(`pairing could not start: ${String(error?.message ?? error)}`))
  } else {
    logger.info('running in legacy mode: peers come from the profile config')
  }

  /** A pairing-facade operation that fails clearly when pairing is not up yet. */
  function requirePairing() {
    if (pairing === undefined) {
      throw new Error('native-env: the pairing service is not ready yet (or `mode` is not `pairing`); try again in a moment')
    }
    return pairing
  }

  /** The projection the Web API serves. */
  async function pairingState() {
    const peers = []
    for (const client of hub.list()) {
      const status = await client.status()
      peers.push({
        name: status.name,
        label: status.label,
        transport: status.transport,
        connected: status.connected,
        connectedSince: status.connectedSince,
        platform: status.platform,
        cwd: status.cwd,
        toolCount: status.toolCount,
        disconnectReason: status.disconnectReason,
        anchor: status.anchor === null || status.anchor === undefined ? null : { id: status.anchor.id ?? null, unavailable: status.anchor.unavailable },
        // What a human compares for a typed pairing. Harmless to expose: it is derived
        // from the session secret and says nothing an observer of this document could
        // use, while its ABSENCE would leave the user with no way to check.
        sas: client.pairingSas,
        pinned: client.pairingPinned === true,
      })
    }
    return {
      enabled: cfg.enabled,
      fullAccess: cfg.fullAccess === true,
      public: { ...publicState },
      mode: cfg.mode,
      host: pairing === undefined ? null : { fingerprint: pairing.fingerprint, label: pairing.label, relays: cfg.relayUrls },
      terms: pairing?.termsStatus() ?? { accepted: cfg.requireTerms === false, reason: 'pairing is not active' },
      invites: pairing?.invites() ?? [],
      peers,
      listening: hub.status,
      migration: cfg.migration ? inspectLegacy() : { found: false, disabled: true },
    }
  }

  /** Render the invite URI the way a command receipt should. */
  function formatInvite(created) {
    return [
      `invite ${created.status.inviteIdPrefix} created on ${created.status.relay}`,
      `host fingerprint: ${created.status.fingerprint}`,
      `expires: ${new Date(created.status.expiresAt).toLocaleString()}`,
      '',
      'Give this to the other machine (paste it into /env connect there, or scan the QR in the Native Env settings page):',
      created.uri,
      '',
      'The token above is a credential: it authorises a pairing until it expires.',
    ].join('\n')
  }

  /**
   * Render the device card the way a command receipt should — the shape people know
   * from remote-desktop software.
   * @param created - the `{ card, status }` from `createDeviceCard`.
   * @returns the text.
   */
  function formatDeviceCardText(created) {
    return [
      'Device card — type these two values on the other machine:',
      '',
      `    device code    ${created.card.displayCode}`,
      `    password       ${created.card.displayPassword}`,
      '',
      `This host's identity: ${created.card.hostFingerprint}`,
      `expires: ${new Date(created.card.expiresAt).toLocaleString()}`,
      `on: /env connect ${created.card.displayCode} ${created.card.displayPassword}`,
      '',
      'The code stays the same on this machine; refresh the password with `/env card refresh`.',
      'The password is a credential: it authorises a pairing until it expires.',
      '',
      'NOTE: a typed pairing cannot pin this host\'s identity the way a QR invite does.',
      'After connecting, compare the short code shown on both machines — a mismatch means',
      'something is sitting in the middle.',
    ].join('\n')
  }

  // ── model-facing tools ─────────────────────────────────────────────────────

  ctx.tools.register(
    defineTool({
      name: 'env_enter',
      description:
        'Enter a connected remote DSH peer\'s environment for THIS session. Afterwards the session\'s read, write, ' +
        'edit, glob, grep and pwsh execute on the REMOTE machine as a real agent of that runtime, while keeping ' +
        'their names and argument schemas; every other session is unaffected. By default UI, orchestration, ' +
        'attachment and screen tools stay local. The optional full-access component also permits those tools; ' +
        'the receipt lists precisely which tools moved and which were skipped. The remote ' +
        'runtime\'s own policy does. Call env_exit to return.',
      parameters: {
        type: 'object',
        additionalProperties: false,
        properties: {
          peer: { type: 'string', description: 'Peer name from env_status. Optional when exactly one peer is configured.' },
        },
      },
      output: { schema: STATUS_SCHEMA, render: (_args, value) => asText(formatReceipt(value, 'entered')) },
      timeoutMs: 120000,
      async execute(args, exec) {
        const agent = exec?.agent
        if (agent === undefined) throw new Error('env_enter: this tool needs a session (no agent scope was supplied)')
        return enter(agent, args.peer)
      },
    }),
  )

  ctx.tools.register(
    defineTool({
      name: 'env_exit',
      description:
        'Leave the remote environment this session entered and restore the local tools. Safe to call when no ' +
        'takeover is active. The remote machine is not modified by leaving.',
      parameters: { type: 'object', additionalProperties: false, properties: {} },
      output: { schema: STATUS_SCHEMA, render: (_args, value) => asText(formatReceipt(value, 'left')) },
      timeoutMs: 30000,
      async execute(_args, exec) {
        const agent = exec?.agent
        if (agent === undefined) throw new Error('env_exit: this tool needs a session (no agent scope was supplied)')
        return exit(agent)
      },
    }),
  )

  ctx.tools.register(
    defineTool({
      name: 'env_status',
      description:
        'Report the remote peers: which are connected and since when, the remote anchor agent, the remote platform ' +
        'and working directory, how many tools each exposes, which peer THIS session has entered, the listener ' +
        'state, and — in pairing mode — this host\'s fingerprint, the live invites, and whether the pairing ' +
        'disclaimer has been accepted. Read-only. Call it before env_enter when you do not know a peer name, and ' +
        'after a failure to see whether the peer or the listener is down.',
      parameters: { type: 'object', additionalProperties: false, properties: {} },
      output: { schema: STATUS_SCHEMA, render: (_args, value) => asText(value) },
      isConcurrencySafe: () => true,
      timeoutMs: 60000,
      async execute(_args, exec) {
        const peers = []
        for (const client of hub.list()) peers.push(await client.status())
        const current = exec?.agent === undefined ? undefined : bindings.get(exec.agent)
        return {
          mode: cfg.mode,
          fullAccess: cfg.fullAccess === true,
          public: { ...publicState },
          listening: hub.status,
          pairing: await pairingState(),
          peers,
          thisSession: current === undefined ? null : current.receipt(),
        }
      },
    }),
  )

  ctx.tools.register(
    defineTool({
      name: 'env_invite',
      description:
        'Create a pairing invite on this host so another machine can connect by scanning a QR code or pasting a ' +
        'token. Requires the pairing disclaimer to have been accepted on this machine (a human action). The ' +
        'invite URI itself is deliberately NOT returned to the model: it is a credential, and returning it would ' +
        'write it into the session log. The human reads it with /env invite or in the Native Env settings page. ' +
        'Use this when the user asks to connect a new machine.',
      parameters: { type: 'object', additionalProperties: false, properties: {} },
      output: { schema: STATUS_SCHEMA, render: (_args, value) => asText(value) },
      timeoutMs: 30000,
      async execute() {
        const created = await requirePairing().createInvite()
        return {
          created: true,
          invite: created.status,
          notice:
            'The invite URI is a credential and was NOT returned here. Run /env invite on this machine, or open ' +
            'Settings → Plugins → Native Env, to see the QR code and the token to copy.',
        }
      },
    }),
  )

  // ── human commands ─────────────────────────────────────────────────────────

  const commands = ctx.get('commands')
  if (commands === undefined) {
    logger.warn('the `commands` service is not mounted in this profile; /enter and /exit are unavailable (env_enter still works)')
  } else {
    const register = (primary, fallback, definition) => {
      try {
        return commands.register({ ...definition, name: primary })
      } catch (error) {
        logger.warn(`/${primary} is already taken (${String(error?.message ?? error)}); registering /${fallback} instead`)
        return commands.register({ ...definition, name: fallback })
      }
    }

    register('enter', 'env-enter', {
      description: 'Enter a remote DSH peer\'s environment in this session (native tools then run on that machine)',
      input: { hint: 'peer name, e.g. guest-ab12cd34' },
      handler: async (invocation) => {
        try {
          const receipt = await enter(invocation.agent, invocation.rawInput.trim())
          return { kind: 'success', text: formatReceipt(receipt, 'entered') }
        } catch (error) {
          return { kind: 'error', text: String(error?.message ?? error) }
        }
      },
    })

    register('exit', 'env-exit', {
      description: 'Leave the remote environment and restore this session\'s local tools',
      handler: async (invocation) => {
        try {
          return { kind: 'success', text: formatReceipt(exit(invocation.agent), 'left') }
        } catch (error) {
          return { kind: 'error', text: String(error?.message ?? error) }
        }
      },
    })

    register('env', 'native-env', {
      description: 'Pairing: /env invite, /env peers, /env terms [accept], /env revoke <invite|peer>',
      input: { hint: 'invite | peers | terms [accept] | revoke <invite-or-peer>' },
      handler: async (invocation) => {
        const [subcommand, ...rest] = invocation.rawInput.trim().split(/\s+/).filter((part) => part.length > 0)
        try {
          switch (subcommand) {
            case undefined:
            case 'status': {
              const value = await pairingState()
              return { kind: 'success', text: JSON.stringify(value, null, 2) }
            }
            case 'invite': {
              const created = await requirePairing().createInvite()
              return { kind: 'success', text: formatInvite(created) }
            }
            case 'card': {
              // The remote-desktop shape: a stable device code on this screen, and a
              // temporary password the other machine types. `rest[0] === 'refresh'`
              // keeps the code and mints a new password, which is what makes the card
              // safe to leave on screen.
              const created = await requirePairing().createDeviceCard({ refresh: rest[0] === 'refresh' })
              return { kind: 'success', text: formatDeviceCardText(created) }
            }
            case 'peers': {
              const value = await pairingState()
              const lines = value.peers.map(
                (peer) =>
                  `${peer.connected ? 'connected' : 'offline'}  ${peer.name}${peer.label === undefined ? '' : ` — ${peer.label}`}` +
                  `${peer.toolCount === undefined ? '' : ` (${String(peer.toolCount)} tools)`}`,
              )
              return {
                kind: 'success',
                text: [`mode: ${value.mode}`, `fingerprint: ${value.host?.fingerprint ?? '(pairing inactive)'}`, ...lines].join('\n'),
              }
            }
            case 'terms': {
              if (rest[0] === 'accept') {
                const record = requirePairing().acceptTerms('host')
                return { kind: 'success', text: `disclaimer version ${String(record.termsVersion)} accepted at ${new Date(record.acceptedAt).toISOString()}` }
              }
              if (rest[0] === 'reject') {
                return { kind: 'success', text: 'Nothing was recorded. Pairing stays blocked until the disclaimer is accepted.' }
              }
              const status = pairing?.termsStatus() ?? { accepted: false, reason: 'pairing is not active' }
              return {
                kind: 'success',
                text: [
                  renderTermsText({ locale: rest[0] === 'zh' ? 'zh' : '' }),
                  '',
                  status.accepted
                    ? `Already accepted (recorded acceptance: ${status.reason ?? 'current version'}).`
                    : `NOT accepted: ${status.reason}. Accept it with /env terms accept.`,
                ].join('\n'),
              }
            }
            case 'revoke': {
              const target = rest[0]
              if (target === undefined) return { kind: 'error', text: 'usage: /env revoke <invite-id-prefix|peer-name>' }
              const stoppedInvites = requirePairing().revoke(target)
              const releasedPeer = hub.release(target)
              return {
                kind: 'success',
                text: `stopped ${String(stoppedInvites)} invite(s); released peer: ${releasedPeer ? 'yes' : 'no'}`,
              }
            }
            default:
              return { kind: 'error', text: `unknown /env subcommand ${JSON.stringify(subcommand)}; try invite, peers, terms or revoke` }
          }
        } catch (error) {
          return { kind: 'error', text: String(error?.message ?? error) }
        }
      },
    })
  }

  // ── Web API ────────────────────────────────────────────────────────────────

  // The Web connection may activate after this tools-only controller. Register
  // routes in its injected scope instead of permanently missing them at boot.
  ctx.inject(['connection'], (webCtx) => {
    const apiDisposers = registerHostApi({
    ctx: webCtx,
    logger,
    facade: {
      state: pairingState,
      setEnabled: async (enabled) => {
        const target = join(process.env.DSH_HOME ?? resolveDshHome(), 'native-env-v2.enabled')
        writeFileSync(target, enabled ? '1\n' : '0\n', 'utf8')
      },
      termsStatus: () => pairing?.termsStatus() ?? { accepted: cfg.requireTerms === false, reason: 'pairing is not active' },
      acceptTerms: (role) => requirePairing().acceptTerms(role === 'guest' ? 'guest' : 'host'),
      createInvite: (options) => requirePairing().createInvite(options),
      createDeviceCard: (options) => requirePairing().createDeviceCard(options),
      revokeInvite: (inviteId) => requirePairing().revoke(String(inviteId ?? '')),
      revokePeer: async (peer) => hub.release(String(peer ?? '')),
      inviteSvg: (inviteId) => pairing?.svgFor(inviteId),
    },
    })
    webCtx.effect(() => () => {
      for (const dispose of apiDisposers) dispose()
    }, 'native-env-v2:web-api')
  })

  // ── lifecycle ──────────────────────────────────────────────────────────────

  // A disposed agent must not leave its shadows behind: the disposers belong to
  // the agent's scope, but the map entry does not.
  ctx.on('agent/disposed', ({ agent }) => {
    const binding = bindings.get(agent)
    if (binding === undefined) return
    bindings.delete(agent)
    binding.dispose()
  })

  // Binding a port must never block boot; failures land in `env_status`.
  const started = hub.start()
  started.then(
    (status) => {
      if (status.listening.length > 0) {
        logger.info(`listening on ${status.listening.map((entry) => `${entry.address}:${entry.port}`).join(', ')}`)
      }
      for (const failure of status.failures) logger.warn(`listener not started for ${failure.address}: ${failure.reason}`)
      if (cfg.mode === 'legacy' && cfg.peers.length === 0) logger.info('no peers declared; nothing will be exposed')
    },
    (error) => logger.warn(`hub start failed: ${String(error?.message ?? error)}`),
  )

  ctx.effect(
    () => () => {
      for (const binding of bindings.values()) binding.dispose()
      bindings.clear()
      void pairing?.stop()
      void started.then(() => hub.stop())
    },
    'native-env-v2:lifecycle',
  )
}
