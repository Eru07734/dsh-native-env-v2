/**
 * dsh-native-env / binding — ONE agent's takeover of ONE remote peer.
 *
 * This is the whole point of the plugin. `install()` registers a same-named tool
 * for every tool the remote exposes (minus the denylist) into the CALLING AGENT's
 * scope, and a scoped registration shadows the same-named global one — so that
 * session's `read`/`write`/`edit`/`glob`/`grep`/`pwsh` keep their names, their
 * descriptions and their argument schemas, but execute on the remote machine.
 * Every other session in the process is untouched.
 *
 * Registration goes through `agent.ctx.tools.register(def)` DIRECTLY, not through
 * `ctx.inject(['tools'], …)`. Both work, but the direct form returns the exact
 * disposer, needs no child fiber, and is the form the Phase 0 spike proved:
 * `docs/00-phase0-findings.md` records that agent A resolved the shadow while
 * agent B still resolved the global, and that disposing restored it.
 *
 * Two deliberate choices:
 *
 *   - **`content` is forwarded verbatim** and the shadow declares a permissive
 *     object output with `render: (_args, value) => value.content`. The remote
 *     already rendered its own result through its own `finalizeContent`, so
 *     re-rendering here would be a second, different opinion about the same call.
 *   - **A failed remote call THROWS.** `defineTool` turns that into the loop's
 *     ordinary `Error: <message>` result, which is how a tool failure is supposed
 *     to read; returning a success-shaped value would hide it.
 *
 * @module dsh-native-env/binding
 */

import { denialReason } from './env-protocol.js'
import { defineTool } from './tool-def.js'

/**
 * Tool names whose shadows may overlap with siblings.
 *
 * Matched by exact name and deliberately conservative: a name that is not here
 * is scheduled exclusively, so an unrecognised remote tool can never race a
 * writer.
 */
const READ_ONLY_TOOLS = new Set([
  'read',
  'read_file',
  'read_text_file',
  'list_directory',
  'list_dir',
  'glob',
  'grep',
  'search_files',
  'file_info',
  'stat',
])

/** Flatten content blocks to text, for an error message. */
function textOf(content) {
  const blocks = Array.isArray(content) ? content : []
  const text = blocks
    .filter((block) => block?.type === 'text')
    .map((block) => block.text)
    .join('\n')
    .trim()
  return text.length > 0 ? text : '(the remote tool failed without a message)'
}

/** One agent's takeover. */
export class SessionBinding {
  /**
   * @param options.agent - the local agent whose scope is shadowed.
   * @param options.client - the `EnvClient` for the target peer.
   * @param options.config - `{ callTimeoutMs, exclude, fullAccess }`.
   * @param options.logger - optional log sink.
   */
  constructor(options) {
    this.agent = options.agent
    this.client = options.client
    this.config = options.config
    this.logger = options.logger

    /** Disposers for everything this binding registered, newest last. */
    this.disposers = []
    this.shadowed = []
    this.skipped = []
    this.installedAt = undefined
    this.promptInstalled = false
    /** Guards against re-entrant refreshes from a burst of `tools/change`. */
    this.refreshing = false
    this.generation = 0
  }

  /** @returns the peer name this binding targets. */
  get peer() {
    return this.client.name
  }

  /**
   * Build the local shadow of one remote tool.
   *
   * The schema is the REMOTE's, verbatim — that is what makes the takeover
   * invisible to the model. Only the body differs.
   *
   * @param remote - one entry from `env/list`.
   * @returns a registry-ready definition.
   */
  buildDefinition(remote) {
    const client = this.client
    const name = remote.name
    const policy = this.config
    return defineTool({
      name,
      description: remote.description,
      parameters: remote.parameters,
      output: {
        schema: { type: 'object' },
        render: (_args, value) => (Array.isArray(value?.content) ? value.content : []),
      },
      isConcurrencySafe: () => READ_ONLY_TOOLS.has(name),
      timeoutMs: this.config.callTimeoutMs,
      async execute(args, exec) {
        // Check again at execution time: a policy switch must revoke a queued
        // full-access call even while a directory refresh is awaiting the peer.
        const denied = denialReason(name, policy.exclude, { fullAccess: policy.fullAccess === true })
        if (denied !== undefined) {
          const error = new Error(`remote tool ${name} is no longer permitted: ${denied}; no local tool was executed`)
          error.code = 'REMOTE_POLICY_DENIED'
          throw error
        }
        const result = await client.call(name, args, exec?.signal)
        if (result?.isError === true) throw new Error(textOf(result.content))
        return { content: Array.isArray(result?.content) ? result.content : [] }
      },
    })
  }

  /**
   * Tell the model where it is.
   *
   * Without this the assembled prompt still describes the LOCAL working
   * directory, which would be a lie the moment the first `read` ran. Defensive:
   * a prompt section is worth having but never worth failing a takeover over, so
   * a service that will not take the section is logged and skipped.
   *
   * @returns true when the section was installed.
   */
  installPromptSection() {
    const systemPrompt = this.agent.ctx.systemPrompt
    if (systemPrompt === undefined || typeof systemPrompt.section !== 'function') return false

    let order = 500
    try {
      order = systemPrompt.getSectionOrder?.('FILE_REFERENCE') ?? 500
    } catch {
      /* an unknown section name is not a reason to skip the notice */
    }

    const localOnly = this.skipped.length > 0
      ? this.skipped.map((entry) => `${entry.name} (${entry.reason})`).join(', ')
      : '(none)'
    const lines = [
      `You are operating in a REMOTE environment: peer \`${this.peer}\`` +
        (this.client.platform === undefined ? '' : ` (${this.client.platform})`) +
        (this.client.cwd === undefined ? '' : `, working directory \`${this.client.cwd}\``) +
        '.',
      '',
      `These tools run ON THAT MACHINE, not on the local one: ${this.shadowed.join(', ')}.`,
      'Local paths do not exist there, and paths you see in results are remote paths.',
      '',
      `${this.config.fullAccess === true ? 'These remote tools were excluded by the explicit configuration:' : 'These capabilities deliberately STAYED LOCAL:'} ${localOnly}.`,
      '',
      'Run `/exit` to return to the local environment.',
    ]

    try {
      const disposer = systemPrompt.section({
        name: 'context:native-env-v2',
        order,
        text: () => lines.join('\n'),
      })
      if (typeof disposer === 'function') this.disposers.push(disposer)
      this.promptInstalled = true
      return true
    } catch (error) {
      this.logger?.warn?.(`native-env: could not install the remote-environment prompt section: ${String(error?.message ?? error)}`)
      return false
    }
  }

  /**
   * Shadow this peer's tools for this agent.
   *
   * Idempotent: an existing installation is disposed first, so calling it twice
   * (or calling it to move to a different peer) can never leave a stale shadow.
   *
   * @returns the receipt the `/enter` command and `env_enter` tool report.
   */
  async install() {
    const generation = ++this.generation
    const listed = await this.client.list()
    // Do not resurrect shadows when the component/session was disabled while
    // the peer was answering. Keep old shadows during the asynchronous list so
    // a failed refresh cannot accidentally expose same-named local tools.
    if (generation !== this.generation) return this.receipt()
    this.dispose()

    this.shadowed = []
    this.skipped = []
    for (const remote of listed.tools) {
      const reason = denialReason(remote.name, this.config.exclude, { fullAccess: this.config.fullAccess === true })
      if (reason !== undefined) {
        this.skipped.push({ name: remote.name, reason })
        continue
      }
      this.disposers.push(this.agent.ctx.tools.register(this.buildDefinition(remote)))
      this.shadowed.push(remote.name)
    }

    this.installPromptSection()
    this.installedAt = Date.now()

    return this.receipt()
  }

  /** The `/enter` receipt: exactly what happened, including what did not. */
  receipt() {
    return {
      peer: this.peer,
      fullAccess: this.config.fullAccess === true,
      label: this.client.config.label,
      transport: this.client.config.transport,
      anchor: this.client.anchor,
      platform: this.client.platform,
      cwd: this.client.cwd,
      remoteToolCount: this.client.tools.length,
      shadowed: [...this.shadowed].sort(),
      shadowedCount: this.shadowed.length,
      skipped: [...this.skipped].sort((a, b) => a.name.localeCompare(b.name)),
      skippedCount: this.skipped.length,
      promptSection: this.promptInstalled,
      installedAt: this.installedAt,
      // Stated plainly because it is the surprising part of a takeover.
      notice:
        (this.config.fullAccess === true
          ? 'Full access is enabled: every serializable remote tool was requested. Control tools and explicit exclusions remain local.'
          : 'Local approval and sandbox policy no longer apply to the shadowed tools: the REMOTE runtime\'s own policy governs them.') +
        ' Only the tools listed as skipped are still running locally.',
    }
  }

  /**
   * Re-list the peer and re-shadow. Used when the remote reports `tools/change`,
   * which is how a plugin mounted AFTER a takeover becomes usable without a
   * re-enter, and how the `agent/created` registration race is closed.
   * @returns the fresh receipt.
   */
  async refresh() {
    // The peer can report several changes in a burst; a refresh already in flight
    // makes a second one pointless, and re-entering would interleave disposers.
    if (this.refreshing) return this.receipt()
    this.refreshing = true
    try {
      return await this.install()
    } finally {
      this.refreshing = false
    }
  }

  /** Unregister everything, restoring the global tools for this agent. */
  dispose() {
    this.generation += 1
    for (const dispose of this.disposers.splice(0).reverse()) {
      try {
        dispose()
      } catch (error) {
        this.logger?.warn?.(`native-env: failed to unregister a shadowed tool: ${String(error?.message ?? error)}`)
      }
    }
    this.shadowed = []
    this.skipped = []
    this.promptInstalled = false
    this.installedAt = undefined
  }
}
