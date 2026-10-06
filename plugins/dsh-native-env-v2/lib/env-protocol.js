/**
 * dsh-native-env / env-protocol — the method names, the argument validation, and
 * the DENYLIST that decides which remote tools may never be shadowed.
 *
 * The env wire carries `env/list`, `env/call`, `env/cancel`, `env/status` and the
 * `env/tools-changed` notification. Both halves import this file, so a method
 * name or a validation rule can never drift between them.
 *
 * The denylist is the load-bearing policy in this file. The host shadows
 * *everything* the remote exposes except these names, so the list is what keeps
 * a takeover from moving machinery that only works on the machine it came from:
 *
 *   - orchestration (subagents, the net bridge itself, workflows, goals, jobs)
 *     must stay local, or a takeover would spawn remote agents the caller can no
 *     longer see or steer;
 *   - `ask_user_question` needs a UI to answer it, and the remote has none
 *     attached to this session;
 *   - `read_image` returns a reference into the REMOTE attachment store, which
 *     this process cannot open — a silently broken result, not a slow one;
 *   - `computer_*` drives the remote's screen, which is almost never what the
 *     caller means by "run this command over there";
 *   - `web_*` egress: the host's own egress goes through a local proxy, so
 *     moving it would silently change where requests appear to come from.
 *
 * Every entry carries its reason, because the `/enter` receipt reports the skips
 * and a bare name would not explain itself.
 *
 * @module dsh-native-env/env-protocol
 */

/** The channel tag this wire uses in `bridge/hello`. */
export const CHANNEL = 'env'

/** Every method name on the env wire. */
export const METHODS = Object.freeze({
  list: 'env/list',
  call: 'env/call',
  cancel: 'env/cancel',
  status: 'env/status',
  /** guest → host notification: the remote's visible tool set changed. */
  toolsChanged: 'env/tools-changed',
})

/** v2 application methods. The bridge/auth wire remains v1 compatible. */
export const V2_METHODS = Object.freeze({
  hello: 'env2/hello',
  list: 'env2/list',
  call: 'env2/call',
  cancel: 'env2/cancel',
  status: 'env2/status',
  toolsChanged: 'env2/tools-changed',
})

/** A protocol violation; the message reaches the caller as a tool error. */
export class EnvProtocolError extends Error {
  constructor(message) {
    super(message)
    this.name = 'EnvProtocolError'
  }
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Tools that must never be shadowed, with the reason the `/enter` receipt shows.
 *
 * A pattern ending in `*` is a prefix match; anything else is exact. Order is
 * the order skips are reported in.
 */
export const DEFAULT_DENYLIST = Object.freeze([
  // ── local orchestration ────────────────────────────────────────────────────
  { pattern: 'subagent*', reason: 'delegation must stay local; a remote subagent would be invisible to this caller' },
  { pattern: 'net_*', reason: 'the net bridge itself; taking it over would displace this very connection' },
  { pattern: 'env_*', reason: 'this plugin\'s own tools; shadowing them would let a takeover recurse' },
  { pattern: 'workflow', reason: 'orchestration stays local' },
  { pattern: 'ralph', reason: 'orchestration stays local' },
  { pattern: 'create_goal', reason: 'goal state is owned by the local session' },
  { pattern: 'get_goal', reason: 'goal state is owned by the local session' },
  { pattern: 'update_goal', reason: 'goal state is owned by the local session' },
  { pattern: 'todo_write', reason: 'the todo list is local session state' },
  { pattern: 'job_*', reason: 'background jobs are local process state' },
  { pattern: 'interrupt_agent', reason: 'subagent control stays local' },
  { pattern: 'send_message', reason: 'subagent control stays local' },
  { pattern: 'list_agents', reason: 'subagent control stays local' },
  { pattern: 'exit_plan_mode', reason: 'plan mode is local session state' },

  // ── needs a UI the remote does not have attached ───────────────────────────
  { pattern: 'ask_user_question', reason: 'the remote has no UI attached to this session to answer it' },

  // ── results this process cannot consume ────────────────────────────────────
  { pattern: 'read_image', reason: 'returns a reference into the REMOTE attachment store, which this process cannot open' },

  // ── drives the remote's own screen ─────────────────────────────────────────
  { pattern: 'computer_*', reason: 'drives the remote screen, not the remote filesystem' },

  // ── egress ─────────────────────────────────────────────────────────────────
  { pattern: 'web_search', reason: 'egress stays local so requests keep using the host\'s proxy' },
  { pattern: 'web_fetch', reason: 'egress stays local so requests keep using the host\'s proxy' },

  // ── local-session concepts ─────────────────────────────────────────────────
  { pattern: 'present', reason: 'deliverables are a local concept' },
  { pattern: 'skill', reason: 'the skill catalog assembled into this prompt is the LOCAL one' },
  { pattern: 'skill_*', reason: 'the skill catalog assembled into this prompt is the LOCAL one' },

  // ── reserved by the registry ───────────────────────────────────────────────
  { pattern: 'run_code', reason: 'reserved PTC-mode transport name; the registry refuses to register it at all' },
])

/** Controls that must stay local even when the explicit full-access component is on. */
const FULL_ACCESS_CONTROL_DENYLIST = Object.freeze([
  { pattern: 'env_enter', reason: 'the local session must retain the enter control' },
  { pattern: 'env_exit', reason: 'the local session must retain the exit control' },
  { pattern: 'env_status', reason: 'the local session must retain environment status' },
  { pattern: 'env_invite', reason: 'the local session must retain pairing controls' },
  { pattern: 'run_code', reason: 'reserved PTC-mode transport name; the registry refuses to register it at all' },
])

/**
 * The reason a tool name is denied, or `undefined` when it may be shadowed.
 * @param name - the remote tool name.
 * @param extra - caller-supplied patterns, checked before the defaults so a
 *   deployment can explain its own exclusions; same `*`-suffix syntax.
 * @returns the first matching reason.
 */
export function denialReason(name, extra = [], options = {}) {
  // The ordinary mode protects local orchestration/UI tools.  The explicit
  // "full access" component opts out of that default policy while retaining
  // any deployment-specific exclusions supplied in `extra`.
  const defaults = options?.fullAccess === true ? FULL_ACCESS_CONTROL_DENYLIST : DEFAULT_DENYLIST
  for (const entry of [...extra, ...defaults]) {
    const pattern = typeof entry === 'string' ? entry : entry.pattern
    const reason = typeof entry === 'string' ? 'excluded by configuration' : entry.reason
    if (pattern.endsWith('*')) {
      if (name.startsWith(pattern.slice(0, -1))) return reason
    } else if (name === pattern) {
      return reason
    }
  }
  return undefined
}

/**
 * A one-line summary of the denylist for the injected system-prompt section, so
 * the model knows which capabilities did NOT follow it into the remote.
 * @returns a comma-joined list of the non-prefix patterns.
 */
export function denylistSummary() {
  return DEFAULT_DENYLIST.filter((entry) => !entry.pattern.endsWith('*'))
    .map((entry) => entry.pattern)
    .join(', ')
}

/**
 * Validate `env/call` params.
 * @param params - the raw params object.
 * @returns `{ callId, name, arguments }`.
 * @throws {EnvProtocolError} on a missing or malformed field.
 */
export function parseCallParams(params) {
  if (!isPlainObject(params)) throw new EnvProtocolError('env/call: params must be an object')
  const { callId, name, arguments: args } = params
  if (typeof callId !== 'string' || callId.length === 0) throw new EnvProtocolError('env/call: callId must be a non-empty string')
  if (typeof name !== 'string' || name.length === 0) throw new EnvProtocolError('env/call: name must be a non-empty string')
  if (args !== undefined && !isPlainObject(args)) throw new EnvProtocolError('env/call: arguments must be an object when present')
  return { callId, name, arguments: args ?? {} }
}

/**
 * Validate `env/cancel` params.
 * @param params - the raw params object.
 * @returns `{ callId }`.
 * @throws {EnvProtocolError} when the id is missing.
 */
export function parseCancelParams(params) {
  if (!isPlainObject(params)) throw new EnvProtocolError('env/cancel: params must be an object')
  const { callId } = params
  if (typeof callId !== 'string' || callId.length === 0) throw new EnvProtocolError('env/cancel: callId must be a non-empty string')
  return { callId }
}

/**
 * Coerce a tool's model-facing content into the block array this wire carries.
 *
 * The remote returns whatever its own tool produced; this side never inspects
 * the shape beyond "it is an array", because the whole point of the design is
 * that the remote's rendering is forwarded verbatim.
 * @param content - the remote result's content.
 * @returns an array of content blocks (possibly empty).
 */
export function normalizeContent(content) {
  return Array.isArray(content) ? content : []
}
