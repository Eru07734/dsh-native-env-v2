/**
 * Application-level v2 negotiation for dsh-native-env-v2.
 *
 * The bridge/auth handshake is intentionally left compatible with the v1
 * package.  Once that authenticated wire exists, env2/hello negotiates the
 * application protocol and carries the runtime metadata needed by DSH↔DSH.
 */

export const PROTOCOL_VERSION = 2
export const MAX_MESSAGE_BYTES = 4 * 1024 * 1024

export const V2_METHODS = Object.freeze({
  hello: 'env2/hello',
  list: 'env2/list',
  call: 'env2/call',
  cancel: 'env2/cancel',
  status: 'env2/status',
  toolsChanged: 'env2/tools-changed',
})

export const CAPABILITIES = Object.freeze([
  'env2',
  'structured-content',
  'cancel',
  'tool-revisions',
  'fail-closed',
])

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function text(value, fallback = 'unknown') {
  return typeof value === 'string' && value.length > 0 ? value : fallback
}

/** Build the metadata returned from env2/hello and env2/status. */
export function buildHello({ peer, label, runtimeVersion, platform, cwd, maxMessageBytes = MAX_MESSAGE_BYTES, capabilities = CAPABILITIES, revision = 0 } = {}) {
  return {
    protocol: PROTOCOL_VERSION,
    dshVersion: text(runtimeVersion, process.env.DSH_VERSION ?? 'unknown'),
    runtime: { name: 'dsh', version: text(runtimeVersion, process.env.DSH_VERSION ?? 'unknown') },
    platform: text(platform, process.platform),
    peer: text(peer),
    ...(label === undefined ? {} : { label: text(label) }),
    ...(cwd === undefined ? {} : { cwd: text(cwd) }),
    capabilities: [...new Set(Array.isArray(capabilities) ? capabilities.filter((x) => typeof x === 'string') : CAPABILITIES)],
    revision: Number.isInteger(revision) && revision >= 0 ? revision : 0,
    maxMessageBytes: Number.isInteger(maxMessageBytes) && maxMessageBytes > 0 ? maxMessageBytes : MAX_MESSAGE_BYTES,
  }
}

/** Validate a peer's env2/hello result without trusting arbitrary fields. */
export function validateHello(value) {
  if (!plain(value)) throw new Error('env2/hello: result must be an object')
  if (value.protocol !== PROTOCOL_VERSION) throw new Error(`env2/hello: unsupported protocol ${String(value.protocol)}`)
  if (typeof value.peer !== 'string' || value.peer.length === 0) throw new Error('env2/hello: peer must be a non-empty string')
  if (!Array.isArray(value.capabilities)) throw new Error('env2/hello: capabilities must be an array')
  if (!Number.isInteger(value.revision) || value.revision < 0) throw new Error('env2/hello: revision must be a non-negative integer')
  if (!Number.isInteger(value.maxMessageBytes) || value.maxMessageBytes <= 0) throw new Error('env2/hello: maxMessageBytes must be positive')
  return {
    ...value,
    capabilities: value.capabilities.filter((item) => typeof item === 'string'),
  }
}

export function isUnknownMethod(error) {
  return error?.code === -32601 || /method not found|unknown env method|does not serve.*env2\//i.test(String(error?.message ?? error))
}
