/**
 * dsh-native-env-relay / config — every knob, read from the environment once.
 *
 * Environment-only on purpose: a relay is deployed by an operator who already has
 * a service manager or a container runtime, and a config FILE would be a second
 * thing to keep in sync with the deployment. Every value has a safe default, and
 * the defaults are the conservative ones:
 *
 *   - bind LOOPBACK unless told otherwise, so a misconfigured `docker run` cannot
 *     expose the relay by accident;
 *   - one megabyte per frame, which is above what an env payload needs (a 256 KiB
 *     tool result plus its base64 and envelope lands near 460 KiB) and far below
 *     what a hostile client would like to send;
 *   - log at `info` with invite ids truncated, so a default deployment does not
 *     create a log file full of correlatable identifiers.
 *
 * @module dsh-native-env-relay/config
 */

import { DEFAULT_INVITE_TTL_MS, MAX_INVITE_TTL_MS } from './embedded-relay-registry.js'

/** Read one integer from the environment, falling back on anything unusable. */
function intFromEnv(name, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const raw = process.env[name]
  if (raw === undefined || raw === '') return fallback
  const value = Number(raw)
  if (!Number.isFinite(value) || !Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${String(min)} and ${String(max)}, got ${JSON.stringify(raw)}`)
  }
  return value
}

/** Read one string from the environment, falling back on anything empty. */
function stringFromEnv(name, fallback) {
  const raw = process.env[name]
  return raw === undefined || raw === '' ? fallback : raw
}

/**
 * Resolve the relay's configuration.
 *
 * @param overrides - explicit values, used by tests; they win over the environment.
 * @returns the resolved configuration.
 */
export function resolveRelayConfig(overrides = {}) {
  const logLevel = stringFromEnv('DSH_RELAY_LOG_LEVEL', 'info')
  if (!['silent', 'info', 'debug'].includes(logLevel)) {
    throw new Error(`DSH_RELAY_LOG_LEVEL must be silent, info or debug, got ${JSON.stringify(logLevel)}`)
  }
  const tlsCert = stringFromEnv('DSH_RELAY_TLS_CERT', undefined)
  const tlsKey = stringFromEnv('DSH_RELAY_TLS_KEY', undefined)
  if ((tlsCert === undefined) !== (tlsKey === undefined)) {
    throw new Error('DSH_RELAY_TLS_CERT and DSH_RELAY_TLS_KEY must be set together')
  }
  return {
    host: overrides.host ?? stringFromEnv('DSH_RELAY_HOST', '127.0.0.1'),
    port: overrides.port ?? intFromEnv('DSH_RELAY_PORT', 8931, { min: 0, max: 65535 }),
    inviteTtlMs: overrides.inviteTtlMs ?? intFromEnv('DSH_RELAY_INVITE_TTL_MS', DEFAULT_INVITE_TTL_MS, { min: 1000, max: MAX_INVITE_TTL_MS }),
    maxFrameBytes: overrides.maxFrameBytes ?? intFromEnv('DSH_RELAY_MAX_FRAME_BYTES', 1024 * 1024, { min: 4096, max: 64 * 1024 * 1024 }),
    maxConnections: overrides.maxConnections ?? intFromEnv('DSH_RELAY_MAX_CONNECTIONS', 512, { min: 1 }),
    maxConnectionsPerIp: overrides.maxConnectionsPerIp ?? intFromEnv('DSH_RELAY_MAX_CONNECTIONS_PER_IP', 8, { min: 1 }),
    /**
     * How many failed rendezvous proofs one client address may produce inside the
     * window before it is refused. The default is generous enough for a human who
     * mistypes a password a few times and far too small for enumeration: a nine-digit
     * device code is only safe to display because guessing it is rate-limited.
     */
    maxAuthFailuresPerIp: overrides.maxAuthFailuresPerIp ?? intFromEnv('DSH_RELAY_MAX_AUTH_FAILURES_PER_IP', 20, { min: 1 }),
    authFailureWindowMs: overrides.authFailureWindowMs ?? intFromEnv('DSH_RELAY_AUTH_FAILURE_WINDOW_MS', 60000, { min: 1000 }),
    messagesPerSecond: overrides.messagesPerSecond ?? intFromEnv('DSH_RELAY_MESSAGES_PER_SECOND', 400, { min: 10 }),
    joinTimeoutMs: overrides.joinTimeoutMs ?? intFromEnv('DSH_RELAY_JOIN_TIMEOUT_MS', 15000, { min: 1000 }),
    maxInvites: overrides.maxInvites ?? intFromEnv('DSH_RELAY_MAX_INVITES', 10000, { min: 1 }),
    maxHttpBodyBytes: overrides.maxHttpBodyBytes ?? intFromEnv('DSH_RELAY_MAX_HTTP_BODY_BYTES', 8192, { min: 256 }),
    idleTimeoutMs: overrides.idleTimeoutMs ?? intFromEnv('DSH_RELAY_IDLE_TIMEOUT_MS', 0, { min: 0 }),
    trustProxy: overrides.trustProxy ?? stringFromEnv('DSH_RELAY_TRUST_PROXY', '0') === '1',
    logLevel: overrides.logLevel ?? logLevel,
    tls: tlsCert === undefined ? undefined : { cert: tlsCert, key: tlsKey },
  }
}
