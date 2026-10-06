/**
 * dsh-native-env / state-store — where pairing remembers things, and where it
 * refuses to.
 *
 * Two stores, split along the one line that matters:
 *
 *   - **`StateStore`** holds NON-SECRET state in one JSON file: which peers are
 *     known, their labels, the terms acceptance, the active invite's public
 *     fields. Losing this file costs a re-pair, nothing more, so a plain file is
 *     the right medium.
 *   - **`SecretStore`** holds SECRETS in the harness credential service: the
 *     machine identity's private key, and the invite a guest needs in order to
 *     reconnect. If that service is unavailable it does NOT fall back to the JSON
 *     file. It refuses, logs why, and the pairing works for this process only —
 *     because a private key written into a world-readable state file is a worse
 *     outcome than a pairing that does not survive a restart.
 *
 * That refusal is the whole point of this module existing as a separate file
 * rather than as two helper functions inside the pairing code: it is the one
 * decision a later change is most likely to make "convenient".
 *
 * @module dsh-native-env/state-store
 */

import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { randomBytes } from 'node:crypto'

/**
 * Resolve the harness home directory.
 *
 * `$DSH_HOME` first because that is what every other part of the harness honours,
 * including the credential store; a plugin that guessed differently would put its
 * state somewhere the operator does not expect.
 *
 * @returns the directory path.
 */
export function resolveDshHome() {
  const configured = process.env.DSH_HOME
  if (typeof configured === 'string' && configured.length > 0) return configured
  return join(homedir(), '.dsh')
}

/** The state file's name inside the harness home. */
export const STATE_FILE_NAME = 'native-env-v2-state.json'

/**
 * The non-secret state file.
 *
 * Reads are tolerant by design: a corrupt or unreadable file yields an empty state
 * and a warning rather than an exception, because refusing to start a plugin over
 * a stale cache would trade a small inconvenience for a broken profile.
 */
export class StateStore {
  /**
   * @param options.file - the state file path; defaults to the harness home.
   * @param options.logger - optional `{ info, warn }`.
   */
  constructor(options = {}) {
    this.file = options.file ?? join(resolveDshHome(), STATE_FILE_NAME)
    this.logger = options.logger
    this.cache = undefined
  }

  /**
   * Read the whole state document.
   * @returns the state, or an empty object when there is nothing readable.
   */
  read() {
    if (this.cache !== undefined) return this.cache
    if (!existsSync(this.file)) {
      this.cache = {}
      return this.cache
    }
    try {
      const parsed = JSON.parse(readFileSync(this.file, 'utf8'))
      this.cache = parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {}
    } catch (error) {
      this.logger?.warn?.(`native-env: the state file ${this.file} is unreadable (${String(error?.message ?? error)}); starting from an empty state`)
      this.cache = {}
    }
    return this.cache
  }

  /**
   * Read one key, with a default.
   * @param key - the key.
   * @param fallback - the value when the key is absent.
   * @returns the value.
   */
  get(key, fallback = undefined) {
    const state = this.read()
    return Object.hasOwn(state, key) ? state[key] : fallback
  }

  /**
   * Merge one patch into the state and persist it.
   *
   * Written through a temporary file and renamed, so an interrupted write leaves
   * the previous state intact instead of a truncated document that the next read
   * would silently treat as "no state at all" — the latter would look like the
   * terms gate had never been accepted.
   *
   * @param patch - the keys to merge; a `null` value removes the key.
   * @returns the merged state.
   */
  write(patch) {
    const next = { ...this.read() }
    for (const [key, value] of Object.entries(patch)) {
      if (value === null || value === undefined) delete next[key]
      else next[key] = value
    }
    this.cache = next
    try {
      mkdirSync(dirname(this.file), { recursive: true })
      const temporary = `${this.file}.${randomBytes(4).toString('hex')}.tmp`
      writeFileSync(temporary, `${JSON.stringify(next, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 })
      renameSync(temporary, this.file)
    } catch (error) {
      this.logger?.warn?.(`native-env: could not persist the state file ${this.file} (${String(error?.message ?? error)})`)
    }
    return next
  }

  /** Remove the state file. Best effort. */
  clear() {
    this.cache = {}
    try {
      if (existsSync(this.file)) unlinkSync(this.file)
    } catch (error) {
      this.logger?.warn?.(`native-env: could not remove the state file ${this.file} (${String(error?.message ?? error)})`)
    }
  }
}

/**
 * The secret store, over the harness credential service.
 *
 * Every method is async because the credential service is, and every failure is
 * reported rather than thrown: a pairing attempt that cannot persist its identity
 * should still work for this session, with a warning that says so.
 */
export class SecretStore {
  /**
   * @param options.credentials - `ctx.credentials`, when the profile mounts it.
   * @param options.namespace - a prefix that keeps these keys from colliding with
   *   another plugin's.
   * @param options.logger - optional `{ info, warn }`.
   */
  constructor(options) {
    this.credentials = options.credentials
    this.namespace = options.namespace ?? 'dsh-native-env-v2'
    this.logger = options.logger
    this.warned = false
  }

  /** @returns true when secrets can be persisted at all. */
  get available() {
    return this.credentials !== undefined && typeof this.credentials.readRecord === 'function'
  }

  /**
   * The credential key for one secret name.
   * @param name - the secret's name.
   * @returns the key.
   */
  keyFor(name) {
    // dsh-credentials uses `<scope>/<id>` refs. Keep the plugin namespace
    // separate without producing a malformed key that prevents the whole
    // credentials provider from loading.
    return `${this.namespace}/${name}`
  }

  /** Warn once, so a missing credential service does not spam the log. */
  warnUnavailable(action) {
    if (this.warned) return
    this.warned = true
    this.logger?.warn?.(
      `native-env: the credential service is not mounted, so ${action} cannot be stored on this machine. ` +
        'Pairing still works for this process, but it will not survive a restart. Mount a profile that provides ' +
        '`credentials` (the standard web and base profiles do) to persist it.',
    )
  }

  /**
   * Read one secret.
   * @param name - the secret's name.
   * @returns the stored value, or `undefined`.
   */
  async read(name) {
    if (!this.available) return undefined
    try {
      const record = await this.credentials.readRecord(this.keyFor(name))
      if (record === undefined || record === null) return undefined
      if (record.kind === 'grant' && record.payload !== null && typeof record.payload === 'object') {
        const value = record.payload.value
        return typeof value === 'string' && value.length > 0 ? value : undefined
      }
      if (record.kind === 'api-key' && typeof record.key === 'string') return record.key
      return undefined
    } catch (error) {
      this.logger?.warn?.(`native-env: could not read the stored ${name} (${String(error?.message ?? error)})`)
      return undefined
    }
  }

  /**
   * Store one secret.
   * @param name - the secret's name.
   * @param value - the value.
   * @returns true when it was persisted.
   */
  async write(name, value) {
    if (!this.available || typeof this.credentials.modifyRecord !== 'function') {
      this.warnUnavailable(`the ${name}`)
      return false
    }
    try {
      await this.credentials.modifyRecord(this.keyFor(name), async () => ({ kind: 'grant', payload: { value: String(value) } }))
      return true
    } catch (error) {
      this.logger?.warn?.(`native-env: could not store the ${name} (${String(error?.message ?? error)})`)
      return false
    }
  }

  /**
   * Remove one secret.
   * @param name - the secret's name.
   * @returns true when the store was reachable.
   */
  async remove(name) {
    if (!this.available || typeof this.credentials.deleteRecord !== 'function') return false
    try {
      await this.credentials.deleteRecord(this.keyFor(name))
      return true
    } catch (error) {
      this.logger?.warn?.(`native-env: could not remove the stored ${name} (${String(error?.message ?? error)})`)
      return false
    }
  }
}
