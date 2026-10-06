/**
 * dsh-native-env-relay — the public rendezvous service.
 *
 * WHAT THIS PROCESS CAN AND CANNOT SEE, because that is the only question that
 * matters about a relay:
 *
 *   CAN see: an invite id, the role names, the remote IP addresses, connection
 *   times, and the SIZE and TIMING of every forwarded frame. It also holds the
 *   invite secret for the invite's lifetime, because it is the verifier for the
 *   rendezvous proof.
 *
 *   CANNOT see: any tool name, argument, file path, file content, tool result, or
 *   machine hostname. Everything after the pairing handshake is AES-256-GCM sealed
 *   by `e2ee.js` with a key the relay never receives — the ephemeral X25519
 *   exchange happens INSIDE the forwarded payloads, so the relay could not derive
 *   it even if it tried. There is no env method name anywhere in this process's
 *   code path, and no branch that inspects a payload beyond its length.
 *
 * What the relay deliberately does NOT do is authenticate the two machines to each
 * other. It authorizes the rendezvous (via the invite secret) and it forwards
 * bytes; the machines authenticate each other with Ed25519 signatures, so a relay
 * that lies, replays or substitutes keys is DETECTED by the guest rather than
 * trusted. This division is what makes "self-host a relay, or use someone else's"
 * a tractable choice instead of a leap of faith.
 *
 * Run it with `node server.js`; see README.md for deployment, TLS and limits.
 *
 * @module dsh-native-env-relay/server
 */

import { randomBytes, timingSafeEqual } from 'node:crypto'
import { createServer as createHttpServer } from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import process from 'node:process'

import { acceptWebSocket } from './ws.js'
import {
  RELAY_CHANNEL_PATH,
  RELAY_ERROR,
  RELAY_HEALTH_PATH,
  RELAY_INVITE_PATH,
  RELAY_MESSAGE,
  RELAY_VERSION,
  PRESENCE,
  isRole,
  parseJson,
  relayJoinProof,
} from './relay-protocol.js'
import { resolveRelayConfig } from './embedded-relay-config.js'
import { InviteRegistry, RegistryError } from './embedded-relay-registry.js'

/** The max age of one invite id prefix in a log line. Never the full id. */
const ID_PREFIX_LENGTH = 8

/**
 * A JSON-lines logger that cannot log a secret by construction.
 *
 * Every call site passes explicit, named fields — there is no "log this object"
 * path — so a future field added to a slot cannot leak into the log by being
 * spread. That is the point: the redaction is structural, not a filter that a new
 * code path can forget to apply.
 */
export class RelayLog {
  /**
   * @param level - `silent`, `info` or `debug`.
   * @param sink - the write sink, injectable for tests.
   */
  constructor(level = 'info', sink = (line) => process.stdout.write(`${line}\n`)) {
    this.level = level
    this.sink = sink
  }

  /**
   * Write one structured line.
   * @param level - `info` or `debug`.
   * @param event - the event name.
   * @param fields - explicit, named fields only.
   */
  write(level, event, fields = {}) {
    if (this.level === 'silent') return
    if (level === 'debug' && this.level !== 'debug') return
    const record = { time: new Date().toISOString(), level, event, ...fields }
    try {
      this.sink(JSON.stringify(record))
    } catch {
      /* a broken log sink must never take the relay down */
    }
  }

  /** @param event - the event name. @param fields - named fields. */
  info(event, fields) {
    this.write('info', event, fields)
  }

  /** @param event - the event name. @param fields - named fields. */
  debug(event, fields) {
    this.write('debug', event, fields)
  }

  /** @param event - the event name. @param fields - named fields. */
  warn(event, fields) {
    this.write('warn', event, fields)
  }
}

/** @returns the first 8 characters of an invite id, for correlation only. */
function idPrefix(inviteId) {
  return String(inviteId).slice(0, ID_PREFIX_LENGTH)
}

/**
 * One client occupying one role in one invite.
 */
export class RelayConnection {
  /**
   * @param options.ws - the accepted WebSocket.
   * @param options.ip - the client address, for limits and logs.
   * @param options.pathInviteId - the invite id from the request path.
   * @param options.registry - the invite registry.
   * @param options.config - the resolved relay configuration.
   * @param options.log - the relay logger.
   * @param options.onClosed - called exactly once when this connection is gone.
   */
  constructor(options) {
    this.ws = options.ws
    this.ip = options.ip
    this.pathInviteId = options.pathInviteId
    this.registry = options.registry
    this.config = options.config
    this.log = options.log
    this.onClosed = options.onClosed
    this.onAuthFailure = options.onAuthFailure

    this.state = 'joining'
    this.role = undefined
    this.slot = undefined
    this.invitePrefix = idPrefix(options.pathInviteId)
    /** A token bucket: `messagesPerSecond` with a one-second burst on top. */
    this.budget = options.config.messagesPerSecond
    this.budgetAt = Date.now()
    this.closed = false
    this.secret = undefined

    this.onMessage = (text) => this.handleMessage(text)
    this.onClose = () => this.handleClosed()
    this.onError = () => this.handleClosed()
    this.ws.on('message', this.onMessage)
    this.ws.on('close', this.onClose)
    this.ws.on('error', this.onError)

    this.timer = setTimeout(() => {
      this.refuse(RELAY_ERROR.badMessage, 'no join message arrived in time')
    }, options.config.joinTimeoutMs)
    this.timer.unref?.()
  }

  /** Send one relay message. */
  send(message) {
    if (this.closed) return
    try {
      this.ws.send(JSON.stringify({ v: RELAY_VERSION, ...message }))
    } catch {
      this.handleClosed()
    }
  }

  /** Send one relay error and close. */
  refuse(code, message) {
    this.send({ t: RELAY_MESSAGE.error, code, message })
    this.close(1008, code)
  }

  /** Close the connection. Idempotent. */
  close(code = 1000, reason = '') {
    if (this.closed) return
    this.closed = true
    try {
      this.ws.close(code, reason)
    } catch {
      /* already gone */
    }
    this.handleClosed()
  }

  /**
   * Apply the per-connection message budget.
   * @returns true when the message may be processed.
   */
  spendBudget() {
    const now = Date.now()
    this.budget = Math.min(this.config.messagesPerSecond * 2, this.budget + ((now - this.budgetAt) / 1000) * this.config.messagesPerSecond)
    this.budgetAt = now
    if (this.budget < 1) return false
    this.budget -= 1
    return true
  }

  /**
   * Route one inbound relay message.
   * @param text - the raw message text.
   */
  handleMessage(text) {
    if (this.closed) return
    if (!this.spendBudget()) {
      this.log.warn('rate-limited', { invite: this.invitePrefix, role: this.role })
      this.refuse(RELAY_ERROR.rateLimited, 'too many messages; slow down')
      return
    }
    const decoded = parseJson(text)
    if (!decoded.ok) {
      this.refuse(RELAY_ERROR.badMessage, decoded.error)
      return
    }
    const message = decoded.value
    if (message === null || typeof message !== 'object') {
      this.refuse(RELAY_ERROR.badMessage, 'a relay message must be a JSON object')
      return
    }
    switch (this.state) {
      case 'joining':
        this.handleJoin(message)
        return
      case 'authorizing':
        this.handleAuth(message)
        return
      case 'ready':
        this.handleReady(message)
        return
      default:
        this.refuse(RELAY_ERROR.badMessage, 'this connection is not accepting messages')
    }
  }

  /**
   * Handle the `join` message: identify the invite and issue a challenge.
   * @param message - the parsed message.
   */
  handleJoin(message) {
    if (message.t !== RELAY_MESSAGE.join) {
      this.refuse(RELAY_ERROR.badMessage, `expected a ${RELAY_MESSAGE.join} message, got ${JSON.stringify(message.t)}`)
      return
    }
    if (message.v !== undefined && message.v !== RELAY_VERSION) {
      this.refuse(RELAY_ERROR.versionMismatch, `this relay speaks v${String(RELAY_VERSION)}; the client asked for v${String(message.v)}`)
      return
    }
    if (String(message.inviteId ?? '') !== this.pathInviteId) {
      // The id travels in both the path and the body; a mismatch means the client
      // is confused or trying to use a path it does not own.
      this.refuse(RELAY_ERROR.badMessage, 'the invite id in the message does not match the one in the request path')
      return
    }
    if (!isRole(message.role)) {
      this.refuse(RELAY_ERROR.badRole, 'role must be "host" or "guest"')
      return
    }
    if (typeof message.nonce !== 'string' || !/^[0-9a-f]{16,64}$/.test(message.nonce)) {
      this.refuse(RELAY_ERROR.badMessage, 'the join nonce must be 16-64 lowercase hex characters')
      return
    }
    let slot
    try {
      slot = this.registry.require(this.pathInviteId)
    } catch (error) {
      const registryError = error instanceof RegistryError ? error : new RegistryError(RELAY_ERROR.inviteUnknown, String(error))
      this.refuse(registryError.code, registryError.message)
      return
    }
    if (slot.roles[message.role] !== undefined) {
      this.refuse(RELAY_ERROR.roleTaken, `a ${String(message.role)} is already connected to this invite`)
      return
    }
    this.role = message.role
    this.slot = slot
    this.secret = slot.secret
    this.clientNonce = message.nonce
    this.serverNonce = randomHex()
    this.state = 'authorizing'
    this.send({ t: RELAY_MESSAGE.challenge, nonce: this.serverNonce, expiresAt: slot.expiresAt })
  }

  /**
   * Handle the `auth` message: prove the invite secret and occupy the role.
   * @param message - the parsed message.
   */
  handleAuth(message) {
    if (message.t !== RELAY_MESSAGE.auth || typeof message.proof !== 'string') {
      this.refuse(RELAY_ERROR.badMessage, `expected an ${RELAY_MESSAGE.auth} message carrying a proof`)
      return
    }
    const expected = relayJoinProof(this.secret, this.pathInviteId, this.role, this.clientNonce, this.serverNonce)
    // Wiped as soon as it has been used: the relay never needs the secret again,
    // because the machines authenticate each other from here on.
    this.secret = undefined
    if (!constantTimeEqualHex(message.proof, expected)) {
      this.log.warn('auth-failed', { invite: this.invitePrefix, role: this.role })
      // Reported to the relay so the ADDRESS can be throttled: without this, a
      // nine-digit device code would be enumerable at whatever rate the attacker
      // can open connections.
      this.onAuthFailure?.()
      this.refuse(RELAY_ERROR.authFailed, 'the pairing secret proof did not verify')
      return
    }
    let claimed
    try {
      claimed = this.registry.claim(this.slot, this.role, this)
    } catch (error) {
      const registryError = error instanceof RegistryError ? error : new RegistryError(RELAY_ERROR.badMessage, String(error))
      this.refuse(registryError.code, registryError.message)
      return
    }
    this.state = 'ready'
    this.log.info('joined', { invite: this.invitePrefix, role: this.role, paired: claimed.isPaired })
    if (claimed.peer === undefined) {
      this.send({ t: RELAY_MESSAGE.waiting })
      return
    }
    // Both ends are here. `ready` tells this side to proceed, and the peer is told
    // the same so it does not have to poll.
    this.send({ t: RELAY_MESSAGE.ready })
    claimed.peer.notifyPeerPresent()
  }

  /**
   * Handle `peer` and `leave` messages once the slot is open.
   * @param message - the parsed message.
   */
  handleReady(message) {
    if (message.t === RELAY_MESSAGE.peer) {
      if (typeof message.d !== 'string') {
        this.refuse(RELAY_ERROR.badMessage, 'a peer payload must be a string')
        return
      }
      const peer = this.slot.peerOf(this.role)
      if (peer === undefined) {
        // Dropped rather than queued: the peer is gone, and the client will see
        // `peer-left` and either re-pair or give up. Buffering for a peer that may
        // never return is how a relay grows unbounded memory.
        return
      }
      peer.sendPayload(message.d)
      return
    }
    if (message.t === RELAY_MESSAGE.join || message.t === RELAY_MESSAGE.auth) {
      this.refuse(RELAY_ERROR.badMessage, 'this connection has already joined an invite')
      return
    }
    this.refuse(RELAY_ERROR.badMessage, `unknown message ${JSON.stringify(message.t)}`)
  }

  /** Forward one opaque payload to the peer, without inspecting it. */
  sendPayload(payload) {
    this.send({ t: RELAY_MESSAGE.peer, d: payload })
  }

  /** Tell the peer that its counterpart has arrived. */
  notifyPeerPresent() {
    this.send({ t: RELAY_MESSAGE.presence, state: PRESENCE.peerJoined })
  }

  /** Release this connection's role exactly once. */
  handleClosed() {
    if (this.timer !== undefined) {
      clearTimeout(this.timer)
      this.timer = undefined
    }
    if (this.released) return
    this.released = true
    this.ws.off('message', this.onMessage)
    this.ws.off('close', this.onClose)
    this.ws.off('error', this.onError)
    if (this.slot !== undefined && this.role !== undefined) {
      const { peer } = this.registry.release(this.slot, this.role)
      this.log.info('left', { invite: this.invitePrefix, role: this.role })
      if (peer !== undefined && peer !== this) {
        try {
          peer.send({ t: RELAY_MESSAGE.presence, state: PRESENCE.peerLeft })
        } catch {
          /* the peer is going away too */
        }
      }
    }
    this.slot = undefined
    this.secret = undefined
    this.onClosed?.(this)
  }
}

/** @returns 16 random hex characters. */
function randomHex() {
  return randomBytes(8).toString('hex')
}

/**
 * Constant-time comparison of two hex digests.
 *
 * A length mismatch returns false without comparing, because `timingSafeEqual`
 * throws on unequal lengths; the length is fixed by the protocol, so nothing is
 * leaked by checking it.
 *
 * @param a - the candidate digest.
 * @param b - the expected digest.
 * @returns true only when both are non-empty and byte-identical.
 */
function constantTimeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length === 0 || a.length !== b.length) return false
  const left = Buffer.from(a, 'utf8')
  const right = Buffer.from(b, 'utf8')
  if (left.length !== right.length) return false
  return timingSafeEqual(left, right)
}

/**
 * Build one relay instance.
 *
 * Returned un-listened so a test can bind an ephemeral port and a deployment can
 * bind a fixed one from the same code path.
 *
 * @param overrides - configuration overrides (used by tests).
 * @returns `{ server, registry, log, config, listen, close, stats }`.
 */
export function createRelay(overrides = {}) {
  const config = resolveRelayConfig(overrides)
  const log = overrides.logger ?? new RelayLog(config.logLevel, overrides.sink)
  const registry = new InviteRegistry({ ttlMs: config.inviteTtlMs, maxSlots: config.maxInvites })
  /** @type {Map<string, number>} */
  const perIp = new Map()
  /**
   * Failed rendezvous proofs per client address, with the window they fall in.
   *
   * This is the defence a nine-digit device code depends on. 10^9 is enumerable, so
   * the only thing standing between a typed code and an attacker is that guessing
   * costs a connection and the password still carries 60 bits — which means the
   * failure rate has to be capped, or an attacker simply never stops. The counter is
   * per ADDRESS rather than per slot so that one noisy client cannot lock a
   * legitimate host's card out.
   *
   * @type {Map<string, { count: number, since: number }>}
   */
  const authFailures = new Map()
  let connections = 0

  /**
   * Record one failed proof and report whether the address is now over budget.
   * @param ip - the client address.
   * @returns true when further attempts from this address should be refused.
   */
  const recordAuthFailure = (ip) => {
    const now = Date.now()
    const entry = authFailures.get(ip)
    if (entry === undefined || now - entry.since > config.authFailureWindowMs) {
      authFailures.set(ip, { count: 1, since: now })
      return false
    }
    entry.count += 1
    return entry.count > config.maxAuthFailuresPerIp
  }

  /**
   * Whether one address is currently throttled.
   * @param ip - the client address.
   * @returns true when it should be refused until the window rolls over.
   */
  const isThrottled = (ip) => {
    const entry = authFailures.get(ip)
    if (entry === undefined) return false
    if (Date.now() - entry.since > config.authFailureWindowMs) {
      authFailures.delete(ip)
      return false
    }
    return entry.count > config.maxAuthFailuresPerIp
  }

  const sweepTimer = setInterval(() => {
    const removed = registry.sweep()
    if (removed > 0) log.debug('swept', { removed })
  }, Math.max(30000, Math.min(config.inviteTtlMs, 60000)))
  sweepTimer.unref?.()

  /** @returns the client address, honouring X-Forwarded-For only when trusted. */
  const clientIpOf = (req) => {
    if (config.trustProxy) {
      const forwarded = req.headers['x-forwarded-for']
      const first = Array.isArray(forwarded) ? forwarded[0] : forwarded
      if (typeof first === 'string' && first.length > 0) return first.split(',')[0].trim()
    }
    return req.socket?.remoteAddress ?? 'unknown'
  }

  /** Answer one registration request. */
  const handleRegister = (req, res) => {
    if (req.method !== 'POST') {
      respond(res, 405, { code: 'method-not-allowed', message: 'use POST' })
      return
    }
    const chunks = []
    let size = 0
    let aborted = false
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > config.maxHttpBodyBytes) {
        aborted = true
        respond(res, 413, { code: 'body-too-large', message: 'the registration body is too large' })
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      if (aborted) return
      const decoded = parseJson(Buffer.concat(chunks).toString('utf8'))
      if (!decoded.ok) {
        respond(res, 400, { code: RELAY_ERROR.badMessage, message: decoded.error })
        return
      }
      const body = decoded.value
      if (body?.v !== undefined && body.v !== RELAY_VERSION) {
        respond(res, 400, {
          code: RELAY_ERROR.versionMismatch,
          message: `this relay speaks v${String(RELAY_VERSION)}; the client asked for v${String(body.v)}`,
        })
        return
      }
      try {
        const receipt = registry.register(body)
        log.info(receipt.rotated === true ? 'rotated' : 'registered', {
          invite: idPrefix(receipt.inviteId),
          expiresAt: receipt.expiresAt,
          ...(receipt.reRegistered === true ? { reRegistered: true } : {}),
        })
        respond(res, 201, {
          ok: true,
          v: RELAY_VERSION,
          inviteId: receipt.inviteId,
          expiresAt: receipt.expiresAt,
          reRegistered: receipt.reRegistered === true,
          rotated: receipt.rotated === true,
        })
      } catch (error) {
        const registryError = error instanceof RegistryError ? error : new RegistryError(RELAY_ERROR.badMessage, String(error))
        const status = registryError.code === RELAY_ERROR.rateLimited ? 503 : 409
        log.warn('registration-refused', { code: registryError.code })
        respond(res, status, { code: registryError.code, message: registryError.message })
      }
    })
    req.on('error', () => {
      /* the socket died mid-body; nothing to answer */
    })
  }

  const handler = (req, res) => {
    let url
    try {
      url = new URL(req.url ?? '/', 'http://relay.invalid')
    } catch {
      respond(res, 400, { code: RELAY_ERROR.badMessage, message: 'unparseable request target' })
      return
    }
    if (url.pathname === RELAY_HEALTH_PATH) {
      // Unauthenticated on purpose, and containing no invite id: a health check
      // must work from a load balancer that has no credentials.
      respond(res, 200, { ok: true, v: RELAY_VERSION, ...registry.stats(), connections })
      return
    }
    if (url.pathname === RELAY_INVITE_PATH) {
      handleRegister(req, res)
      return
    }
    respond(res, 404, { code: 'not-found', message: 'unknown endpoint' })
  }

  const server = config.tls === undefined ? createHttpServer(handler) : createHttpsServer({ cert: config.tls.cert, key: config.tls.key }, handler)

  server.on('upgrade', (req, socket, head) => {
    const ip = clientIpOf(req)
    let inviteId
    try {
      const url = new URL(req.url ?? '/', 'http://relay.invalid')
      const prefix = `${RELAY_CHANNEL_PATH}/`
      if (!url.pathname.startsWith(prefix)) {
        refuseUpgrade(socket, 404, 'Not Found')
        return
      }
      inviteId = decodeURIComponent(url.pathname.slice(prefix.length))
    } catch {
      refuseUpgrade(socket, 400, 'Bad Request')
      return
    }
    // One pattern for both pairing modes: a 32-hex invite id and a nine-digit device
    // code are the same thing to the relay — an opaque slot key — and validating only
    // the QR shape here refused every typed pairing with a bare 400 before a single
    // protocol frame was exchanged.
    if (!/^[0-9a-z]{4,64}$/.test(inviteId)) {
      refuseUpgrade(socket, 400, 'Bad Request')
      return
    }
    if (connections >= config.maxConnections) {
      log.warn('connection-refused', { reason: 'max-connections' })
      refuseUpgrade(socket, 503, 'Service Unavailable')
      return
    }
    // Checked BEFORE the protocol switch, so a guessing client never even gets a
    // challenge: the cheap refusal is the one that scales.
    if (isThrottled(ip)) {
      log.warn('connection-refused', { reason: 'auth-failures', invite: idPrefix(inviteId) })
      refuseUpgrade(socket, 429, 'Too Many Requests')
      return
    }
    const forIp = perIp.get(ip) ?? 0
    if (forIp >= config.maxConnectionsPerIp) {
      log.warn('connection-refused', { reason: 'max-connections-per-ip' })
      refuseUpgrade(socket, 429, 'Too Many Requests')
      return
    }

    let connection
    try {
      connection = acceptWebSocket(req, socket, head, { maxPayload: config.maxFrameBytes, label: `relay:${idPrefix(inviteId)}` })
    } catch (error) {
      log.warn('upgrade-failed', { reason: String(error?.message ?? error) })
      refuseUpgrade(socket, 400, 'Bad Request')
      return
    }
    connections += 1
    perIp.set(ip, forIp + 1)
    log.debug('connected', { invite: idPrefix(inviteId), ip })
    // The connection owns its own lifecycle: it removes itself from the counters
    // through `onClosed`, and nothing here holds a reference to it afterwards.
    new RelayConnection({
      ws: connection,
      ip,
      pathInviteId: inviteId,
      registry,
      config,
      log,
      onAuthFailure: () => recordAuthFailure(ip),
      onClosed: () => {
        connections -= 1
        const remaining = (perIp.get(ip) ?? 1) - 1
        if (remaining <= 0) perIp.delete(ip)
        else perIp.set(ip, remaining)
      },
    })
  })

  return {
    server,
    registry,
    log,
    config,
    /** Bind the listener. @returns a promise for the bound address. */
    listen() {
      return new Promise((resolve, reject) => {
        const onError = (error) => reject(error)
        server.once('error', onError)
        server.listen({ host: config.host, port: config.port }, () => {
          server.removeListener('error', onError)
          const address = server.address()
          log.info('listening', { host: address.address, port: address.port, tls: config.tls !== undefined })
          resolve(address)
        })
      })
    },
    /** Stop the listener and forget every invite. @returns a promise. */
    close() {
      clearInterval(sweepTimer)
      registry.clear()
      return new Promise((resolve) => {
        server.close(() => resolve())
        // Sockets held open by an idle client would otherwise keep `close` pending
        // until each one times out, which for a health check looks like a hang.
        server.closeAllConnections?.()
      })
    },
    /** @returns the health document. */
    stats() {
      return { ok: true, v: RELAY_VERSION, ...registry.stats(), connections }
    },
  }
}

/** Write one JSON response with no caching. */
function respond(res, status, body) {
  const text = JSON.stringify(body)
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': String(Buffer.byteLength(text)) })
  res.end(text)
}

/** Refuse an upgrade before the protocol switch, with a plain HTTP response. */
function refuseUpgrade(socket, status, reason) {
  try {
    socket.write(`HTTP/1.1 ${String(status)} ${reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`)
  } catch {
    /* the socket is already gone */
  }
  socket.destroy()
}

export { RELAY_ERROR, RELAY_VERSION }
