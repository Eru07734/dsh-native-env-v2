/**
 * dsh-native-env / ws — a minimal RFC 6455 endpoint, both roles.
 *
 * Why not `ws`: the two plugin halves are mounted by ABSOLUTE PATH and therefore
 * cannot resolve a bare specifier at all (`wire.js` explains this at length, and
 * `tests/guest-closure.test.mjs` enforces it). `ws` is not installed next to the
 * plugin and cannot be. Node's global `WebSocket` exists only from v22 and would
 * silently be `undefined` on a v20 guest — which is precisely the machine most
 * likely to be the guest. So the framing is implemented here, in `node:` builtins,
 * once, and both the plugin and the relay use it.
 *
 * Scope is deliberately narrow, because every unneeded feature is attack surface
 * and code nobody tests:
 *
 *   - text messages only (`send` takes and emits strings);
 *   - no extensions, so `Sec-WebSocket-Extensions` is never sent — no
 *     permessage-deflate, no compression oracle;
 *   - no subprotocols;
 *   - control frames handled (ping/pong/close), fragmentation accepted on input,
 *     but nothing is ever fragmented on output: every message this protocol sends
 *     is a single frame;
 *   - masking is ENFORCED in both directions, as the RFC requires, rather than
 *     tolerated. A server that accepted an unmasked client frame, or a client
 *     that accepted a masked server frame, would be speaking a different protocol
 *     than the one the relay was reviewed against;
 *   - a payload ceiling is applied BEFORE the buffer grows, so a hostile peer
 *     cannot make us allocate a 1 GiB frame header's worth of memory.
 *
 * @module dsh-native-env/ws
 */

import { EventEmitter } from 'node:events'
import { createHash, randomBytes } from 'node:crypto'
import { connect as netConnect } from 'node:net'
import { connect as tlsConnect } from 'node:tls'

/** The magic GUID the RFC appends to the client key when computing the accept. */
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

/** Opcodes this endpoint understands. */
const OP_CONTINUATION = 0x0
const OP_TEXT = 0x1
const OP_BINARY = 0x2
const OP_CLOSE = 0x8
const OP_PING = 0x9
const OP_PONG = 0xa

/** The default ceiling for one frame. env payloads are capped well below this. */
export const DEFAULT_MAX_PAYLOAD = 8 * 1024 * 1024

/** The default handshake deadline. */
export const DEFAULT_HANDSHAKE_TIMEOUT_MS = 10000

/** Connection states, mirroring the browser API's numbering. */
export const STATE = Object.freeze({ CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3 })

/**
 * A WebSocket protocol violation.
 *
 * Distinct from an ordinary socket error because the correct response differs:
 * a violation means the peer is not speaking this protocol and the connection
 * must be failed with a close code, while a socket error just means the network
 * went away.
 */
export class WsProtocolError extends Error {
  /**
   * @param message - what the peer did wrong.
   * @param code - the close code to fail the connection with.
   */
  constructor(message, code = 1002) {
    super(message)
    this.name = 'WsProtocolError'
    this.closeCode = code
  }
}

/**
 * Compute the `Sec-WebSocket-Accept` value for one client key.
 * @param key - the `Sec-WebSocket-Key` header.
 * @returns the base64 SHA-1 the RFC prescribes.
 */
export function computeAccept(key) {
  return createHash('sha1').update(`${String(key)}${WS_GUID}`).digest('base64')
}

/**
 * Whether one HTTP request is a WebSocket upgrade we can serve.
 *
 * The check is deliberately strict about the version: this endpoint implements
 * 13 only, and answering anything else with a 101 would be a lie.
 *
 * @param req - the HTTP request.
 * @returns true when the request is a v13 websocket upgrade.
 */
export function isWebSocketUpgrade(req) {
  const upgrade = String(req?.headers?.upgrade ?? '').toLowerCase()
  const connection = String(req?.headers?.connection ?? '').toLowerCase()
  const version = String(req?.headers?.['sec-websocket-version'] ?? '')
  return upgrade === 'websocket' && connection.includes('upgrade') && version === '13' && typeof req?.headers?.['sec-websocket-key'] === 'string'
}

/**
 * One WebSocket endpoint over an established byte stream.
 *
 * Emits `open`, `message` (a string), `close`, and `error`. `send` throws when
 * the connection is not open, because silently dropping a frame would desynchronize
 * a JSON-RPC peer in a way that only shows up as a hang.
 */
export class WebSocketConnection extends EventEmitter {
  /**
   * @param options.socket - the connected stream.
   * @param options.mask - true when this endpoint must mask outgoing frames.
   * @param options.maxPayload - the per-frame ceiling.
   * @param options.label - a short description for diagnostics.
   */
  constructor(options) {
    super()
    this.socket = options.socket
    this.mask = options.mask === true
    this.maxPayload = Number.isSafeInteger(options.maxPayload) ? options.maxPayload : DEFAULT_MAX_PAYLOAD
    this.label = options.label ?? 'websocket'

    this.state = STATE.CONNECTING
    this.buffered = Buffer.alloc(0)
    /** Fragments of an in-progress message. */
    this.fragments = []
    this.fragmentOpcode = undefined
    this.closeSent = false
    this.closeReceived = false

    this.onData = (chunk) => this.feed(chunk)
    this.onError = (error) => this.fail(error instanceof Error ? error : new Error(String(error)))
    this.onEnd = () => {
      if (this.state !== STATE.CLOSED) this.emit('close', { code: 1006, reason: 'the transport ended' })
      this.destroy()
    }
    this.socket.on('data', this.onData)
    this.socket.on('error', this.onError)
    this.socket.on('end', this.onEnd)
    this.socket.on('close', this.onEnd)
    this.state = STATE.OPEN
    // `open` is emitted asynchronously so a caller that attaches its listener
    // after construction still sees it, which is what every caller does.
    queueMicrotask(() => {
      if (this.state === STATE.OPEN) this.emit('open')
    })
  }

  /** @returns true when frames can be sent. */
  get open() {
    return this.state === STATE.OPEN
  }

  /**
   * Send one text message.
   * @param text - the message body.
   * @throws {Error} when the connection is not open.
   */
  send(text) {
    if (this.state !== STATE.OPEN) throw new Error(`${this.label}: cannot send, the connection is not open`)
    this.writeFrame(OP_TEXT, Buffer.from(String(text), 'utf8'))
  }

  /**
   * Send one ping. The peer's pong is surfaced as a `pong` event.
   * @param payload - up to 125 bytes.
   */
  ping(payload = Buffer.alloc(0)) {
    if (this.state !== STATE.OPEN) return
    this.writeFrame(OP_PING, Buffer.from(payload).subarray(0, 125))
  }

  /**
   * Begin a close handshake.
   * @param code - the close code.
   * @param reason - a short reason; truncated to fit a control frame.
   */
  close(code = 1000, reason = '') {
    if (this.state === STATE.CLOSED) return
    if (!this.closeSent) {
      this.closeSent = true
      const body = Buffer.alloc(2 + Buffer.byteLength(reason))
      body.writeUInt16BE(code, 0)
      body.write(reason, 2, 'utf8')
      try {
        this.writeFrame(OP_CLOSE, body.subarray(0, 125))
      } catch {
        /* the transport is already gone; the close is best effort */
      }
    }
    this.state = STATE.CLOSING
    // A peer that never answers the close handshake must not hold the socket
    // open indefinitely; the RFC's own prescription is to drop it.
    const timer = setTimeout(() => this.destroy(), 5000)
    timer.unref?.()
  }

  /** Drop the socket without a handshake. Safe to call repeatedly. */
  destroy() {
    if (this.state === STATE.CLOSED) return
    const wasOpen = this.state === STATE.OPEN
    this.state = STATE.CLOSED
    this.socket.off('data', this.onData)
    this.socket.off('error', this.onError)
    this.socket.off('end', this.onEnd)
    this.socket.off('close', this.onEnd)
    try {
      this.socket.destroy()
    } catch {
      /* already gone */
    }
    if (wasOpen) this.emit('close', { code: 1006, reason: 'destroyed locally' })
  }

  /**
   * Surface a fatal error and drop the connection.
   *
   * The emit is GUARDED because Node throws when an `'error'` event has no
   * listener. A socket that fails while nobody is attached yet would then take
   * the whole runtime down — a teardown failure turning into a process crash is
   * strictly worse than the original error.
   *
   * @param error - the cause.
   */
  fail(error) {
    if (this.state === STATE.CLOSED) return
    if (this.listenerCount('error') > 0) this.emit('error', error)
    this.destroy()
  }

  /**
   * Encode and write one frame.
   *
   * @param opcode - the frame opcode.
   * @param payload - the frame body.
   */
  writeFrame(opcode, payload) {
    const length = payload.length
    let header
    if (length < 126) {
      header = Buffer.alloc(2)
      header[1] = length
    } else if (length < 65536) {
      header = Buffer.alloc(4)
      header[1] = 126
      header.writeUInt16BE(length, 2)
    } else {
      header = Buffer.alloc(10)
      header[1] = 127
      header.writeBigUInt64BE(BigInt(length), 2)
    }
    header[0] = 0x80 | opcode
    let frame
    if (this.mask) {
      header[1] |= 0x80
      const key = randomBytes(4)
      frame = Buffer.concat([header, key, applyMask(payload, key)])
    } else {
      frame = Buffer.concat([header, payload])
    }
    this.socket.write(frame)
  }

  /**
   * Feed raw bytes into the frame parser.
   * @param chunk - bytes from the transport.
   */
  feed(chunk) {
    if (this.state === STATE.CLOSED) return
    this.buffered = this.buffered.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.buffered, chunk])
    try {
      this.drain()
    } catch (error) {
      if (error instanceof WsProtocolError) {
        this.close(error.closeCode, error.message)
        return
      }
      this.fail(error instanceof Error ? error : new Error(String(error)))
    }
  }

  /** Parse every complete frame currently buffered. */
  drain() {
    for (;;) {
      const frame = this.readFrame()
      if (frame === undefined) return
      this.handleFrame(frame)
      if (this.state === STATE.CLOSED) return
    }
  }

  /**
   * Read one frame out of the buffer, or `undefined` when it is incomplete.
   * @returns `{ fin, opcode, payload }`.
   */
  readFrame() {
    if (this.buffered.length < 2) return undefined
    const first = this.buffered[0]
    const second = this.buffered[1]
    const fin = (first & 0x80) !== 0
    const rsv = first & 0x70
    const opcode = first & 0x0f
    const masked = (second & 0x80) !== 0
    let length = second & 0x7f
    let offset = 2

    // RSV bits are only legal when an extension negotiated them, and this
    // endpoint negotiates none. A peer that sets one is speaking a different
    // protocol and must not be guessed at.
    if (rsv !== 0) throw new WsProtocolError('reserved bits were set without a negotiated extension')

    if (length === 126) {
      if (this.buffered.length < offset + 2) return undefined
      length = this.buffered.readUInt16BE(offset)
      offset += 2
    } else if (length === 127) {
      if (this.buffered.length < offset + 8) return undefined
      const big = this.buffered.readBigUInt64BE(offset)
      // A length above the payload ceiling is refused BEFORE allocating.
      if (big > BigInt(this.maxPayload)) throw new WsProtocolError(`frame exceeds the ${String(this.maxPayload)}-byte ceiling`, 1009)
      length = Number(big)
      offset += 8
    }
    if (length > this.maxPayload) throw new WsProtocolError(`frame exceeds the ${String(this.maxPayload)}-byte ceiling`, 1009)

    const isControl = (opcode & 0x8) !== 0
    if (isControl && (length > 125 || !fin)) {
      throw new WsProtocolError('a control frame must be final and at most 125 bytes')
    }

    // Masking is mandatory in exactly one direction per role. Enforcing it is
    // what keeps this endpoint interoperable with real clients and servers.
    if (this.mask && masked) throw new WsProtocolError('a client must not receive a masked frame')
    if (!this.mask && !masked) throw new WsProtocolError('a client frame must be masked')

    const maskKey = masked ? this.buffered.subarray(offset, offset + 4) : undefined
    if (masked) offset += 4
    if (this.buffered.length < offset + length) return undefined

    const payload = this.buffered.subarray(offset, offset + length)
    this.buffered = this.buffered.subarray(offset + length)
    return { fin, opcode, payload: masked ? applyMask(payload, maskKey) : Buffer.from(payload) }
  }

  /**
   * Dispatch one decoded frame.
   * @param frame - `{ fin, opcode, payload }`.
   */
  handleFrame(frame) {
    const { fin, opcode, payload } = frame
    if (opcode === OP_CLOSE) {
      this.closeReceived = true
      const code = payload.length >= 2 ? payload.readUInt16BE(0) : 1005
      const reason = payload.length > 2 ? payload.subarray(2).toString('utf8') : ''
      if (!this.closeSent) {
        this.closeSent = true
        try {
          this.writeFrame(OP_CLOSE, payload.subarray(0, 125))
        } catch {
          /* best effort */
        }
      }
      this.state = STATE.CLOSED
      this.socket.off('data', this.onData)
      try {
        this.socket.destroy()
      } catch {
        /* already gone */
      }
      this.emit('close', { code, reason })
      return
    }
    if (opcode === OP_PING) {
      this.writeFrame(OP_PONG, payload)
      return
    }
    if (opcode === OP_PONG) {
      this.emit('pong', payload)
      return
    }
    if (opcode === OP_TEXT || opcode === OP_BINARY) {
      if (this.fragmentOpcode !== undefined) throw new WsProtocolError('a new data frame started before the previous one finished')
      if (fin) {
        this.deliver(opcode, payload)
        return
      }
      this.fragmentOpcode = opcode
      this.fragments = [payload]
      return
    }
    if (opcode === OP_CONTINUATION) {
      if (this.fragmentOpcode === undefined) throw new WsProtocolError('a continuation frame arrived with nothing to continue')
      this.fragments.push(payload)
      if (this.fragments.reduce((total, part) => total + part.length, 0) > this.maxPayload) {
        throw new WsProtocolError(`message exceeds the ${String(this.maxPayload)}-byte ceiling`, 1009)
      }
      if (fin) {
        const opcodeOfMessage = this.fragmentOpcode
        const joined = Buffer.concat(this.fragments)
        this.fragmentOpcode = undefined
        this.fragments = []
        this.deliver(opcodeOfMessage, joined)
      }
      return
    }
    throw new WsProtocolError(`unknown opcode ${String(opcode)}`)
  }

  /**
   * Emit one complete message.
   *
   * A binary frame is surfaced as text rather than rejected: the env protocol is
   * text, and a peer that mislabels its frames is better served by a JSON parse
   * error naming the offending frame than by a message that silently vanishes.
   *
   * @param opcode - the message's opcode (unused beyond documentation; both data
   *   opcodes are delivered as text).
   * @param payload - the assembled body.
   */
  deliver(opcode, payload) {
    void opcode
    this.emit('message', payload.toString('utf8'))
  }
}

/**
 * XOR one payload with a 4-byte mask key.
 * @param payload - the bytes.
 * @param key - the 4-byte key.
 * @returns a new masked/unmasked buffer.
 */
function applyMask(payload, key) {
  const output = Buffer.allocUnsafe(payload.length)
  for (let index = 0; index < payload.length; index += 1) output[index] = payload[index] ^ key[index & 3]
  return output
}

/**
 * Dial one WebSocket endpoint.
 *
 * @param rawUrl - a `ws:` or `wss:` URL.
 * @param options.timeoutMs - handshake deadline.
 * @param options.maxPayload - frame ceiling.
 * @param options.tls - extra `tls.connect` options (`ca`, `servername`, `rejectUnauthorized`).
 * @returns a promise for the open connection.
 * @throws {WsProtocolError} when the peer answers something other than a valid 101.
 */
export function connectWebSocket(rawUrl, options = {}) {
  const url = new URL(String(rawUrl))
  if (url.protocol !== 'ws:' && url.protocol !== 'wss:') {
    throw new WsProtocolError(`a WebSocket URL must be ws: or wss:, got ${url.protocol}`, 1007)
  }
  const secure = url.protocol === 'wss:'
  const port = url.port === '' ? (secure ? 443 : 80) : Number(url.port)
  const path = `${url.pathname === '' ? '/' : url.pathname}${url.search}`
  const key = randomBytes(16).toString('base64')
  const timeoutMs = Number.isSafeInteger(options.timeoutMs) ? options.timeoutMs : DEFAULT_HANDSHAKE_TIMEOUT_MS

  return new Promise((resolve, reject) => {
    const socket = secure
      ? tlsConnect({
          host: url.hostname,
          port,
          servername: options.tls?.servername ?? url.hostname,
          ...(options.tls?.ca === undefined ? {} : { ca: options.tls.ca }),
          ...(options.tls?.rejectUnauthorized === undefined ? {} : { rejectUnauthorized: options.tls.rejectUnauthorized }),
        })
      : netConnect({ host: url.hostname, port })

    let settled = false
    let handshakeBuffer = Buffer.alloc(0)
    const timer = setTimeout(() => {
      finish(new Error(`the WebSocket handshake to ${url.host} timed out after ${String(timeoutMs)} ms`))
    }, timeoutMs)
    timer.unref?.()

    /** Settle the handshake exactly once, cleaning up the listeners. */
    function finish(error, connection) {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.off('error', onError)
      socket.off('connect', onConnect)
      socket.off('secureConnect', onConnect)
      socket.off('data', onHandshakeData)
      if (error !== undefined) {
        try {
          socket.destroy()
        } catch {
          /* already gone */
        }
        reject(error)
        return
      }
      resolve(connection)
    }

    const onError = (error) => finish(error instanceof Error ? error : new Error(String(error)))
    const onConnect = () => {
      socket.write(
        `GET ${path} HTTP/1.1\r\n` +
          `Host: ${url.host}\r\n` +
          `Upgrade: websocket\r\n` +
          `Connection: Upgrade\r\n` +
          `Sec-WebSocket-Key: ${key}\r\n` +
          `Sec-WebSocket-Version: 13\r\n` +
          `\r\n`,
      )
    }
    const onHandshakeData = (chunk) => {
      handshakeBuffer = Buffer.concat([handshakeBuffer, chunk])
      const end = handshakeBuffer.indexOf('\r\n\r\n')
      if (end < 0) {
        if (handshakeBuffer.length > 16384) finish(new Error('the WebSocket handshake response header is implausibly large'))
        return
      }
      const header = handshakeBuffer.subarray(0, end).toString('latin1')
      const rest = handshakeBuffer.subarray(end + 4)
      const lines = header.split('\r\n')
      const status = lines[0] ?? ''
      if (!/^HTTP\/1\.[01] 101\b/.test(status)) {
        finish(new Error(`the relay refused the WebSocket upgrade: ${status.trim() || '(no status line)'}`))
        return
      }
      const headers = new Map()
      for (const line of lines.slice(1)) {
        const colon = line.indexOf(':')
        if (colon < 0) continue
        headers.set(line.slice(0, colon).trim().toLowerCase(), line.slice(colon + 1).trim())
      }
      const accept = headers.get('sec-websocket-accept')
      if (accept !== computeAccept(key)) {
        finish(new Error('the relay answered an invalid Sec-WebSocket-Accept; this is not a WebSocket server'))
        return
      }
      if (headers.has('sec-websocket-extensions')) {
        finish(new Error('the relay negotiated an extension this client never offered'))
        return
      }
      socket.off('data', onHandshakeData)
      socket.off('error', onError)
      const connection = new WebSocketConnection({
        socket,
        mask: true,
        maxPayload: options.maxPayload,
        label: options.label ?? `ws:${url.host}`,
      })
      // `end`/`close` are already attached by the constructor; the error listener
      // is re-attached there too, so nothing is lost by removing ours above.
      if (rest.length > 0) connection.feed(rest)
      finish(undefined, connection)
    }

    socket.once('error', onError)
    if (secure) socket.once('secureConnect', onConnect)
    else socket.once('connect', onConnect)
    socket.on('data', onHandshakeData)
  })
}

/**
 * Complete a server-side upgrade on an accepted socket.
 *
 * The HTTP request has already been parsed by Node's HTTP server; `head` holds
 * any bytes it read past the header, which must be fed to the frame parser or the
 * peer's first frame is silently lost.
 *
 * @param req - the HTTP upgrade request.
 * @param socket - the accepted socket.
 * @param head - bytes already read past the request header.
 * @param options.maxPayload - frame ceiling.
 * @returns the open connection.
 * @throws {WsProtocolError} when the request is not a v13 upgrade.
 */
export function acceptWebSocket(req, socket, head, options = {}) {
  if (!isWebSocketUpgrade(req)) {
    throw new WsProtocolError('this is not a WebSocket v13 upgrade request', 1002)
  }
  const accept = computeAccept(req.headers['sec-websocket-key'])
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${accept}\r\n` +
      '\r\n',
  )
  const connection = new WebSocketConnection({
    socket,
    mask: false,
    maxPayload: options.maxPayload,
    label: options.label ?? 'ws:server',
  })
  if (head !== undefined && head.length > 0) connection.feed(head)
  return connection
}
