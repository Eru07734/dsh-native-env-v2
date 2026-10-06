/**
 * dsh-net-bridge / wire — newline-delimited JSON-RPC 2.0 over caller-owned byte
 * streams.
 *
 * Why this file exists instead of importing `@deepseek-ai/dsh-sdk-protocol`:
 * a `file:`-installed / absolute-path-mounted plugin resolves bare specifiers
 * from its own real path, where the first-party packages are not visible. The
 * plugin is therefore zero-dependency, and this class reproduces the observable
 * semantics of the first-party `JsonRpcLineTransport` exactly:
 *
 *   - one JSON-RPC 2.0 message per `\n`-terminated line;
 *   - `id`+`method` is a request, `id` alone is a response, `method` alone is a
 *     notification; malformed lines are ignored;
 *   - a request with no registered handler answers `-32601`, a handler failure
 *     answers `-32603`, and an error response rejects the pending request with
 *     {@link WireResponseError} preserving the wire `code` and `data`;
 *   - `start()` attaches input listeners, `close()` detaches them and rejects
 *     every pending request without destroying the streams.
 *
 * A `net.Socket` satisfies both roles: it emits `data`/`error`/`end`/`close`
 * and it has `write(string, callback)`. The decoder handles Buffer chunks, so
 * no `setEncoding` is required on either side.
 *
 * @module dsh-net-bridge/wire
 */

import { randomUUID } from 'node:crypto'
import { StringDecoder } from 'node:string_decoder'

/** A JSON-RPC error response, preserving the wire `code` and optional `data`. */
export class WireResponseError extends Error {
  /**
   * @param code - the wire error code, or `undefined` when the peer sent none.
   * @param message - the wire error message.
   * @param data - the optional structured error payload, verbatim.
   */
  constructor(code, message, data) {
    super(message)
    this.name = 'WireResponseError'
    this.code = code
    this.data = data
  }
}

/** Normalize a JSON-RPC `params` value to a plain object. */
function objectParams(params) {
  return params !== null && typeof params === 'object' && !Array.isArray(params) ? params : {}
}

/** Normalize an abort reason into the rejection Error. */
function abortError(reason) {
  return reason instanceof Error ? reason : new Error(`JSON-RPC request aborted: ${String(reason)}`)
}

/**
 * Line-delimited JSON-RPC endpoint over caller-owned streams.
 *
 * Every method mirrors the first-party transport; the additions are counters
 * (`counts`) and an optional `onMalformed` hook, both used for observability by
 * the bridge (dropped/garbage frames are otherwise invisible).
 */
export class LineWire {
  /**
   * @param input - a stream emitting `data`/`error`/`end` (a socket or a child
   *   process stream).
   * @param output - a stream with `write(string, callback)` (the same socket, or
   *   a child's stdin).
   * @param hooks - optional `onMalformed(line)` and `onFrame(direction, message)`
   *   observers; both are contained (a throwing hook cannot break framing).
   */
  constructor(input, output, hooks = {}) {
    this.input = input
    this.output = output
    this.onMalformed = hooks.onMalformed
    this.onFrame = hooks.onFrame
    this.onDisconnect = hooks.onDisconnect
    this.maxMessageBytes = Number.isInteger(hooks.maxMessageBytes) && hooks.maxMessageBytes > 0 ? hooks.maxMessageBytes : 4 * 1024 * 1024

    this.buffer = ''
    this.decoder = new StringDecoder('utf8')
    this.started = false
    this.closed = false
    this.disconnected = false

    this.requestHandler = undefined
    this.notificationHandler = undefined
    this.pending = new Map()

    /** Frame counters for status reporting. */
    this.counts = {
      requestsIn: 0,
      notificationsIn: 0,
      responsesIn: 0,
      framesOut: 0,
      malformed: 0,
    }

    this.handleData = (chunk) => {
      this.buffer += typeof chunk === 'string' ? chunk : this.decoder.write(chunk)
      this.drainLines()
      if (!this.disconnected && Buffer.byteLength(this.buffer, 'utf8') > this.maxMessageBytes) {
        this.disconnect(new Error(`JSON-RPC frame exceeds ${this.maxMessageBytes} bytes`))
      }
    }
    this.handleError = (error) => {
      this.disconnect(error instanceof Error ? error : new Error(String(error)))
    }
    this.handleEnd = () => {
      this.buffer += this.decoder.end()
      this.drainLines()
      this.disconnect(new Error('JSON-RPC input closed'))
    }
    this.handleClose = () => {
      this.disconnect(new Error('JSON-RPC transport closed'))
    }
    this.handleOutputError = (error) => {
      this.disconnect(error instanceof Error ? error : new Error(String(error)))
    }
  }

  /** Attach the input listeners. Idempotent; a closed wire never re-opens. */
  start() {
    if (this.started || this.closed || this.disconnected) return
    this.started = true
    this.input.on('data', this.handleData)
    this.input.on('error', this.handleError)
    this.input.on('end', this.handleEnd)
    this.input.on('close', this.handleClose)
    if (this.output !== this.input) this.output.on?.('error', this.handleOutputError)
  }

  /**
   * Detach the input listeners and reject every pending request.
   * Safe before {@link start}; idempotent.
   * @param reason - rejection carried to pending requests (default: closed).
   */
  close(reason) {
    if (this.closed) return
    this.closed = true
    this.input.off('data', this.handleData)
    this.input.off('error', this.handleError)
    this.input.off('end', this.handleEnd)
    this.input.off('close', this.handleClose)
    if (this.output !== this.input) this.output.off?.('error', this.handleOutputError)
    this.failPending(reason instanceof Error ? reason : new Error('JSON-RPC transport closed'))
  }

  /**
   * Install the request handler, replacing any prior handler.
   * @param handler - resolves to the response `result`; a rejection becomes a
   *   `-32603` error response carrying the message.
   */
  onRequest(handler) {
    this.requestHandler = handler
  }

  /**
   * Install the notification handler, replacing any prior handler.
   * @param handler - invoked per notification with the method and normalized
   *   params object.
   */
  onNotification(handler) {
    this.notificationHandler = handler
  }

  /**
   * Send a request and await its response.
   * @param method - the JSON-RPC method name.
   * @param params - the request parameters object.
   * @param signal - optional abandonment signal: aborting removes the pending
   *   entry and rejects with the signal's reason.
   * @returns the `result` value; rejects with {@link WireResponseError} on an
   *   error response.
   */
  request(method, params, signal) {
    const id = `req_${randomUUID().replaceAll('-', '')}`
    const message = { jsonrpc: '2.0', id, method, params }
    return new Promise((resolve, reject) => {
      let detach = () => {}
      if (signal !== undefined) {
        if (signal.aborted) {
          reject(abortError(signal.reason))
          return
        }
        const onAbort = () => {
          this.pending.delete(id)
          reject(abortError(signal.reason))
        }
        signal.addEventListener('abort', onAbort, { once: true })
        detach = () => {
          signal.removeEventListener('abort', onAbort)
        }
      }
      this.pending.set(id, {
        resolve: (value) => {
          detach()
          resolve(value)
        },
        reject: (error) => {
          detach()
          reject(error)
        },
      })
      if (!this.safeWrite(message)) {
        this.pending.delete(id)
        detach()
        reject(new Error('JSON-RPC transport disconnected while writing'))
      }
    })
  }

  /**
   * Send a notification (no response is expected).
   * @param method - the JSON-RPC method name.
   * @param params - optional parameters object.
   */
  notify(method, params) {
    return this.safeWrite(params === undefined ? { jsonrpc: '2.0', method } : { jsonrpc: '2.0', method, params })
  }

  /**
   * Wait for prior frame write callbacks. The empty barrier emits no bytes.
   * @returns a promise settling with the output write callback.
   */
  flush() {
    return new Promise((resolve, reject) => {
      if (this.closed || this.disconnected) return reject(new Error('JSON-RPC transport is closed'))
      try {
        this.output.write('', (error) => {
          if (error) {
            this.disconnect(error instanceof Error ? error : new Error(String(error)))
            reject(error)
          } else resolve()
        })
      } catch (error) {
        this.disconnect(error instanceof Error ? error : new Error(String(error)))
        reject(error)
      }
    })
  }

  /** Number of requests awaiting a response. */
  get pendingCount() {
    return this.pending.size
  }

  /** Feed raw text that arrived before {@link start} (used by the pre-auth reader). */
  pushRaw(text) {
    if (typeof text !== 'string' || text.length === 0) return
    this.buffer += text
    this.drainLines()
  }

  /** Split the buffer into complete lines and dispatch each frame. */
  drainLines() {
    for (;;) {
      const newline = this.buffer.indexOf('\n')
      if (newline < 0) break
      const line = this.buffer.slice(0, newline).trim()
      this.buffer = this.buffer.slice(newline + 1)
      if (!line) continue
      if (Buffer.byteLength(line, 'utf8') > this.maxMessageBytes) {
        this.disconnect(new Error(`JSON-RPC message exceeds ${this.maxMessageBytes} bytes`))
        return
      }
      this.handleLine(line)
    }
  }

  /** Parse and route one frame. Malformed input is counted and ignored. */
  handleLine(line) {
    let message
    try {
      message = JSON.parse(line)
    } catch {
      this.counts.malformed += 1
      this.onMalformed?.(line)
      return
    }
    if (message === null || typeof message !== 'object') {
      this.counts.malformed += 1
      this.onMalformed?.(line)
      return
    }
    const id = message.id
    const method = message.method
    const hasId = typeof id === 'string' || typeof id === 'number'
    if (hasId && typeof method === 'string') {
      this.counts.requestsIn += 1
      this.handleIncomingRequest(id, method, objectParams(message.params))
      return
    }
    if (hasId) {
      this.counts.responsesIn += 1
      this.handleIncomingResponse(id, message)
      return
    }
    if (typeof method === 'string') {
      this.counts.notificationsIn += 1
      this.notificationHandler?.(method, objectParams(message.params))
    }
  }

  /** Dispatch one incoming request through the installed handler. */
  async handleIncomingRequest(id, method, params) {
    const handler = this.requestHandler
    if (handler === undefined) {
      this.writeError(id, -32601, `method not found: ${method}`)
      return
    }
    try {
      const result = await handler(method, params)
      this.safeWrite({ jsonrpc: '2.0', id, result })
    } catch (error) {
      this.writeError(id, -32603, error instanceof Error ? error.message : String(error))
    }
  }

  /** Settle one pending request from a response frame. */
  handleIncomingResponse(id, frame) {
    const pending = this.pending.get(id)
    if (pending === undefined) return
    this.pending.delete(id)
    if (frame.error !== null && typeof frame.error === 'object') {
      const error = frame.error
      pending.reject(
        new WireResponseError(
          typeof error.code === 'number' ? error.code : undefined,
          typeof error.message === 'string' ? error.message : 'JSON-RPC error',
          error.data,
        ),
      )
      return
    }
    pending.resolve(frame.result)
  }

  /** Write one error response. */
  writeError(id, code, message) {
    this.safeWrite({ jsonrpc: '2.0', id, error: { code, message } })
  }

  /** Write one frame as a single line. */
  write(message) {
    if (this.closed || this.disconnected) throw new Error('JSON-RPC transport is closed')
    const serialized = `${JSON.stringify(message)}\n`
    if (Buffer.byteLength(serialized, 'utf8') > this.maxMessageBytes) throw new Error(`JSON-RPC message exceeds ${this.maxMessageBytes} bytes`)
    this.counts.framesOut += 1
    this.onFrame?.('out', message)
    this.output.write(serialized)
  }

  /** Write without allowing EPIPE/socket reset to escape into DSH. */
  safeWrite(message) {
    if (this.closed || this.disconnected) return false
    try {
      this.write(message)
      return true
    } catch (error) {
      this.disconnect(error instanceof Error ? error : new Error(String(error)))
      return false
    }
  }

  /** Mark the wire offline exactly once and notify the owning client. */
  disconnect(reason) {
    if (this.disconnected) return
    this.disconnected = true
    this.failPending(reason instanceof Error ? reason : new Error(String(reason)))
    try {
      this.onDisconnect?.(reason instanceof Error ? reason : new Error(String(reason)))
    } catch {
      /* disconnect observers are contained; a broken observer cannot crash DSH */
    }
  }

  /** Reject every pending request with one error. */
  failPending(error) {
    const pending = [...this.pending.values()]
    this.pending.clear()
    for (const waiter of pending) waiter.reject(error)
  }
}
