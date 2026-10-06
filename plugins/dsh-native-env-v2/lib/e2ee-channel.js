/**
 * dsh-native-env / e2ee-channel — the encrypted frame stream.
 *
 * This is the seam that lets the pairing transport reuse the ENTIRE existing env
 * implementation unchanged. `wire.js`'s `LineWire` already knows how to be a
 * JSON-RPC peer given only "an input that emits data" and "an output with
 * `write(string, callback)`" — it was written that way so a `net.Socket` and a
 * child's stdio could both back it. So the encrypted channel does not implement
 * JSON-RPC, timeouts, cancellation or error propagation a second time. It presents
 * the SAME shape over a relay, and every semantic the legacy transports have
 * (pending requests, malformed-frame counting, close rejecting in-flight calls)
 * is inherited rather than re-derived.
 *
 * One message per encrypted frame, and one line per message: the plaintext inside
 * a sealed frame is exactly one JSON-RPC line. That keeps the framing invariant
 * `LineWire` depends on ("one message per `\n`-terminated line") true across the
 * encryption boundary, so a frame that fails to decrypt can never be mistaken for
 * a partial line and silently joined to the next one.
 *
 * Sequence numbers are implicit and strictly increasing per direction. The relay
 * channel is ordered and reliable (WebSocket over TCP), so the receiver can
 * predict the sender's sequence exactly, and any gap, repeat or reorder fails the
 * GCM tag instead of being accepted. That is why no sequence number needs to
 * travel on the wire — and why an attacker cannot renumber one.
 *
 * @module dsh-native-env/e2ee-channel
 */

import { EventEmitter } from 'node:events'

import { CryptoFailure, keyForDirection, openFrame, sealFrame } from './e2ee.js'

/**
 * One encrypted, ordered, byte stream over an opaque payload transport.
 *
 * Emits `data` (a Buffer, always ending in a newline), `end` when the transport
 * goes away, and `error` on a cryptographic failure. It never emits `error`
 * without a listener: a Node `'error'` event with no handler throws, and a
 * decryption failure on a dying connection must not take the runtime down.
 */
export class E2eeStream extends EventEmitter {
  /**
   * @param options.send - `(payloadBase64: string) => void`, the opaque transport.
   * @param options.keys - `{ hostToGuest, guestToHost }` from `deriveSessionKeys`.
   * @param options.inviteId - the session's invite id, bound into every frame's AAD.
   * @param options.sendDirection - the direction THIS side seals with.
   * @param options.receiveDirection - the direction THIS side opens with.
   * @param options.sendIv - this side's 4-byte IV prefix.
   * @param options.receiveIv - the peer's 4-byte IV prefix.
   * @param options.label - a short description for diagnostics.
   */
  constructor(options) {
    super()
    this.send = options.send
    this.inviteId = options.inviteId
    // The two direction keys are resolved ONCE, here. Passing the key PAIR down to
    // `sealFrame` and letting it pick would put the direction-to-key mapping in the
    // crypto module, where `frameAad` already uses the direction for a different
    // purpose; keeping the selection at this seam is what makes "seal with the key
    // I send under, open with the key the peer sends under" a single readable line
    // instead of a coincidence.
    this.sendKey = keyForDirection(options.keys, options.sendDirection)
    this.receiveKey = keyForDirection(options.keys, options.receiveDirection)
    this.sendDirection = options.sendDirection
    this.receiveDirection = options.receiveDirection
    this.sendIv = options.sendIv
    this.receiveIv = options.receiveIv
    this.label = options.label ?? 'e2ee'
    this.sendSeq = 0
    this.receiveSeq = 0
    this.closed = false
  }

  /**
   * Seal and ship one chunk of stream data.
   *
   * The signature is `stream.write(string, callback)` because that is what
   * `LineWire` calls on its output. An empty write still invokes the callback —
   * `LineWire.flush()` is implemented as a zero-length write and would hang
   * forever otherwise.
   *
   * @param text - the chunk (one JSON-RPC line, with its trailing newline).
   * @param callback - invoked once the frames have been handed to the transport.
   */
  write(text, callback) {
    if (this.closed) {
      callback?.(new Error(`${this.label}: the channel is closed`))
      return false
    }
    try {
      for (const line of String(text).split('\n')) {
        if (line.length === 0) continue
        this.sendFrame(line)
      }
      callback?.()
      return true
    } catch (error) {
      const failure = error instanceof Error ? error : new Error(String(error))
      callback?.(failure)
      this.fail(failure)
      return false
    }
  }

  /**
   * Seal one already-single-line message and send it.
   *
   * Public because the pairing handshake writes its own messages before any
   * `LineWire` exists: the handshake runs INSIDE the encrypted channel (so the
   * relay never sees a hostname or a fingerprint), and that means the channel has
   * to be usable before the JSON-RPC layer is.
   *
   * @param line - the plaintext, one line, no trailing newline.
   */
  sendFrame(line) {
    if (this.closed) throw new Error(`${this.label}: the channel is closed`)
    this.sendSeq += 1
    const sealed = sealFrame(this.sendKey, this.sendIv, this.sendDirection, this.sendSeq, this.inviteId, line)
    this.send(sealed.toString('base64'))
  }

  /**
   * Open one incoming opaque payload.
   *
   * A failure is fatal to the channel on purpose: a frame that fails
   * authentication means the peer's numbering, the key, or the bytes are wrong,
   * and continuing would pair the plaintext of a later frame with the sequence of
   * an earlier one. The caller's pending requests are rejected by the `end` that
   * follows, exactly as a dropped socket rejects them.
   *
   * @param payload - the base64 payload the relay forwarded.
   */
  feed(payload) {
    if (this.closed) return
    this.receiveSeq += 1
    let plaintext
    try {
      plaintext = openFrame(this.receiveKey, this.receiveIv, this.receiveDirection, this.receiveSeq, this.inviteId, Buffer.from(payload, 'base64'))
    } catch (error) {
      this.fail(error instanceof Error ? error : new CryptoFailure('frame-auth-failed', String(error)))
      return
    }
    this.emit('data', Buffer.from(`${plaintext}\n`, 'utf8'))
  }

  /**
   * Fail the channel: report once, then end it.
   * @param error - the cause.
   */
  fail(error) {
    if (this.closed) return
    if (this.listenerCount('error') > 0) this.emit('error', error)
    this.end()
  }

  /** End the channel. Idempotent; the `end` event fires at most once. */
  end() {
    if (this.closed) return
    this.closed = true
    this.emit('end')
  }
}

/**
 * Build one encrypted stream for a session.
 *
 * `role` only selects which direction this side seals with; the crypto itself is
 * symmetric, which is why a single function serves both halves of the pairing.
 *
 * @param options.role - `host` or `guest`.
 * @param options.keys - the derived session keys.
 * @param options.inviteId - the session's invite id.
 * @param options.send - the opaque transport.
 * @param options.sendIv - this side's IV prefix.
 * @param options.receiveIv - the peer's IV prefix.
 * @param options.label - a diagnostic label.
 * @returns the stream.
 */
export function createE2eeStream(options) {
  const host = options.role === 'host'
  return new E2eeStream({
    send: options.send,
    keys: options.keys,
    inviteId: options.inviteId,
    sendDirection: host ? 'h2g' : 'g2h',
    receiveDirection: host ? 'g2h' : 'h2g',
    sendIv: options.sendIv,
    receiveIv: options.receiveIv,
    label: options.label,
  })
}

/**
 * A tiny newline-delimited reader over a {@link E2eeStream}.
 *
 * The pairing handshake exchanges a handful of small JSON messages before any
 * `LineWire` exists, and it needs to await a REPLY to a message it just sent. This
 * is the smallest thing that does that: buffer decrypted text, split on newlines,
 * hand each line to whoever is waiting.
 */
export class LineReader {
  /**
   * @param stream - the encrypted stream to read.
   */
  constructor(stream) {
    this.stream = stream
    this.buffer = ''
    this.waiters = []
    this.onData = (chunk) => this.push(chunk)
    this.onEnd = () => this.failAll(new Error('the channel closed before the expected message arrived'))
    stream.on('data', this.onData)
    stream.on('end', this.onEnd)
  }

  /**
   * Feed one chunk.
   * @param chunk - decrypted bytes.
   */
  push(chunk) {
    this.buffer += Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk)
    for (;;) {
      const newline = this.buffer.indexOf('\n')
      if (newline < 0) break
      const line = this.buffer.slice(0, newline)
      this.buffer = this.buffer.slice(newline + 1)
      if (line.trim().length === 0) continue
      const waiter = this.waiters.shift()
      if (waiter === undefined) continue
      waiter.resolve(line)
    }
  }

  /**
   * Await the next complete line.
   * @param timeoutMs - the deadline.
   * @returns the line, without its newline.
   * @throws {Error} on timeout or when the channel ends first.
   */
  next(timeoutMs) {
    return new Promise((resolve, reject) => {
      const waiter = { resolve: undefined, reject: undefined, timer: undefined }
      waiter.resolve = (line) => {
        clearTimeout(waiter.timer)
        resolve(line)
      }
      waiter.reject = (error) => {
        clearTimeout(waiter.timer)
        reject(error)
      }
      if (Number.isSafeInteger(timeoutMs) && timeoutMs > 0) {
        waiter.timer = setTimeout(() => {
          const index = this.waiters.indexOf(waiter)
          if (index >= 0) this.waiters.splice(index, 1)
          reject(new Error(`timed out after ${String(timeoutMs)} ms waiting for the peer's next message`))
        }, timeoutMs)
        waiter.timer.unref?.()
      }
      this.waiters.push(waiter)
    })
  }

  /**
   * Reject everyone still waiting.
   * @param error - the cause.
   */
  failAll(error) {
    for (const waiter of this.waiters.splice(0)) waiter.reject(error)
  }

  /** Detach from the stream. */
  dispose() {
    this.stream.off('data', this.onData)
    this.stream.off('end', this.onEnd)
    this.failAll(new Error('the reader was disposed'))
  }
}
