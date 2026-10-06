/**
 * Test helper: an in-memory duplex pair that behaves like two connected sockets.
 *
 * `LineWire` only needs `on('data'|'error'|'end')` on its input and
 * `write(string, callback)` on its output, so two of these cross-wired give a
 * faithful, fully synchronous socket pair for framing and protocol tests.
 *
 * @module dsh-net-bridge/tests/helpers/duplex
 */

import { EventEmitter } from 'node:events'

/** One end of an in-memory byte pipe. */
export class DuplexEnd extends EventEmitter {
  constructor(label = 'end') {
    super()
    this.label = label
    /** @type {DuplexEnd | undefined} */
    this.peer = undefined
    this.destroyed = false
    this.writes = []
  }

  /** Connect two ends to each other. */
  static pair(leftLabel = 'left', rightLabel = 'right') {
    const left = new DuplexEnd(leftLabel)
    const right = new DuplexEnd(rightLabel)
    left.peer = right
    right.peer = left
    return [left, right]
  }

  write(chunk, callback) {
    if (this.destroyed) {
      callback?.(new Error('write after destroy'))
      return false
    }
    this.writes.push(String(chunk))
    if (this.peer !== undefined && !this.peer.destroyed) {
      // Deliver asynchronously so framing code sees the same turn boundaries a
      // real socket would produce.
      const text = String(chunk)
      queueMicrotask(() => {
        if (!this.peer.destroyed) this.peer.emit('data', Buffer.from(text, 'utf8'))
      })
    }
    callback?.()
    return true
  }

  end() {
    if (this.destroyed) return
    const peer = this.peer
    queueMicrotask(() => peer?.emit('end'))
  }

  destroy() {
    if (this.destroyed) return
    this.destroyed = true
    this.emit('close')
  }
}

/** Wait for one microtask/timer turn. */
export function tick(ms = 0) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/** Wait until a predicate holds or the budget runs out. */
export async function until(predicate, timeoutMs = 1000, intervalMs = 5) {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const value = await predicate()
    if (value) return value
    if (Date.now() > deadline) return undefined
    await tick(intervalMs)
  }
}
