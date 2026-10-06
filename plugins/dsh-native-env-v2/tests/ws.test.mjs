/**
 * dsh-native-env / ws tests — the RFC 6455 endpoint both the plugin and the relay
 * speak.
 *
 * Two kinds of test here, and they answer different questions:
 *
 *   - **Against a real socket and a real HTTP server**, that a real client and a
 *     real server interoperate: the handshake, the accept digest, long frames in
 *     both extended-length forms, ping/pong and the close handshake.
 *   - **Against a hand-built frame fed to the parser**, that the endpoint REFUSES
 *     what the RFC forbids. These cases are nearly impossible to provoke from a
 *     well-behaved peer, which is exactly why they are hand-built: an unmasked
 *     client frame, a set RSV bit, an oversized length, a stray continuation.
 *
 * @module dsh-native-env/tests/ws
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { createServer } from 'node:http'
import { createServer as netCreateServer } from 'node:net'

import { DuplexEnd, until } from './helpers/duplex.mjs'
import {
  DEFAULT_MAX_PAYLOAD,
  STATE,
  WebSocketConnection,
  WsProtocolError,
  acceptWebSocket,
  computeAccept,
  connectWebSocket,
  isWebSocketUpgrade,
} from '../lib/ws.js'

/**
 * Build one wire-level frame by hand.
 *
 * @param opcode - the frame opcode.
 * @param payload - the body (a Buffer or a string).
 * @param options.mask - whether to mask, as a client must.
 * @param options.fin - the FIN bit.
 * @param options.rsv - the reserved bits.
 * @param options.lengthOverride - force the extended-length form, for the
 *   "declared longer than it is" cases.
 * @returns the encoded frame.
 */
function buildFrame(opcode, payload, options = {}) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8')
  const mask = options.mask === true
  const fin = options.fin !== false
  const rsv = options.rsv ?? 0
  const declared = options.lengthOverride ?? body.length

  let header
  if (declared < 126) {
    header = Buffer.alloc(2)
    header[1] = declared
  } else if (declared < 65536) {
    header = Buffer.alloc(4)
    header[1] = 126
    header.writeUInt16BE(declared, 2)
  } else {
    header = Buffer.alloc(10)
    header[1] = 127
    header.writeBigUInt64BE(BigInt(declared), 2)
  }
  header[0] = (fin ? 0x80 : 0) | (rsv << 4) | opcode
  if (!mask) return Buffer.concat([header, body])

  header[1] |= 0x80
  const key = Buffer.from([0x11, 0x22, 0x33, 0x44])
  const masked = Buffer.allocUnsafe(body.length)
  for (let index = 0; index < body.length; index += 1) masked[index] = body[index] ^ key[index & 3]
  return Buffer.concat([header, key, masked])
}

/**
 * A minimal socket stand-in for parser-level tests.
 *
 * It records the RAW buffers written to it. The shared `DuplexEnd` helper stores
 * `String(chunk)`, which mangles binary frame headers — useless for asserting on
 * an encoded close frame.
 */
function fakeSocket() {
  const end = new DuplexEnd('ws-test')
  end.frames = []
  end.write = (chunk, callback) => {
    end.frames.push(Buffer.from(chunk))
    callback?.()
    return true
  }
  end.destroy = () => {
    end.destroyed = true
  }
  return end
}

/**
 * The close code of the last frame written to a fake socket, or `undefined`.
 *
 * A protocol violation does not synchronously emit `close`: the endpoint begins
 * the close HANDSHAKE, which by design waits for the peer to answer. Asserting on
 * the frame it sent is what pins the refusal without needing a peer that replies.
 *
 * The frame is decoded rather than read at a fixed offset because a CLIENT masks
 * its own frames, so the code sits after the mask key there and immediately after
 * the length header on a server.
 *
 * @param socket - the fake socket.
 * @returns the close code, or `undefined` when the last frame is not a close.
 */
function closeCodeWrittenTo(socket) {
  const frame = socket.frames.at(-1)
  if (frame === undefined || frame.length < 4) return undefined
  if ((frame[0] & 0x0f) !== 0x8) return undefined
  const masked = (frame[1] & 0x80) !== 0
  let length = frame[1] & 0x7f
  let offset = 2
  if (length === 126) {
    length = frame.readUInt16BE(2)
    offset = 4
  } else if (length === 127) {
    offset = 10
  }
  let key
  if (masked) {
    key = frame.subarray(offset, offset + 4)
    offset += 4
  }
  if (length < 2) return undefined
  const code = Buffer.from(frame.subarray(offset, offset + 2))
  if (key !== undefined) {
    code[0] ^= key[0]
    code[1] ^= key[1]
  }
  return code.readUInt16BE(0)
}

/**
 * Start a socket that answers every connection with a plain HTTP response.
 *
 * A raw `net` server rather than an `http` server on purpose: an `http` server
 * would answer the upgrade itself (or destroy the socket if it has no `upgrade`
 * listener), and the case being pinned here is what this CLIENT does when it
 * reads a real status line that is not 101.
 *
 * @param status - the status line to answer with.
 * @returns `{ url, close }`.
 */
function startPlainServer(status = 'HTTP/1.1 400 Bad Request') {
  return new Promise((resolve) => {
    const sockets = new Set()
    const server = netCreateServer((socket) => {
      sockets.add(socket)
      socket.on('close', () => sockets.delete(socket))
      socket.once('data', () => {
        socket.end(`${status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`)
      })
      socket.on('error', () => socket.destroy())
    })
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      resolve({
        url: `ws://127.0.0.1:${String(address.port)}/v2/relay/test`,
        close: () =>
          new Promise((done) => {
            for (const socket of sockets) socket.destroy()
            server.close(() => done())
          }),
      })
    })
  })
}

/** Start an echo server and return its `ws://` URL plus a disposer. */
function startEchoServer() {
  return new Promise((resolve) => {
    const server = createServer((_req, res) => {
      res.writeHead(400)
      res.end('not a websocket endpoint')
    })
    server.on('upgrade', (req, socket, head) => {
      let connection
      try {
        connection = acceptWebSocket(req, socket, head, { label: 'ws:echo' })
      } catch {
        socket.destroy()
        return
      }
      connection.on('message', (text) => connection.send(text))
      connection.on('error', () => connection.destroy())
    })
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      resolve({
        url: `ws://127.0.0.1:${String(address.port)}/v2/relay/test`,
        httpUrl: `http://127.0.0.1:${String(address.port)}/`,
        close: () =>
          new Promise((done) => {
            server.close(() => done())
          }),
      })
    })
  })
}

// ── the handshake ────────────────────────────────────────────────────────────

test('computeAccept matches the RFC 6455 worked example', () => {
  assert.equal(computeAccept('dGhlIHNhbXBsZSBub25jZQ=='), 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=')
})

test('a v13 upgrade is recognized and anything else is not', () => {
  const good = { headers: { upgrade: 'websocket', connection: 'Upgrade', 'sec-websocket-version': '13', 'sec-websocket-key': 'x' } }
  assert.equal(isWebSocketUpgrade(good), true)
  assert.equal(isWebSocketUpgrade({ headers: { ...good.headers, 'sec-websocket-version': '8' } }), false)
  assert.equal(isWebSocketUpgrade({ headers: { ...good.headers, upgrade: 'h2c' } }), false)
  assert.equal(isWebSocketUpgrade({ headers: { ...good.headers, 'sec-websocket-key': undefined } }), false)
  assert.equal(isWebSocketUpgrade(undefined), false)
})

test('a plain HTTP response is refused as a failed upgrade', async () => {
  const server = await startPlainServer()
  try {
    await assert.rejects(
      () => connectWebSocket(server.url),
      /refused the WebSocket upgrade: HTTP\/1\.1 400 Bad Request/,
    )
  } finally {
    await server.close()
  }
})

test('a non-WebSocket URL is refused before any socket is opened', () => {
  assert.throws(() => connectWebSocket('https://relay.test/x'), WsProtocolError)
})

// ── interoperation over a real socket ────────────────────────────────────────

test('a text message round-trips through a real server', async () => {
  const server = await startEchoServer()
  const ws = await connectWebSocket(server.url)
  try {
    assert.equal(ws.state, STATE.OPEN)
    const seen = new Promise((resolve) => ws.once('message', resolve))
    ws.send('{"jsonrpc":"2.0","method":"env/list"}')
    assert.equal(await seen, '{"jsonrpc":"2.0","method":"env/list"}')
  } finally {
    ws.destroy()
    await server.close()
  }
})

test('a frame that needs the 16-bit length round-trips', async () => {
  const server = await startEchoServer()
  const ws = await connectWebSocket(server.url)
  try {
    const body = 'a'.repeat(1000)
    const seen = new Promise((resolve) => ws.once('message', resolve))
    ws.send(body)
    assert.equal(await seen, body)
  } finally {
    ws.destroy()
    await server.close()
  }
})

test('a frame that needs the 64-bit length round-trips', async () => {
  const server = await startEchoServer()
  const ws = await connectWebSocket(server.url)
  try {
    const body = 'b'.repeat(200000)
    const seen = new Promise((resolve) => ws.once('message', resolve))
    ws.send(body)
    const echoed = await seen
    assert.equal(echoed.length, body.length)
    assert.equal(echoed, body)
  } finally {
    ws.destroy()
    await server.close()
  }
})

test('the close handshake reports the peer code to both sides', async () => {
  const server = await startEchoServer()
  const ws = await connectWebSocket(server.url)
  try {
    const closed = new Promise((resolve) => ws.once('close', resolve))
    ws.close(1000, 'done')
    const event = await closed
    assert.equal(event.code, 1000)
  } finally {
    ws.destroy()
    await server.close()
  }
})

test('a ping is answered with a pong', async () => {
  const server = await startEchoServer()
  const ws = await connectWebSocket(server.url)
  try {
    const pong = new Promise((resolve) => ws.once('pong', resolve))
    ws.ping(Buffer.from('hb'))
    assert.equal((await pong).toString('utf8'), 'hb')
  } finally {
    ws.destroy()
    await server.close()
  }
})

test('sending on a closed connection throws instead of dropping the frame', async () => {
  const server = await startEchoServer()
  const ws = await connectWebSocket(server.url)
  try {
    ws.destroy()
    assert.throws(() => ws.send('x'), /not open/)
  } finally {
    await server.close()
  }
})

// ── protocol refusals, fed to the parser by hand ─────────────────────────────

test('a server refuses an unmasked client frame', () => {
  const socket = fakeSocket()
  const connection = new WebSocketConnection({ socket, mask: false })
  connection.feed(buildFrame(0x1, 'hello', { mask: false }))
  assert.equal(closeCodeWrittenTo(socket), 1002)
  assert.equal(connection.state, STATE.CLOSING)
  connection.destroy()
})

test('a server accepts a masked client frame', async () => {
  const socket = fakeSocket()
  const connection = new WebSocketConnection({ socket, mask: false })
  const seen = new Promise((resolve) => connection.once('message', resolve))
  connection.feed(buildFrame(0x1, 'hello', { mask: true }))
  assert.equal(await seen, 'hello')
  connection.destroy()
})

test('a client refuses a masked server frame', () => {
  const socket = fakeSocket()
  const connection = new WebSocketConnection({ socket, mask: true })
  connection.feed(buildFrame(0x1, 'hello', { mask: true }))
  assert.equal(closeCodeWrittenTo(socket), 1002)
  connection.destroy()
})

test('a reserved bit without a negotiated extension is refused', () => {
  const socket = fakeSocket()
  const connection = new WebSocketConnection({ socket, mask: false })
  connection.feed(buildFrame(0x1, 'hello', { mask: true, rsv: 4 }))
  assert.equal(closeCodeWrittenTo(socket), 1002)
  connection.destroy()
})

test('an oversized declared length is refused before allocating', () => {
  const socket = fakeSocket()
  const connection = new WebSocketConnection({ socket, mask: false, maxPayload: 1024 })
  // Only the header is fed: the refusal must come from the DECLARED length, so a
  // hostile peer cannot make the endpoint buffer gigabytes first.
  connection.feed(buildFrame(0x1, Buffer.alloc(0), { mask: true, lengthOverride: 5 * 1024 * 1024 }))
  assert.equal(closeCodeWrittenTo(socket), 1009, 'the close code must be "message too big"')
  connection.destroy()
})

test('a stray continuation frame is refused', () => {
  const socket = fakeSocket()
  const connection = new WebSocketConnection({ socket, mask: false })
  connection.feed(buildFrame(0x0, 'orphan', { mask: true }))
  assert.equal(closeCodeWrittenTo(socket), 1002)
  connection.destroy()
})

test('a fragmented message is assembled in order', async () => {
  const socket = fakeSocket()
  const connection = new WebSocketConnection({ socket, mask: false })
  const seen = new Promise((resolve) => connection.once('message', resolve))
  connection.feed(buildFrame(0x1, 'one-', { mask: true, fin: false }))
  connection.feed(buildFrame(0x0, 'two-', { mask: true, fin: false }))
  connection.feed(buildFrame(0x0, 'three', { mask: true, fin: true }))
  assert.equal(await seen, 'one-two-three')
  connection.destroy()
})

test('a frame split across two socket reads is reassembled', async () => {
  const socket = fakeSocket()
  const connection = new WebSocketConnection({ socket, mask: false })
  const seen = new Promise((resolve) => connection.once('message', resolve))
  const frame = buildFrame(0x1, 'split-me', { mask: true })
  connection.feed(frame.subarray(0, 3))
  connection.feed(frame.subarray(3))
  assert.equal(await seen, 'split-me')
  connection.destroy()
})

test('an error with no listener does not take the process down', async () => {
  const socket = fakeSocket()
  const connection = new WebSocketConnection({ socket, mask: false })
  // No 'error' listener attached: Node's EventEmitter would rethrow.
  assert.doesNotThrow(() => connection.fail(new Error('boom')))
  assert.equal(connection.state, STATE.CLOSED)
})

test('the default payload ceiling is generous enough for an env frame', () => {
  assert.ok(DEFAULT_MAX_PAYLOAD >= 4 * 1024 * 1024)
})

test('a destroyed connection reports closed exactly once', async () => {
  const socket = fakeSocket()
  const connection = new WebSocketConnection({ socket, mask: false })
  let closes = 0
  connection.on('close', () => {
    closes += 1
  })
  connection.destroy()
  connection.destroy()
  await until(() => closes > 0)
  assert.equal(closes, 1)
})
