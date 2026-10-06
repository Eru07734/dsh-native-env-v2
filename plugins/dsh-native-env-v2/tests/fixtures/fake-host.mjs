#!/usr/bin/env node
/**
 * Test fixture: a minimal env HOST.
 *
 * The host half of `dsh-native-env` does not exist yet (Phase 2), so this stands
 * in for it: it listens, authenticates one dial-in, and then drives the
 * conversation the real host will drive — `env/list`, then `env/call` for a read
 * and for a shell command, then a deliberate call to a tool that does not exist.
 *
 * That last case matters: an unknown name must come back as an ERROR RESULT on a
 * working wire, not as a wire failure, so the host can tell "the remote tool
 * failed" from "the env connection broke".
 *
 * Usage: node fake-host.mjs <tokenFile> <port> <reportPath> <readTarget>
 *
 * @module dsh-native-env/tests/fixtures/fake-host
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'

import { METHODS } from '../../lib/env-protocol.js'
import {
  AUTH_METHOD,
  BRIDGE_VERSION,
  CHANNEL_ENV,
  HELLO_METHOD,
  hostProof,
  newNonce,
  parseHello,
  peerProof,
  sameProof,
} from '../../lib/handshake.js'
import { LineWire } from '../../lib/wire.js'

const [tokenFile, portArg, reportPath, readTarget] = process.argv.slice(2)
const port = Number(portArg)
const token = readFileSync(tokenFile, 'utf8').trim()

const report = { startedAt: new Date().toISOString(), verdict: 'running', steps: [] }
const flush = () => writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8')
const record = (key, value) => {
  report.steps.push({ key, value })
  flush()
}

/** Flatten content blocks to text for readable assertions. */
const textOf = (content) =>
  (Array.isArray(content) ? content : [])
    .filter((block) => block?.type === 'text')
    .map((block) => block.text)
    .join('\n')

const server = createServer()
server.listen(port, '127.0.0.1', () => record('listening', { port }))

server.on('connection', (socket) => {
  const wire = new LineWire(socket, socket, {
    onMalformed: (line) => record('malformed-frame', line.slice(0, 200)),
  })

  let stage = 'hello'
  let clientNonce
  let serverNonce
  let peerName

  wire.onRequest(async (method, params) => {
    if (stage === 'hello') {
      if (method !== HELLO_METHOD) throw new Error(`handshake required (expected ${HELLO_METHOD})`)
      const hello = parseHello(params, CHANNEL_ENV)
      peerName = hello.peer
      clientNonce = hello.nonce
      serverNonce = newNonce()
      stage = 'auth'
      return {
        ok: true,
        version: BRIDGE_VERSION,
        nonce: serverNonce,
        hmac: hostProof(token, clientNonce, serverNonce),
        peer: peerName,
        channel: hello.channel,
      }
    }
    if (method !== AUTH_METHOD) throw new Error(`handshake required (expected ${AUTH_METHOD})`)
    if (!sameProof(params.hmac, peerProof(token, clientNonce, serverNonce))) throw new Error('the peer failed to prove the token')
    stage = 'ready'
    record('authenticated', { peer: peerName })
    setImmediate(() => {
      drive(wire).catch((error) => {
        report.verdict = 'threw'
        record('error', String(error?.stack ?? error))
        server.close()
        setTimeout(() => process.exit(0), 100)
      })
    })
    return { ok: true, peer: peerName }
  })

  wire.onNotification((method, params) => {
    if (method === METHODS.toolsChanged) record('env/tools-changed', { toolCount: params?.tools?.length ?? null })
  })

  wire.start()
})

async function drive(wire) {
  const listed = await wire.request(METHODS.list, {}, AbortSignal.timeout(20000))
  record('env/list', {
    peer: listed.peer,
    platform: listed.platform,
    cwd: listed.cwd,
    anchor: listed.anchor,
    toolCount: listed.tools.length,
    names: listed.tools.map((tool) => tool.name).sort(),
  })

  // Argument names are the REMOTE runtime's, taken from its own schemas: `read`
  // wants `file_path`, and `pwsh`/`bash` require a `description`. Getting these
  // wrong is instructive rather than fatal — the remote's real pipeline validates
  // them and answers an error result, which is exactly the behaviour a takeover
  // depends on for the shadow schemas it copies from this same `env/list`.
  const readResult = await wire.request(
    METHODS.call,
    { callId: 'c1', name: 'read', arguments: { file_path: readTarget } },
    AbortSignal.timeout(30000),
  )
  record('env/call read', {
    isError: readResult.isError,
    bytes: readResult.bytes,
    truncated: readResult.truncated,
    text: textOf(readResult.content).slice(0, 400),
  })

  const shellName = listed.tools.some((tool) => tool.name === 'pwsh') ? 'pwsh' : 'bash'
  const shellResult = await wire.request(
    METHODS.call,
    { callId: 'c2', name: shellName, arguments: { command: 'hostname', description: 'print the hostname' } },
    AbortSignal.timeout(60000),
  )
  record(`env/call ${shellName} hostname`, {
    isError: shellResult.isError,
    text: textOf(shellResult.content).slice(0, 300),
  })

  // An unknown name must be an error RESULT on a healthy wire.
  const unknown = await wire.request(
    METHODS.call,
    { callId: 'c3', name: 'definitely_not_a_tool_xyz', arguments: {} },
    AbortSignal.timeout(20000),
  )
  record('env/call unknown tool', { isError: unknown.isError, text: textOf(unknown.content).slice(0, 200) })

  // Cancelling an id that is not in flight must be reported, not thrown.
  const cancel = await wire.request(METHODS.cancel, { callId: 'never-existed' }, AbortSignal.timeout(10000))
  record('env/cancel unknown id', cancel)

  const status = await wire.request(METHODS.status, {}, AbortSignal.timeout(10000))
  record('env/status', { peer: status.peer, anchor: status.anchor, inflight: status.inflight })

  const listOk = listed.tools.length > 0 && listed.anchor?.id !== null
  const readOk = readResult.isError === false && textOf(readResult.content).length > 0
  const shellOk = shellResult.isError === false && textOf(shellResult.content).trim().length > 0
  const unknownOk = unknown.isError === true
  const cancelOk = cancel?.ok === false
  report.verdict = listOk && readOk && shellOk && unknownOk && cancelOk ? 'pass' : 'fail'
  record('verdict-inputs', { listOk, readOk, shellOk, unknownOk, cancelOk })
  record('finishedAt', new Date().toISOString())

  server.close()
  setTimeout(() => process.exit(0), 150)
}
