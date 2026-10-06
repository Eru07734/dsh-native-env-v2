/** Optional public-reachability component for dsh-native-env-v2. */

import { createRelay } from './embedded-relay.js'
import { startQuickTunnel } from './quick-tunnel.js'

export const name = 'native-env-v2-public'
export const inject = ['nativeEnvV2Controller']

export const Config = {
  type: 'object',
  additionalProperties: true,
  properties: {
    download: { type: 'boolean', description: 'download cloudflared into the DSH home when it is missing' },
    cloudflaredPath: { type: 'string', description: 'optional path to an existing cloudflared executable' },
    timeoutMs: { type: 'integer', description: 'maximum time to wait for the public tunnel URL' },
  },
  '~standard': {
    version: 1,
    vendor: 'dsh-native-env-v2',
    validate(value) {
      if (value === undefined || value === null) return { value: {} }
      if (typeof value !== 'object' || Array.isArray(value)) return { issues: [{ message: 'public component config must be an object' }] }
      return { value }
    },
  },
}

export function startPublicAccess(controller, config = {}, dependencies = {}) {
    const abort = new AbortController()
    let relay
    let tunnel
    let stopped = false
    let cleanupPromise
    const cleanup = () => cleanupPromise ??= Promise.allSettled([
      Promise.resolve().then(() => tunnel?.close()),
      Promise.resolve().then(() => relay?.close()),
    ])

    const run = async () => {
      controller.setPublicState({ enabled: true, phase: 'starting', relay: null, error: null, startedAt: Date.now() })
      relay = (dependencies.createRelay ?? createRelay)({ host: '127.0.0.1', port: 0, logLevel: 'silent', trustProxy: true, maxFrameBytes: 8 * 1024 * 1024 })
      const address = await relay.listen()
      if (stopped) return
      const localPort = typeof address === 'object' && address !== null ? address.port : undefined
      if (!Number.isInteger(localPort)) throw new Error('public relay: could not determine the local relay port')
      controller.setPublicState({ localPort, phase: 'tunneling' })
      tunnel = await (dependencies.startQuickTunnel ?? startQuickTunnel)({
        port: localPort,
        path: config.cloudflaredPath,
        download: config.download !== false,
        timeoutMs: config.timeoutMs,
        signal: abort.signal,
        logger: dependencies.logger,
      })
      if (stopped) {
        await tunnel.close()
        return
      }
      const relayUrl = `${tunnel.url.replace(/^https:/i, 'wss:')}/v2/relay`
      controller.setPublicRelay(relayUrl, { publicUrl: tunnel.url, localPort, phase: 'ready' })
      void tunnel.exited.then(async ({ code, signal }) => {
        if (stopped) return
        controller.clearPublicRelay({ enabled: true, phase: 'error', error: `cloudflared exited (${String(code ?? signal ?? 'unknown')}); toggle public access off/on to retry` })
        await cleanup()
      })
    }

    const ready = run().catch(async (error) => {
      const message = String(error?.message ?? error)
      if (!stopped) {
        controller.clearPublicRelay({ enabled: true, phase: 'error', error: message })
        dependencies.logger?.warn?.(message)
      }
      await cleanup()
    })

    return {
      ready,
      async stop() {
        stopped = true
        abort.abort()
        controller.clearPublicRelay()
        // A late listener or binary download cannot resurrect an off component.
        await ready
        await cleanup()
      },
    }
}

export function apply(ctx, config = {}) {
  const handle = startPublicAccess(ctx.get('nativeEnvV2Controller'), config, { logger: ctx.logger })
  ctx.effect(() => () => handle.stop(), 'native-env-v2/public:lifecycle')
}
