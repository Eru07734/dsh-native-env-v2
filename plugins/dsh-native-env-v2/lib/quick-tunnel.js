/** Cloudflare Quick Tunnel adapter; exposes only the loopback pairing relay. */
import { chmod, mkdir, rename, stat, writeFile, rm, mkdtemp } from 'node:fs/promises'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { spawn, execFile, execFileSync } from 'node:child_process'
import { promisify } from 'node:util'
import { createHash } from 'node:crypto'

const execFileAsync = promisify(execFile)

export function platformAsset(platform = process.platform, architecture = process.arch) {
  const arch = { x64: 'amd64', arm64: 'arm64', ia32: '386', arm: 'arm' }[architecture]
  if (!arch) throw new Error(`public relay: unsupported architecture ${architecture}`)
  if (platform === 'win32') return `cloudflared-windows-${arch}.exe`
  if (platform === 'darwin') return `cloudflared-darwin-${arch}.tgz`
  if (platform === 'linux') return `cloudflared-linux-${arch}`
  throw new Error(`public relay: unsupported platform ${platform}`)
}

async function exists(file) {
  try { return (await stat(file)).isFile() } catch { return false }
}

function abortIfNeeded(signal) {
  if (signal?.aborted) throw new Error('public relay: startup cancelled')
}

/** Resolve PATH, v2 cache or pocket's existing binary, then official download. */
export async function resolveCloudflared(options = {}) {
  abortIfNeeded(options.signal)
  const explicit = options.path ?? process.env.DSH_NATIVE_ENV_CLOUDFLARED
  if (typeof explicit === 'string' && explicit.length > 0) {
    if (!(await exists(explicit))) throw new Error(`public relay: configured cloudflared binary does not exist: ${explicit}`)
    return explicit
  }
  try {
    const result = execFileSync(process.platform === 'win32' ? 'where.exe' : 'which', ['cloudflared'], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000, windowsHide: true,
    }).trim().split(/\r?\n/)[0]
    if (result && await exists(result)) return result
  } catch { /* search the caches next */ }
  const asset = platformAsset()
  const home = options.home ?? process.env.DSH_HOME ?? join(homedir(), '.dsh')
  const filename = `cloudflared${process.platform === 'win32' ? '.exe' : ''}`
  const directory = join(home, 'native-env-v2', 'bin')
  const cache = join(directory, filename)
  for (const candidate of [cache, join(directory, asset), join(home, 'dsh-pocket', 'bin', filename), join(home, 'dsh-pocket', 'bin', asset)]) {
    if (!candidate.endsWith('.tgz') && await exists(candidate)) return candidate
  }
  if (options.download === false) throw new Error('public relay: cloudflared is not installed (set cloudflaredPath or enable download)')
  const url = `https://github.com/cloudflare/cloudflared/releases/latest/download/${asset}`
  options.logger?.info?.('public relay: downloading official cloudflared')
  const signal = AbortSignal.any([AbortSignal.timeout(120000), ...(options.signal ? [options.signal] : [])])
  await mkdir(directory, { recursive: true })
  const temporaryDirectory = await mkdtemp(join(directory, '.download-'))
  try {
    let assetInfo
    let response
    try {
      const release = await fetch('https://api.github.com/repos/cloudflare/cloudflared/releases/latest', {
        signal, headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'dsh-native-env-v2' },
      })
      if (!release.ok) throw new Error(`release metadata HTTP ${release.status}`)
      assetInfo = (await release.json()).assets?.find((entry) => entry.name === asset)
      if (!assetInfo || !/^https:\/\/api\.github\.com\/repos\/cloudflare\/cloudflared\/releases\/assets\/\d+$/.test(assetInfo.url)) {
        throw new Error('release has no matching official asset')
      }
      response = await fetch(assetInfo.url, { redirect: 'follow', signal, headers: { Accept: 'application/octet-stream', 'User-Agent': 'dsh-native-env-v2' } })
      if (!response.ok) throw new Error(`asset HTTP ${response.status}`)
    } catch (error) {
      abortIfNeeded(signal)
      // Some networks allow the asset API but reset github.com; others only
      // permit the download URL. Both paths stay on the official release.
      options.logger?.info?.('public relay: trying official release download URL')
      response = await fetch(url, { redirect: 'follow', signal })
    }
    if (!response.ok) throw new Error(`public relay: cloudflared download failed with HTTP ${response.status}`)
    const temporary = join(temporaryDirectory, asset)
    const bytes = Buffer.from(await response.arrayBuffer())
    if (assetInfo?.digest?.startsWith('sha256:') && `sha256:${createHash('sha256').update(bytes).digest('hex')}` !== assetInfo.digest) {
      throw new Error('public relay: official cloudflared asset checksum mismatch')
    }
    await writeFile(temporary, bytes, { signal })
    abortIfNeeded(options.signal)
    let executable = temporary
    if (asset.endsWith('.tgz')) {
      await execFileAsync('tar', ['-xzf', temporary, '-C', temporaryDirectory, 'cloudflared'], { signal, windowsHide: true })
      executable = join(temporaryDirectory, 'cloudflared')
    }
    if (process.platform !== 'win32') await chmod(executable, 0o755)
    await rename(executable, cache)
    return cache
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true }).catch(() => {})
  }
}

/** Dependency parameters allow deterministic process/abort tests without a tunnel. */
export async function startQuickTunnel(options = {}, dependencies = {}) {
  const port = Number(options.port)
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('public relay: invalid loopback port')
  abortIfNeeded(options.signal)
  const binary = await (dependencies.resolveCloudflared ?? resolveCloudflared)(options)
  abortIfNeeded(options.signal)
  const child = (dependencies.spawn ?? spawn)(binary, ['--no-autoupdate', 'tunnel', '--url', `http://127.0.0.1:${port}`, '--protocol', 'http2', '--edge-ip-version', '4'], {
    windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
  })
  let settled = false
  let timer
  let buffer = ''
  let publicUrl
  let registered = false
  let ended = false
  let forceKill
  const timeoutMs = Number.isSafeInteger(options.timeoutMs) && options.timeoutMs > 0 ? options.timeoutMs : 45000
  const exited = new Promise((resolve) => child.once('close', (code, signal) => {
    ended = true
    clearTimeout(forceKill)
    resolve({ code, signal })
  }))
  const close = () => {
    if (!ended && !child.killed) {
      child.kill()
      forceKill = setTimeout(() => { if (!ended) child.kill('SIGKILL') }, 2000)
      forceKill.unref?.()
    }
    return exited
  }
  return new Promise((resolve, reject) => {
    const fail = (error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      close()
      reject(error instanceof Error ? error : new Error(String(error)))
    }
    const onAbort = () => {
      close()
      fail(new Error('public relay: startup cancelled'))
    }
    const found = (chunk) => {
      buffer = `${buffer}${String(chunk)}`.slice(-12000)
      if (settled) return
      publicUrl ??= buffer.match(/https:\/\/[-a-z0-9]+\.trycloudflare\.com\b/i)?.[0]
      registered ||= /Registered tunnel connection/i.test(buffer)
      if (!publicUrl || !registered) return
      settled = true
      clearTimeout(timer)
      resolve({ url: publicUrl, process: child, close, exited, output: () => buffer })
    }
    child.stdout?.on('data', found)
    child.stderr?.on('data', found)
    child.on('error', fail)
    child.once('close', (code, signal) => {
      options.signal?.removeEventListener('abort', onAbort)
      clearTimeout(timer)
      fail(new Error(`public relay: cloudflared exited before creating a tunnel (${String(code ?? signal ?? 'unknown')})`))
    })
    timer = setTimeout(() => {
      const lastError = buffer.split(/\r?\n/).filter((line) => /\bERR\b/.test(line)).at(-1)
      fail(new Error(`public relay: cloudflared did not establish a Quick Tunnel within ${timeoutMs} ms${lastError ? `: ${lastError.slice(0, 500)}` : ''}`))
    }, timeoutMs)
    options.signal?.addEventListener('abort', onAbort, { once: true })
    if (options.signal?.aborted) onAbort()
  })
}
