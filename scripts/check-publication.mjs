import { readdirSync, readFileSync } from 'node:fs'
import { dirname, extname, resolve, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const skipped = new Set(['.git', 'node_modules', '.pnpm-store'])
const rules = [
  ['private-key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/],
  ['github-token', /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/],
  ['provider-token', /\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b/],
  ['credential-in-url', /https?:\/\/[^\s/@:]+:[^\s/@]+@/],
  ['personal-windows-home', /[A-Z]:[\\/]+Users[\\/]+(?!Public\b|Example\b|USER\b)[^\s'"`\\/]+/i],
]
const forbidden = /(?:^|\/)(?:\.env(?:\..*)?|_token|\.credentials\.ya?ml|id_rsa|id_ed25519|.*\.log|.*\.bak(?:-.*)?|.*\.local\.[^/]+|tests\/_.*)$/i
let failures = 0, count = 0, syntaxCount = 0
function report(file, line, reason) {
  // Never print the matched value: a failed check may have found a real secret.
  console.error(`${file}${line ? `:${line}` : ''}: ${reason}`)
  failures++
}
function visit(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (skipped.has(entry.name)) continue
    const path = resolve(directory, entry.name)
    const file = relative(root, path).replaceAll('\\', '/')
    if (entry.isSymbolicLink()) { report(file, 0, 'symlink is outside the publication policy'); continue }
    if (entry.isDirectory()) { visit(path); continue }
    count++
    if (forbidden.test(file) && !file.endsWith('.env.example')) report(file, 0, 'local state or credential file')
    const bytes = readFileSync(path)
    if (bytes.includes(0)) { report(file, 0, 'unexpected binary file'); continue }
    const lines = bytes.toString('utf8').split(/\r?\n/)
    for (let i = 0; i < lines.length; i++) {
      for (const [name, regex] of rules) if (regex.test(lines[i])) report(file, i + 1, name)
      const ips = lines[i].match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []
      for (const ip of ips) {
        const octets = ip.split('.').map(Number)
        if (octets.some((n) => n > 255)) continue
        if (ip === '0.0.0.0' || ip.startsWith('127.') || ip.startsWith('192.0.2.') || ip.startsWith('198.51.100.') || ip.startsWith('203.0.113.')) continue
        report(file, i + 1, 'non-example IPv4 address needs review')
      }
    }
    if (['.js', '.mjs', '.cjs'].includes(extname(path))) {
      syntaxCount++
      const result = spawnSync(process.execPath, ['--check', path], { stdio: 'inherit' })
      if (result.error || result.status !== 0) report(file, 0, 'JavaScript syntax check failed')
    }
  }
}
visit(root)
console.log(`Publication check: ${count} files, ${syntaxCount} JavaScript files, ${failures} findings.`)
process.exitCode = failures ? 1 : 0
