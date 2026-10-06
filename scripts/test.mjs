import { readdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const directories = ['plugins/dsh-native-env-v2/tests', 'relay/test']
const files = directories.flatMap((directory) => readdirSync(resolve(root, directory))
  .filter((name) => name.endsWith('.test.mjs')).sort()
  .map((name) => `${directory}/${name}`))
const result = spawnSync(process.execPath, ['--test', '--test-reporter=spec', ...files], {
  cwd: root,
  stdio: 'inherit',
})
if (result.error) throw result.error
process.exitCode = result.status ?? 1
