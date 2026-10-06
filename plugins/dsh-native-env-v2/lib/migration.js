import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * Read-only legacy discovery. It deliberately never edits the profile, package
 * manifest, ports, state files, or enable flags. The result is suitable for a
 * status page and gives an operator a copyable v2 starting point.
 */
export function inspectLegacy({ dshHome = process.env.DSH_HOME, profile = 'web' } = {}) {
  const root = typeof dshHome === 'string' && dshHome.length > 0 ? dshHome : undefined
  if (root === undefined) return { found: false, reason: 'DSH_HOME is not set', config: null }
  const profileDir = join(root, 'profiles', profile)
  const packagePath = join(profileDir, 'package.json')
  const patchPath = join(profileDir, 'cordis.patch.yml')
  const packageText = readText(packagePath)
  const patchText = readText(patchPath)
  let packageHasLegacy = false
  try {
    const parsed = JSON.parse(packageText)
    const dependencies = { ...(parsed.dependencies ?? {}), ...(parsed.devDependencies ?? {}) }
    packageHasLegacy = Object.hasOwn(dependencies, 'dsh-native-env')
  } catch {
    packageHasLegacy = false
  }
  const legacyPatchText = patchText.replaceAll('dsh-native-env-v2', '').replaceAll('native-env-v2', '')
  const patchHasLegacy = /\bdsh-native-env\b|\bid:\s*native-env(?:\s|$)/m.test(legacyPatchText)
  const found = packageHasLegacy || patchHasLegacy || existsSync(join(root, 'native-env.enabled'))
  return {
    found,
    profile,
    profileDir,
    sources: {
      packageJson: packageHasLegacy,
      cordisPatch: patchHasLegacy,
      enabledFlag: existsSync(join(root, 'native-env.enabled')),
    },
    config: found
      ? {
          mode: 'legacy',
          note: 'Copy the legacy peer rows and denylist into dsh-native-env-v2; review the port and state paths before enabling.',
          packagePath,
          patchPath,
        }
      : null,
  }
}

function readText(path) {
  try {
    return readFileSync(path, 'utf8')
  } catch {
    return ''
  }
}
