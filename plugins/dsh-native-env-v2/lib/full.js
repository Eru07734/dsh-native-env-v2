/** Optional full-access component for dsh-native-env-v2. */

export const name = 'native-env-v2-full'
export const inject = ['nativeEnvV2Controller']

export const Config = {
  type: 'object',
  additionalProperties: true,
  '~standard': {
    version: 1,
    vendor: 'dsh-native-env-v2',
    validate(value) {
      if (value === undefined || value === null) return { value: {} }
      if (typeof value !== 'object' || Array.isArray(value)) return { issues: [{ message: 'full-access component config must be an object' }] }
      return { value }
    },
  },
}

export function apply(ctx) {
  ctx.inject(['nativeEnvV2Controller'], (scope) => {
    const controller = scope.get('nativeEnvV2Controller')
    void controller.setFullAccess(true).catch((error) => ctx.logger?.warn?.(`native-env-v2/full: could not enable full access: ${String(error?.message ?? error)}`))
    scope.effect(
      () => () => {
        void controller.setFullAccess(false).catch((error) => ctx.logger?.warn?.(`native-env-v2/full: could not disable full access: ${String(error?.message ?? error)}`))
      },
      'native-env-v2/full:lifecycle',
    )
  })
}
