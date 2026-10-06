/**
 * dsh-net-bridge / tool-def — the tool contract, restated locally.
 *
 * The harness exposes `defineTool` from `@deepseek-ai/dsh-tools`, but a
 * `file:`-installed / absolute-path-mounted plugin resolves bare specifiers from
 * its own real path, where that package is not visible. A definition registered
 * on `ctx.tools`
 * needs `{ name, description, parameters, output: { schema, render } }`, and the
 * argument validation below is what the harness would otherwise do for us.
 *
 * @module dsh-net-bridge/tool-def
 */

/** Argument validation failed; the message reaches the model as a tool error. */
export class ToolArgsError extends Error {
  constructor(violations) {
    super(`invalid tool arguments:\n- ${violations.join('\n- ')}`)
    this.name = 'ToolArgsError'
    this.violations = violations
  }
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function describeType(value) {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  return typeof value
}

/**
 * Validate one value against the enforced JSON Schema subset.
 * @param schema - the `JsonSchemaNode`.
 * @param value - the candidate value.
 * @param path - diagnostic path.
 * @param violations - accumulator.
 */
export function validateValue(schema, value, path, violations) {
  if (schema === undefined || schema === null) return
  const where = path || 'arguments'

  if (schema.oneOf !== undefined) {
    const matched = schema.oneOf.some((candidate) => {
      const inner = []
      validateValue(candidate, value, path, inner)
      return inner.length === 0
    })
    if (!matched) violations.push(`${where} must match one of the allowed shapes`)
    return
  }

  if (schema.enum !== undefined) {
    if (!schema.enum.includes(value)) {
      violations.push(`${where} must be one of ${schema.enum.map((entry) => JSON.stringify(entry)).join(', ')}`)
    }
    return
  }
  if (schema.const !== undefined && value !== schema.const) {
    violations.push(`${where} must be ${JSON.stringify(schema.const)}`)
    return
  }

  const type = schema.type
  if (type === 'object') {
    if (!isPlainObject(value)) {
      violations.push(`${where} must be an object`)
      return
    }
    const properties = schema.properties ?? {}
    for (const key of schema.required ?? []) {
      if (value[key] === undefined) violations.push(`${where}.${key} is required`)
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!(key in properties)) violations.push(`${where}.${key} is not a known property`)
      }
    }
    for (const [key, sub] of Object.entries(properties)) {
      if (value[key] !== undefined) validateValue(sub, value[key], `${where}.${key}`, violations)
    }
    return
  }
  if (type === 'array') {
    if (!Array.isArray(value)) {
      violations.push(`${where} must be an array`)
      return
    }
    if (schema.items !== undefined) {
      value.forEach((item, index) => validateValue(schema.items, item, `${where}[${index}]`, violations))
    }
    return
  }
  if (type === 'string') {
    if (typeof value !== 'string') violations.push(`${where} must be a string, got ${describeType(value)}`)
    return
  }
  if (type === 'number' || type === 'integer') {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      violations.push(`${where} must be a number, got ${describeType(value)}`)
      return
    }
    if (type === 'integer' && !Number.isInteger(value)) violations.push(`${where} must be an integer`)
    return
  }
  if (type === 'boolean' && typeof value !== 'boolean') {
    violations.push(`${where} must be a boolean, got ${describeType(value)}`)
  }
}

/**
 * Copy one tool value into lossless JSON.
 *
 * The registry materializes a tool's canonical output as lossless JSON and
 * rejects the call when it cannot: an `undefined` property (a peer that is not
 * connected has no `wire` counts), a non-finite number, or a BigInt fails the
 * WHOLE tool call with "value is not lossless JSON" — the model then sees a
 * serialization error instead of the status document it asked for. Dropping
 * absent properties and coercing the rare non-JSON scalars keeps a status
 * payload a status payload.
 *
 * @param value - the raw tool value.
 * @returns a plain-JSON copy.
 */
export function jsonSafe(value) {
  if (value === undefined) return undefined
  return JSON.parse(
    JSON.stringify(value, (_key, item) => {
      if (item === undefined) return undefined
      if (typeof item === 'number' && !Number.isFinite(item)) return null
      if (typeof item === 'bigint') return String(item)
      return item
    }),
  )
}

/**
 * Build a registry-ready tool definition, validating arguments first and
 * copying the returned value into lossless JSON.
 * @param options.name / description / parameters / output / execute - the
 *   harness contract. `parameters` is raw JSON Schema in the enforced subset.
 * @returns the definition registered on `ctx.tools`.
 */
export function defineTool(options) {
  const definition = {
    name: options.name,
    description: options.description,
    parameters: options.parameters,
    output: {
      schema: options.output.schema,
      render: options.output.render,
    },
    async execute(args, exec) {
      const violations = []
      validateValue(options.parameters, args ?? {}, '', violations)
      if (violations.length > 0) throw new ToolArgsError(violations)
      return jsonSafe(await options.execute(args ?? {}, exec))
    },
  }
  if (options.timeoutMs !== undefined) definition.timeoutMs = options.timeoutMs
  if (options.isConcurrencySafe !== undefined) definition.isConcurrencySafe = options.isConcurrencySafe
  return definition
}
