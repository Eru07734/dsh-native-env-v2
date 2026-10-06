/**
 * dsh-native-env / qr tests.
 *
 * A hand-written QR encoder is exactly the kind of code that "looks right" and
 * does not scan, and no structural assertion can tell the difference. So the
 * decisive test here compares EVERY module of this encoder's output against an
 * independent implementation (`qrcode`, pinned as a root development dependency)
 * for the same payload, version, level and mask.
 *
 * The oracle is TEST-ONLY, never a runtime dependency: the plugin halves
 * cannot resolve a bare specifier at all, so a missing oracle SKIPS the comparison
 * rather than failing the suite. What remains when it is absent is the structural
 * set — size, finder patterns, timing, the always-dark module, capacity arithmetic
 * and the SVG contract — which catches a regression in the parts of the encoder
 * that are cheap to state independently.
 *
 * @module dsh-native-env/tests/qr
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  MAX_VERSION,
  QrError,
  QUIET_ZONE,
  alignmentPositions,
  dataCodewords,
  encodeQrMatrix,
  encodeQrSvg,
  rawDataModules,
  reedSolomonDivisor,
  reedSolomonRemainder,
} from '../lib/qr.js'

const HERE = dirname(fileURLToPath(import.meta.url))

/**
 * Load the reference encoder, or `undefined` when this machine has no copy.
 *
 * Resolve the checkout's declared development dependency. A source-only checkout
 * can still run the structural tests without installing it; do not probe sibling
 * projects or a developer's other DSH installations.
 *
 * @returns the `qrcode` module, or `undefined`.
 */
function loadOracle() {
  const require = createRequire(import.meta.url)
  try {
    return require('qrcode')
  } catch (error) {
    if (error.code !== 'MODULE_NOT_FOUND') throw error
    return undefined
  }
}

const oracle = loadOracle()

/** A realistic invite, which is the payload this encoder exists for. */
const INVITE_LIKE =
  'dsh+env://pair?v=2&relay=wss%3A%2F%2Frelay.example.test%2Fv2%2Frelay' +
  '&inviteId=0123456789abcdef0123456789abcdef&exp=1790000000000&fp=a1b2c3d4e5f60718' +
  '#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

/** Payloads spanning several versions. */
const PAYLOADS = [
  'HELLO',
  'https://example.test/',
  'x'.repeat(60),
  INVITE_LIKE,
  'y'.repeat(180),
]

/**
 * Ask the reference encoder for the SAME ENCODING this one performs.
 *
 * The segment is forced to `byte` on purpose, and getting this wrong is how the
 * comparison first failed: given a payload like `HELLO`, an optimising encoder
 * emits an ALPHANUMERIC segment, which is a smaller but different (and equally
 * valid) code. This encoder deliberately has no segment optimisation, so the
 * comparison must pin the mode rather than compare two legitimate encodings of the
 * same text and call the difference a bug.
 *
 * @param payload - the text.
 * @param options - `{ errorCorrectionLevel, version, maskPattern }`.
 * @returns the reference encoder's result.
 */
function reference(payload, options) {
  return oracle.create([{ data: payload, mode: 'byte' }], options)
}

// ── the oracle comparison ────────────────────────────────────────────────────

test('every module matches an independent encoder at level M', { skip: oracle === undefined ? 'no reference encoder installed' : false }, () => {
  for (const payload of PAYLOADS) {
    const mine = encodeQrMatrix(payload, { level: 'M' })
    // The mask is passed to the oracle so the comparison isolates the ENCODER
    // (data placement, ECC, function patterns) from the mask CHOICE, which is
    // asserted separately below.
    const other = reference(payload, { errorCorrectionLevel: 'M', version: mine.version, maskPattern: mine.mask })
    assert.equal(other.modules.size, mine.size, `size mismatch for a ${String(payload.length)}-byte payload`)
    assert.deepEqual(
      Array.from(mine.flatten()),
      Array.from(other.modules.data, (entry) => (entry ? 1 : 0)),
      `module mismatch for a ${String(payload.length)}-byte payload at version ${String(mine.version)}, mask ${String(mine.mask)}`,
    )
  }
})

test('every module matches an independent encoder at level L', { skip: oracle === undefined ? 'no reference encoder installed' : false }, () => {
  for (const payload of PAYLOADS) {
    const mine = encodeQrMatrix(payload, { level: 'L' })
    const other = reference(payload, { errorCorrectionLevel: 'L', version: mine.version, maskPattern: mine.mask })
    assert.deepEqual(
      Array.from(mine.flatten()),
      Array.from(other.modules.data, (entry) => (entry ? 1 : 0)),
      `module mismatch at level L for a ${String(payload.length)}-byte payload`,
    )
  }
})

test('the mask choice matches an independent encoder', { skip: oracle === undefined ? 'no reference encoder installed' : false }, () => {
  for (const payload of PAYLOADS) {
    const mine = encodeQrMatrix(payload, { level: 'M' })
    const other = reference(payload, { errorCorrectionLevel: 'M', version: mine.version })
    assert.equal(
      mine.mask,
      other.maskPattern,
      `mask mismatch for a ${String(payload.length)}-byte payload at version ${String(mine.version)}`,
    )
  }
})

test('the chosen version matches an independent encoder', { skip: oracle === undefined ? 'no reference encoder installed' : false }, () => {
  for (const payload of PAYLOADS) {
    const mine = encodeQrMatrix(payload, { level: 'M' })
    const other = reference(payload, { errorCorrectionLevel: 'M' })
    assert.equal(mine.version, other.version, `version mismatch for a ${String(payload.length)}-byte payload`)
  }
})

// ── capacity arithmetic, which the oracle comparison cannot localise ─────────

test('the raw data module formula matches the published table', () => {
  // Version 1: 21x21 grid minus finders, separators and format areas.
  assert.equal(rawDataModules(1), 208)
  assert.equal(rawDataModules(2), 359)
  // Version 7 is the first with a version-information block.
  assert.equal(rawDataModules(7), 1568)
})

test('the data capacity matches the published table at level M', () => {
  const expected = [16, 28, 44, 64, 86, 108, 124, 154, 182, 216]
  for (let version = 1; version <= MAX_VERSION; version += 1) {
    assert.equal(dataCodewords(version, 'M'), expected[version - 1], `version ${String(version)}`)
  }
})

test('alignment pattern centres match the published table', () => {
  assert.deepEqual(alignmentPositions(1), [])
  assert.deepEqual(alignmentPositions(2), [6, 18])
  assert.deepEqual(alignmentPositions(7), [6, 22, 38])
  assert.deepEqual(alignmentPositions(10), [6, 28, 50])
})

test('the Reed-Solomon divisor matches the published generator polynomials', () => {
  // The published QR generator polynomials are quoted in ALPHA NOTATION — as
  // exponents of the field generator, not as coefficient values — so the assertion
  // converts through a log table. Comparing the raw bytes against the table was the
  // first version of this test, and it "failed" against a correct implementation.
  const log = new Array(256).fill(-1)
  let value = 1
  for (let exponent = 0; exponent < 255; exponent += 1) {
    log[value] = exponent
    value <<= 1
    if (value & 0x100) value ^= 0x11d
  }
  const known = {
    7: [87, 229, 146, 149, 238, 102, 21],
    10: [251, 67, 46, 61, 118, 70, 64, 94, 32, 45],
    13: [74, 152, 176, 100, 86, 100, 106, 104, 130, 218, 206, 140, 78],
  }
  for (const [degree, expected] of Object.entries(known)) {
    const divisor = reedSolomonDivisor(Number(degree))
    assert.equal(divisor.length, Number(degree))
    assert.deepEqual(Array.from(divisor, (coefficient) => log[coefficient]), expected, `divisor of degree ${degree}`)
  }
})

test('the Reed-Solomon remainder carries exactly the error correction length', () => {
  for (const degree of [7, 10, 16, 18, 22, 26]) {
    const divisor = reedSolomonDivisor(degree)
    const remainder = reedSolomonRemainder(
      Uint8Array.from([32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17]),
      divisor,
    )
    assert.equal(remainder.length, degree)
    // A remainder computed from an all-zero message is all zeros: a cheap proof
    // that the loop is a linear feedback shift register and not, say, a copy.
    assert.deepEqual(Array.from(reedSolomonRemainder(new Uint8Array(16), divisor)), new Array(degree).fill(0))
  }
})

// ── structure ────────────────────────────────────────────────────────────────

test('the finder patterns, timing patterns and dark module are where they belong', () => {
  const matrix = encodeQrMatrix(INVITE_LIKE)
  const size = matrix.size
  assert.equal(size, matrix.version * 4 + 17)

  /** Whether one module is dark. */
  const dark = (x, y) => matrix.modules[y][x] === true

  // Each finder is a 7x7 ring: dark border, light ring, 3x3 dark centre.
  for (const [originX, originY] of [
    [0, 0],
    [size - 7, 0],
    [0, size - 7],
  ]) {
    assert.equal(dark(originX + 0, originY + 0), true, 'finder corner')
    assert.equal(dark(originX + 1, originY + 1), false, 'finder light ring')
    assert.equal(dark(originX + 3, originY + 3), true, 'finder centre')
    assert.equal(dark(originX + 6, originY + 6), true, 'finder opposite corner')
  }

  // Timing patterns alternate, starting dark, along row 6 and column 6.
  for (let index = 8; index < size - 8; index += 1) {
    assert.equal(dark(index, 6), index % 2 === 0, `timing row at ${String(index)}`)
    assert.equal(dark(6, index), index % 2 === 0, `timing column at ${String(index)}`)
  }

  // The spec's always-dark module.
  assert.equal(dark(8, size - 8), true)
})

test('a payload that does not fit the supported ceiling is refused by name', () => {
  assert.throws(() => encodeQrMatrix('z'.repeat(500), { level: 'M' }), (error) => error instanceof QrError && error.code === 'too-long')
})

test('an out-of-range forced version is refused', () => {
  assert.throws(() => encodeQrMatrix('hi', { version: 0 }), (error) => error.code === 'bad-version')
  assert.throws(() => encodeQrMatrix('hi', { version: 11 }), (error) => error.code === 'bad-version')
  assert.throws(() => encodeQrMatrix('hi', { level: 'Q' }), (error) => error.code === 'bad-level')
})

test('forcing a mask produces that mask', () => {
  for (let mask = 0; mask < 8; mask += 1) {
    assert.equal(encodeQrMatrix('masked', { mask }).mask, mask)
  }
})

test('a larger payload selects a larger version', () => {
  const small = encodeQrMatrix('a')
  const large = encodeQrMatrix(INVITE_LIKE)
  assert.ok(large.version > small.version, 'the invite must need a bigger code than one byte')
})

// ── SVG ──────────────────────────────────────────────────────────────────────

test('the SVG carries a quiet zone, a viewBox and crisp edges', () => {
  const matrix = encodeQrMatrix(INVITE_LIKE)
  const svg = encodeQrSvg(INVITE_LIKE, { size: 300 })
  const total = matrix.size + QUIET_ZONE * 2
  assert.match(svg, new RegExp(`viewBox="0 0 ${String(total)} ${String(total)}"`))
  assert.match(svg, /width="300"/)
  assert.match(svg, /shape-rendering="crispEdges"/)
  // The quiet zone is IN the image, so a saved file stays scannable.
  assert.match(svg, new RegExp(`<rect width="${String(total)}" height="${String(total)}"`))
})

test('the SVG escapes a hostile label instead of breaking the markup', () => {
  const svg = encodeQrSvg('payload', { label: '"><script>alert(1)</script>' })
  // A `<title>` is element TEXT, so the characters that matter are `&`, `<` and
  // `>`; the quote is legal there and escaping it would be visible noise.
  assert.equal(svg.includes('<script>'), false)
  assert.match(svg, /&lt;script&gt;/)
  assert.equal(svg.includes('</script>'), false)
})

test('the light colour may be omitted for a transparent background', () => {
  const svg = encodeQrSvg('payload', { light: 'none' })
  assert.equal(svg.includes('<rect'), false)
  assert.match(svg, /<path fill="#000000"/)
})

test('the SVG renders every dark module exactly once', () => {
  const text = 'counting'
  const matrix = encodeQrMatrix(text)
  const svg = encodeQrSvg(text)
  // Each path command is one horizontal run; their lengths must sum to the number
  // of dark modules.
  const runs = [...svg.matchAll(/h(\d+)v1h-\1z/g)].map((match) => Number(match[1]))
  let dark = 0
  for (const row of matrix.modules) for (const module of row) if (module) dark += 1
  assert.equal(runs.reduce((total, length) => total + length, 0), dark)
})

test('the encoder file resolves no bare specifier, as the plugin requires', async () => {
  const { readFileSync } = await import('node:fs')
  const source = readFileSync(resolve(HERE, '..', 'lib', 'qr.js'), 'utf8')
  for (const match of source.matchAll(/^[ \t]*import[ \t]*(?:[\s\S]*?from[ \t]*)?['"]([^'"]+)['"]/gm)) {
    const specifier = match[1]
    assert.ok(specifier.startsWith('node:') || specifier.startsWith('.'), `qr.js imports the bare specifier ${JSON.stringify(specifier)}`)
  }
})
