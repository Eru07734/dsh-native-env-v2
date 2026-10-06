/**
 * dsh-native-env / qr — a byte-mode QR encoder, versions 1 to 10, level M.
 *
 * Why this exists instead of an npm package: the plugin halves are mounted by
 * ABSOLUTE PATH and cannot resolve a bare specifier (see `wire.js`), and a QR
 * library is exactly the kind of dependency that would otherwise be added without
 * noticing. The invitation has to become a picture, so the encoder is here.
 *
 * The scope is deliberately narrowed to what an invite needs, and each narrowing
 * REMOVES a class of bug rather than merely reducing code:
 *
 *   - **byte mode only.** An invite is ASCII; numeric/alphanumeric/kanji modes
 *     exist to save space, and their segment-optimisation logic is where QR
 *     encoders usually go wrong.
 *   - **error correction level M only.** ~15% recovery is the right trade at this
 *     size: level L produces a code too fragile to survive a phone camera at an
 *     angle, and level Q/H push a 160-byte invite past the version ceiling for no
 *     benefit a screen-to-camera transfer needs. (Level L is accepted too, for
 *     callers that want a visibly smaller code.)
 *   - **versions 1 to 10.** A 1024-character invite is refused by `pairing.js`
 *     long before it reaches here, and version 10 at level M already holds 216
 *     bytes. The version-info block (needed from version 7 up) is therefore
 *     implemented, but the larger alignment-pattern spacing table is not.
 *   - **one mask chosen by the standard's penalty score**, rather than trying to
 *     be clever. The penalty rules are in the spec for exactly this decision.
 *
 * The public entry points render an SVG string or expose the module matrix; the
 * matrix is what a test can compare against an independent encoder.
 *
 * @module dsh-native-env/qr
 */

/** Error correction levels, as the two-bit field the format information carries. */
export const EC_LEVEL = Object.freeze({
  L: { name: 'L', formatBits: 1 },
  M: { name: 'M', formatBits: 0 },
})

/** Error correction codewords per block, indexed by version, for each level. */
const ECC_CODEWORDS_PER_BLOCK = Object.freeze({
  L: [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18],
  M: [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26],
})

/** Error correction blocks per version, for each level. */
const NUM_BLOCKS = Object.freeze({
  L: [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4],
  M: [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5],
})

/** The largest version this encoder supports. */
export const MAX_VERSION = 10

/** The smallest version this encoder supports. */
export const MIN_VERSION = 1

/** The width of the mandatory quiet zone, in modules, on every side. */
export const QUIET_ZONE = 4

/** A QR encoding failure with a code the caller can act on. */
export class QrError extends Error {
  /**
   * @param code - a stable machine-readable code.
   * @param message - the human-readable explanation.
   */
  constructor(code, message) {
    super(message)
    this.name = 'QrError'
    this.code = code
  }
}

// ── bit buffer ───────────────────────────────────────────────────────────────

/** An append-only bit buffer, as QR's data encoding needs. */
class BitBuffer {
  constructor() {
    /** @type {number[]} one 0/1 per bit. */
    this.bits = []
  }

  /**
   * Append the low `length` bits of `value`, most significant first.
   * @param value - the bits to append.
   * @param length - how many bits.
   */
  put(value, length) {
    for (let index = length - 1; index >= 0; index -= 1) this.bits.push((value >>> index) & 1)
  }

  /** @returns the number of bits written. */
  get length() {
    return this.bits.length
  }
}

// ── capacity arithmetic ──────────────────────────────────────────────────────

/**
 * The number of data modules available in one version, before error correction.
 *
 * Mirrors the spec's table as a formula, which is what makes it short enough to
 * check by eye: the base is the full grid minus the three finders and their
 * separators, and each version may additionally lose alignment patterns, the
 * timing-adjacent format areas, and (from version 7) the version blocks.
 *
 * @param version - the QR version, 1 to 40.
 * @returns the raw data-module count.
 */
export function rawDataModules(version) {
  let result = (16 * version + 128) * version + 64
  if (version >= 2) {
    const align = Math.floor(version / 7) + 2
    result -= (25 * align - 10) * align - 55
    if (version >= 7) result -= 36
  }
  return result
}

/**
 * The number of usable DATA codewords for one version and level.
 * @param version - the QR version.
 * @param level - `L` or `M`.
 * @returns the data-codeword count.
 */
export function dataCodewords(version, level) {
  const table = ECC_CODEWORDS_PER_BLOCK[level]
  const blocks = NUM_BLOCKS[level]
  if (table === undefined || blocks === undefined) throw new QrError('bad-level', `unknown error correction level ${JSON.stringify(level)}`)
  return Math.floor(rawDataModules(version) / 8) - table[version] * blocks[version]
}

/**
 * The character-count indicator width for byte mode.
 * @param version - the QR version.
 * @returns the bit width.
 */
function byteCountBits(version) {
  // Byte mode: 8 bits for versions 1-9, 16 bits for versions 10-26.
  return version <= 9 ? 8 : 16
}

// ── Reed-Solomon over GF(256) ────────────────────────────────────────────────

/** Multiply two field elements, modulo the QR primitive polynomial 0x11D. */
function gfMultiply(x, y) {
  let z = 0
  for (let shift = 7; shift >= 0; shift -= 1) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d)
    z ^= ((y >>> shift) & 1) * x
  }
  return z & 0xff
}

/**
 * Build the Reed-Solomon divisor polynomial for `degree` error correction
 * codewords.
 * @param degree - the number of EC codewords.
 * @returns the coefficients, highest power first, excluding the leading 1.
 */
export function reedSolomonDivisor(degree) {
  const result = new Uint8Array(degree)
  result[degree - 1] = 1
  let root = 1
  for (let index = 0; index < degree; index += 1) {
    for (let position = 0; position < degree; position += 1) {
      result[position] = gfMultiply(result[position], root)
      if (position + 1 < degree) result[position] ^= result[position + 1]
    }
    root = gfMultiply(root, 0x02)
  }
  return result
}

/**
 * Compute the Reed-Solomon remainder for one block.
 * @param data - the block's data codewords.
 * @param divisor - the divisor from {@link reedSolomonDivisor}.
 * @returns the EC codewords.
 */
export function reedSolomonRemainder(data, divisor) {
  const result = new Uint8Array(divisor.length)
  for (const byte of data) {
    const factor = byte ^ result[0]
    result.copyWithin(0, 1)
    result[result.length - 1] = 0
    for (let index = 0; index < result.length; index += 1) result[index] ^= gfMultiply(divisor[index], factor)
  }
  return result
}

// ── codeword assembly ────────────────────────────────────────────────────────

/**
 * Split the data codewords into blocks, add EC codewords to each, and interleave.
 *
 * The block count and EC length come from the tables rather than from a
 * hand-written per-version block structure: the split is derived from the raw
 * codeword count, so a typo in a large table cannot silently produce a code that
 * looks right and scans wrong.
 *
 * @param version - the QR version.
 * @param level - `L` or `M`.
 * @param data - the padded data codewords.
 * @returns the interleaved codewords, ready for placement.
 */
export function addEccAndInterleave(version, level, data) {
  const numBlocks = NUM_BLOCKS[level][version]
  const blockEccLength = ECC_CODEWORDS_PER_BLOCK[level][version]
  const rawCodewords = Math.floor(rawDataModules(version) / 8)
  const numShortBlocks = numBlocks - (rawCodewords % numBlocks)
  const shortBlockLength = Math.floor(rawCodewords / numBlocks)
  const divisor = reedSolomonDivisor(blockEccLength)
  const blocks = []
  let offset = 0
  for (let index = 0; index < numBlocks; index += 1) {
    // Short blocks carry one fewer data codeword than long ones.
    const dataLength = shortBlockLength - blockEccLength + (index < numShortBlocks ? 0 : 1)
    const blockData = data.slice(offset, offset + dataLength)
    offset += dataLength
    const ecc = reedSolomonRemainder(blockData, divisor)
    const block = new Uint8Array(shortBlockLength + 1)
    block.set(blockData)
    block.set(ecc, block.length - blockEccLength)
    blocks.push(block)
  }

  const result = new Uint8Array(rawCodewords)
  let resultOffset = 0
  const longBlockLength = blocks[0].length
  for (let index = 0; index < longBlockLength; index += 1) {
    for (let block = 0; block < blocks.length; block += 1) {
      // Skip the padding byte long blocks carry where short blocks have none, so
      // the interleaving stays aligned with the spec's ordering.
      if (index === shortBlockLength - blockEccLength && block < numShortBlocks) continue
      result[resultOffset] = blocks[block][index]
      resultOffset += 1
    }
  }
  return result
}

// ── matrix construction ──────────────────────────────────────────────────────

/** The alignment pattern centres for one version. */
export function alignmentPositions(version) {
  if (version === 1) return []
  const count = Math.floor(version / 7) + 2
  const size = version * 4 + 17
  const step = Math.ceil((version * 4 + 4) / (count * 2 - 2)) * 2
  const result = [6]
  for (let position = size - 7; result.length < count; position -= step) result.splice(1, 0, position)
  return result
}

/** One QR code's module matrix, plus what was chosen to build it. */
export class QrMatrix {
  /**
   * @param version - the QR version.
   * @param level - the error correction level name.
   */
  constructor(version, level) {
    this.version = version
    this.level = level
    this.size = version * 4 + 17
    /** @type {boolean[][]} `modules[y][x]`, false until set. */
    this.modules = Array.from({ length: this.size }, () => Array.from({ length: this.size }, () => false))
    /** @type {boolean[][]} which modules belong to a function pattern. */
    this.isFunction = Array.from({ length: this.size }, () => Array.from({ length: this.size }, () => false))
    this.mask = 0
  }

  /**
   * Set one module, recording that it is part of a function pattern.
   * @param x - the column.
   * @param y - the row.
   * @param dark - whether the module is dark.
   */
  setFunction(x, y, dark) {
    this.modules[y][x] = dark
    this.isFunction[y][x] = true
  }

  /** Draw the three finder patterns and their separators. */
  drawFinders() {
    const positions = [
      [3, 3],
      [this.size - 4, 3],
      [3, this.size - 4],
    ]
    for (const [x, y] of positions) {
      for (let dy = -4; dy <= 4; dy += 1) {
        for (let dx = -4; dx <= 4; dx += 1) {
          const distance = Math.max(Math.abs(dx), Math.abs(dy))
          const xx = x + dx
          const yy = y + dy
          if (xx < 0 || xx >= this.size || yy < 0 || yy >= this.size) continue
          this.setFunction(xx, yy, distance !== 2 && distance !== 4)
        }
      }
    }
  }

  /** Draw every alignment pattern except the three that would overlap a finder. */
  drawAlignments() {
    const positions = alignmentPositions(this.version)
    const last = positions.length - 1
    for (let i = 0; i < positions.length; i += 1) {
      for (let j = 0; j < positions.length; j += 1) {
        // The corners are already covered by the finder patterns.
        if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue
        for (let dy = -2; dy <= 2; dy += 1) {
          for (let dx = -2; dx <= 2; dx += 1) {
            this.setFunction(positions[i] + dx, positions[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1)
          }
        }
      }
    }
  }

  /** Draw the horizontal and vertical timing patterns. */
  drawTiming() {
    for (let index = 0; index < this.size; index += 1) {
      this.setFunction(6, index, index % 2 === 0)
      this.setFunction(index, 6, index % 2 === 0)
    }
  }

  /**
   * Draw the 15 bits of format information, in both of their copies, plus the
   * always-dark module.
   * @param mask - the mask pattern in use.
   */
  drawFormatBits(mask) {
    const levelBits = EC_LEVEL[this.level].formatBits
    const data = (levelBits << 3) | mask
    let remainder = data
    for (let index = 0; index < 10; index += 1) remainder = (remainder << 1) ^ ((remainder >>> 9) * 0x537)
    const bits = ((data << 10) | remainder) ^ 0x5412

    const bit = (index) => ((bits >>> index) & 1) !== 0
    for (let index = 0; index <= 5; index += 1) this.setFunction(8, index, bit(index))
    this.setFunction(8, 7, bit(6))
    this.setFunction(8, 8, bit(7))
    this.setFunction(7, 8, bit(8))
    for (let index = 9; index < 15; index += 1) this.setFunction(14 - index, 8, bit(index))

    for (let index = 0; index < 8; index += 1) this.setFunction(this.size - 1 - index, 8, bit(index))
    for (let index = 8; index < 15; index += 1) this.setFunction(8, this.size - 15 + index, bit(index))
    // The spec's always-dark module; its absence is a common encoder bug.
    this.setFunction(8, this.size - 8, true)
  }

  /** Draw the version information blocks, for versions 7 and up. */
  drawVersionBits() {
    if (this.version < 7) return
    let remainder = this.version
    for (let index = 0; index < 12; index += 1) remainder = (remainder << 1) ^ ((remainder >>> 11) * 0x1f25)
    const bits = (this.version << 12) | remainder
    for (let index = 0; index < 18; index += 1) {
      const dark = ((bits >>> index) & 1) !== 0
      const a = this.size - 11 + (index % 3)
      const b = Math.floor(index / 3)
      this.setFunction(a, b, dark)
      this.setFunction(b, a, dark)
    }
  }

  /**
   * Place the interleaved codewords in the standard zigzag order, applying the
   * mask as it goes.
   * @param codewords - the interleaved codewords.
   */
  drawCodewords(codewords) {
    let index = 0
    const totalBits = codewords.length * 8
    for (let right = this.size - 1; right >= 1; right -= 2) {
      // Column 6 is the vertical timing pattern; the scan skips over it.
      if (right === 6) right = 5
      for (let vertical = 0; vertical < this.size; vertical += 1) {
        for (let offset = 0; offset < 2; offset += 1) {
          const x = right - offset
          const upward = ((right + 1) & 2) === 0
          const y = upward ? this.size - 1 - vertical : vertical
          if (this.isFunction[y][x]) continue
          let dark = false
          if (index < totalBits) dark = ((codewords[index >>> 3] >>> (7 - (index & 7))) & 1) !== 0
          index += 1
          if (maskApplies(this.mask, x, y)) dark = !dark
          this.modules[y][x] = dark
        }
      }
    }
  }

  /**
   * Apply one mask to the data modules only.
   * @param mask - the mask pattern.
   */
  applyMask(mask) {
    for (let y = 0; y < this.size; y += 1) {
      for (let x = 0; x < this.size; x += 1) {
        if (this.isFunction[y][x]) continue
        if (maskApplies(mask, x, y)) this.modules[y][x] = !this.modules[y][x]
      }
    }
  }

  /**
   * The spec's four penalty rules, used to pick the least-noise mask.
   * @returns the total penalty score.
   */
  penaltyScore() {
    const size = this.size
    let result = 0

    // Rule 1: runs of the same colour in a row or column.
    for (let y = 0; y < size; y += 1) {
      let runColor = false
      let runLength = 0
      for (let x = 0; x < size; x += 1) {
        if (this.modules[y][x] === runColor) {
          runLength += 1
          if (runLength === 5) result += 3
          else if (runLength > 5) result += 1
        } else {
          runColor = this.modules[y][x]
          runLength = 1
        }
      }
    }
    for (let x = 0; x < size; x += 1) {
      let runColor = false
      let runLength = 0
      for (let y = 0; y < size; y += 1) {
        if (this.modules[y][x] === runColor) {
          runLength += 1
          if (runLength === 5) result += 3
          else if (runLength > 5) result += 1
        } else {
          runColor = this.modules[y][x]
          runLength = 1
        }
      }
    }

    // Rule 2: 2x2 blocks of one colour.
    for (let y = 0; y < size - 1; y += 1) {
      for (let x = 0; x < size - 1; x += 1) {
        const color = this.modules[y][x]
        if (color === this.modules[y][x + 1] && color === this.modules[y + 1][x] && color === this.modules[y + 1][x + 1]) result += 3
      }
    }

    // Rule 3: finder-like 1:1:3:1:1 patterns with four light modules on a side.
    const finderLike = (get) => {
      for (let start = 0; start + 11 <= size; start += 1) {
        let pattern = 0
        for (let offset = 0; offset < 11; offset += 1) pattern = (pattern << 1) | (get(start + offset) ? 1 : 0)
        if (pattern === 0x05d || pattern === 0x5d0) result += 40
      }
    }
    for (let y = 0; y < size; y += 1) finderLike((x) => this.modules[y][x])
    for (let x = 0; x < size; x += 1) finderLike((y) => this.modules[y][x])

    // Rule 4: deviation of the dark proportion from one half.
    let dark = 0
    for (const row of this.modules) for (const module of row) if (module) dark += 1
    const total = size * size
    const percent = (dark * 100) / total
    result += Math.floor(Math.abs(percent - 50) / 5) * 10

    return result
  }

  /**
   * The matrix as an independent encoder would expose it: a flat array of 0/1 in
   * row-major order. Used by tests to compare against a reference implementation.
   * @returns the flat module array.
   */
  flatten() {
    const flat = new Uint8Array(this.size * this.size)
    for (let y = 0; y < this.size; y += 1) {
      for (let x = 0; x < this.size; x += 1) flat[y * this.size + x] = this.modules[y][x] ? 1 : 0
    }
    return flat
  }
}

/**
 * Whether one mask pattern inverts the module at `(x, y)`.
 * @param mask - the mask pattern, 0 to 7.
 * @param x - the column.
 * @param y - the row.
 * @returns true when the module is inverted.
 */
export function maskApplies(mask, x, y) {
  switch (mask) {
    case 0:
      return (x + y) % 2 === 0
    case 1:
      return y % 2 === 0
    case 2:
      return x % 3 === 0
    case 3:
      return (x + y) % 3 === 0
    case 4:
      return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0
    case 5:
      return ((x * y) % 2) + ((x * y) % 3) === 0
    case 6:
      return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0
    case 7:
      return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0
    default:
      throw new QrError('bad-mask', `unknown mask pattern ${JSON.stringify(mask)}`)
  }
}

// ── encoding ─────────────────────────────────────────────────────────────────

/**
 * Build the padded data codewords for one version, level and payload.
 * @param version - the QR version.
 * @param level - `L` or `M`.
 * @param bytes - the UTF-8 payload.
 * @returns the data codewords.
 */
export function buildDataCodewords(version, level, bytes) {
  const capacity = dataCodewords(version, level)
  const buffer = new BitBuffer()
  buffer.put(0b0100, 4)
  buffer.put(bytes.length, byteCountBits(version))
  for (const byte of bytes) buffer.put(byte, 8)

  const capacityBits = capacity * 8
  if (buffer.length > capacityBits) {
    throw new QrError('too-long', `the payload needs ${String(buffer.length)} bits but version ${String(version)} holds ${String(capacityBits)}`)
  }
  // Terminator, then pad to a byte boundary, then the spec's alternating pad bytes.
  buffer.put(0, Math.min(4, capacityBits - buffer.length))
  buffer.put(0, (8 - (buffer.length % 8)) % 8)
  for (let pad = 0xec; buffer.length < capacityBits; pad ^= 0xec ^ 0x11) buffer.put(pad, 8)

  const codewords = new Uint8Array(buffer.length / 8)
  for (let index = 0; index < buffer.length; index += 1) {
    if (buffer.bits[index] !== 0) codewords[index >>> 3] |= 0x80 >>> (index & 7)
  }
  return codewords
}

/**
 * Encode one string into a QR module matrix.
 *
 * @param text - the payload; encoded as UTF-8 in byte mode.
 * @param options.level - `M` (default) or `L`.
 * @param options.version - force a version instead of choosing the smallest.
 * @param options.mask - force a mask instead of picking the lowest-penalty one.
 * @returns the matrix.
 * @throws {QrError} when the payload does not fit in version {@link MAX_VERSION}.
 */
export function encodeQrMatrix(text, options = {}) {
  const level = options.level ?? 'M'
  if (EC_LEVEL[level] === undefined) throw new QrError('bad-level', `the error correction level must be L or M, got ${JSON.stringify(level)}`)
  const bytes = Buffer.from(String(text), 'utf8')

  let version = options.version
  if (version === undefined) {
    version = undefined
    for (let candidate = MIN_VERSION; candidate <= MAX_VERSION; candidate += 1) {
      const headerBits = 4 + byteCountBits(candidate)
      if (headerBits + bytes.length * 8 <= dataCodewords(candidate, level) * 8) {
        version = candidate
        break
      }
    }
    if (version === undefined) {
      throw new QrError(
        'too-long',
        `the payload is ${String(bytes.length)} bytes, which does not fit version ${String(MAX_VERSION)} at level ${level}`,
      )
    }
  }
  if (!Number.isInteger(version) || version < MIN_VERSION || version > MAX_VERSION) {
    throw new QrError('bad-version', `the version must be ${String(MIN_VERSION)} to ${String(MAX_VERSION)}, got ${JSON.stringify(options.version)}`)
  }

  const codewords = buildDataCodewords(version, level, bytes)
  const interleaved = addEccAndInterleave(version, level, codewords)

  /** Build one candidate matrix with a specific mask applied. */
  const build = (mask) => {
    const matrix = new QrMatrix(version, level)
    // The draw ORDER is load-bearing, not stylistic. The timing pattern spans the
    // full width and height, so it passes THROUGH the finder patterns and the
    // alignment patterns — and the spec gives those precedence. Drawing timing
    // last, which reads more naturally, leaves two contradicting truths in the
    // overlapping modules and produces a code that looks plausible and does not
    // scan: found by comparing every module against a reference encoder.
    matrix.drawTiming()
    matrix.drawFinders()
    matrix.drawAlignments()
    matrix.drawFormatBits(mask)
    matrix.drawVersionBits()
    matrix.mask = mask
    matrix.drawCodewords(interleaved)
    return matrix
  }

  if (options.mask !== undefined) {
    const matrix = build(options.mask)
    return matrix
  }

  // The spec's own rule: try all eight, keep the one with the lowest penalty. The
  // finder patterns and format bits are identical in every candidate, so only the
  // data placement differs — which is why building eight full matrices is cheap
  // enough to do rather than approximate.
  let best
  for (let mask = 0; mask < 8; mask += 1) {
    const candidate = build(mask)
    const score = candidate.penaltyScore()
    if (best === undefined || score < best.score) best = { matrix: candidate, score }
  }
  return best.matrix
}

/**
 * Render one payload as a standalone SVG.
 *
 * The quiet zone is part of the image rather than a CSS margin: a QR code whose
 * white border is a stylesheet property stops being scannable the moment it is
 * saved, printed or pasted somewhere else.
 *
 * @param text - the payload.
 * @param options.size - the rendered edge length in CSS pixels, quiet zone included.
 * @param options.dark - the dark module colour.
 * @param options.light - the light module colour, or `'none'` for transparency.
 * @param options.label - an accessible title.
 * @param options.level / options.version / options.mask - forwarded to {@link encodeQrMatrix}.
 * @returns the SVG markup.
 */
export function encodeQrSvg(text, options = {}) {
  const matrix = encodeQrMatrix(text, options)
  const size = options.size ?? 320
  const dark = options.dark ?? '#000000'
  const light = options.light ?? '#ffffff'
  const total = matrix.size + QUIET_ZONE * 2

  // Horizontal runs become one path command each: a 53-module code would
  // otherwise emit ~1400 <rect> elements, which is a lot of DOM for a picture.
  const commands = []
  for (let y = 0; y < matrix.size; y += 1) {
    let runStart = -1
    for (let x = 0; x <= matrix.size; x += 1) {
      const dark2 = x < matrix.size && matrix.modules[y][x]
      if (dark2 && runStart < 0) runStart = x
      if (!dark2 && runStart >= 0) {
        commands.push(`M${String(runStart + QUIET_ZONE)} ${String(y + QUIET_ZONE)}h${String(x - runStart)}v1h-${String(x - runStart)}z`)
        runStart = -1
      }
    }
  }

  const background =
    light === 'none'
      ? ''
      : `<rect width="${String(total)}" height="${String(total)}" fill="${escapeAttribute(light)}"/>`
  const title = options.label === undefined ? '' : `<title>${escapeText(options.label)}</title>`
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${String(total)} ${String(total)}" ` +
    `width="${String(size)}" height="${String(size)}" shape-rendering="crispEdges" role="img">` +
    `${title}${background}<path fill="${escapeAttribute(dark)}" d="${commands.join('')}"/></svg>`
  )
}

/** Escape the five characters that may not appear raw in an XML attribute. */
function escapeAttribute(value) {
  return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;')
}

/** Escape the three characters that may not appear raw in XML text. */
function escapeText(value) {
  return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
}
