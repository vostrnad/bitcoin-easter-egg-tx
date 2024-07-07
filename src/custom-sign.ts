import secp256k1 from 'secp256k1'

const mTable = Array.from({ length: 32 }, (_, i) => 256n ** BigInt(31 - i))

const bTable = Array.from({ length: 256 }, (_, i) => BigInt(i))

export const uint8ArrayToBigInt = (input: Uint8Array) => {
  let res = 0n
  for (let i = 31; i >= 0; i--) {
    res += bTable[input[i]] * mTable[i]
  }
  return res
}

export const bigIntToUint8Array = (input: bigint) => {
  const res = new Uint8Array(32)
  for (let i = 31; i >= 0; i--) {
    res[i] = Number(input % 256n)
    input >>= 8n
  }
  return res
}

export const modExp = (a: bigint, b: bigint) => {
  a %= n
  let result = 1n
  let x = a
  while (b > 0) {
    const leastSignificantBit = b % 2n
    b /= 2n
    if (leastSignificantBit === 1n) {
      result *= x
      result %= n
    }
    x *= x
    x %= n
  }
  return result
}

export const modInverse = (a: bigint, m: bigint): bigint | null => {
  a = ((a % m) + m) % m
  if (!a || m < 2n) {
    return null
  }
  const s: Array<{ a: bigint; b: bigint }> = []
  let b = m
  while (b) {
    ;[a, b] = [b, a % b]
    s.push({ a, b })
  }
  if (a !== 1n) {
    return null
  }
  let x = 1n
  let y = 0n
  for (let i = s.length - 2; i >= 0; --i) {
    ;[x, y] = [y, x - y * (s[i].a / s[i].b)]
  }
  return ((y % m) + m) % m
}

const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n

const unsafeK =
  bigIntToUint8Array(
    57896044618658097711785492504343953926418782139537452191302581570759080747169n,
  )
const unsafeKInv = bigIntToUint8Array(2n)
const unsafeR = secp256k1.publicKeyCreate(unsafeK).slice(1)

export const signUnsafeLowR = (h: Uint8Array, d: Uint8Array): Buffer => {
  const s = secp256k1.privateKeyTweakMul(
    Buffer.from(unsafeKInv),
    secp256k1.privateKeyTweakAdd(
      Buffer.from(h),
      secp256k1.privateKeyTweakMul(Buffer.from(unsafeR), Buffer.from(d)),
    ),
  )
  return Buffer.from(secp256k1.signatureNormalize(Buffer.concat([unsafeR, s])))
}

export const signCustomK = (h: Uint8Array, d: Uint8Array, k: Uint8Array) => {
  const [r, kInv] = precomputeCustomK(k)
  return signCustomKPrecomputed(h, d, r, kInv)
}

export const precomputeCustomK = (
  k: Uint8Array,
): [r: Uint8Array, kInv: Uint8Array] => {
  return [
    // r
    secp256k1.publicKeyCreate(k, true).slice(1),
    // k^-1
    bigIntToUint8Array(modInverse(uint8ArrayToBigInt(k), n)!),
  ]
}

export const signCustomKPrecomputed = (
  h: Uint8Array,
  d: Uint8Array,
  r: Uint8Array,
  kInv: Uint8Array,
) => {
  const s = secp256k1.privateKeyTweakMul(
    Buffer.from(kInv),
    secp256k1.privateKeyTweakAdd(
      Buffer.from(h),
      secp256k1.privateKeyTweakMul(Buffer.from(r), Buffer.from(d)),
    ),
  )
  return Buffer.from(secp256k1.signatureNormalize(Buffer.concat([r, s])))
}
