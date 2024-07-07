import { BIP32Interface } from 'bip32'
import * as bitcoin from 'bitcoinjs-lib'
import { sha256 } from 'bitcoinjs-lib/src/crypto'
import secp256k1 from 'secp256k1'
import {
  bigIntToUint8Array,
  modExp,
  modInverse,
  signCustomKPrecomputed,
  uint8ArrayToBigInt,
} from './custom-sign'

export const grindSignature = (
  h: Uint8Array,
  d: Uint8Array,
  fn: (signature: Uint8Array, index: number) => boolean,
  counterStart = 0,
) => {
  const data = Buffer.alloc(32)
  let counter = counterStart
  while (true) {
    data.writeUIntLE(counter, 0, 6)
    const signature = secp256k1.ecdsaSign(h, d, { data }).signature
    if (fn(signature, counter)) return signature
    counter++
  }
}

export const grindDERSignature = (
  h: Uint8Array,
  d: Uint8Array,
  hashType: number,
  fn: (signature: Buffer, index: number) => boolean,
  counterStart = 0,
) => {
  const data = Buffer.alloc(32)
  let counter = counterStart
  while (true) {
    data.writeUIntLE(counter, 0, 6)
    const signature = bitcoin.script.signature.encode(
      Buffer.from(secp256k1.ecdsaSign(h, d, { data }).signature),
      hashType,
    )
    if (fn(signature, counter)) return signature
    counter++
  }
}

export const grindShortSignature = (
  h: Uint8Array,
  d: Uint8Array,
  target: number,
) => {
  return grindSignature(
    h,
    d,
    (signature) =>
      bitcoin.script.signature.encode(Buffer.from(signature), 1).length <=
      target,
  )
}

export const signLowR = (h: Uint8Array, d: Uint8Array) => {
  return grindShortSignature(h, d, 71)
}

const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const inv2Arr = bigIntToUint8Array(modInverse(2n, n)!)

export const grindSignatureFaster = (
  h: Uint8Array,
  d: Uint8Array,
  fn: (signature: Uint8Array, index: number) => boolean,
  offset = 0,
) => {
  let counter = offset
  const k0 =
    (uint8ArrayToBigInt(sha256(Buffer.concat([h, d]))) *
      modExp(2n, BigInt(offset))) %
    n
  let rp = secp256k1.publicKeyCreate(bigIntToUint8Array(k0), false)
  let kInv = bigIntToUint8Array(modInverse(k0, n)!)
  while (true) {
    const signature = signCustomKPrecomputed(h, d, rp.slice(1, 33), kInv)
    if (fn(signature, counter)) return signature
    rp = secp256k1.publicKeyCombine([rp, rp], false)
    kInv = secp256k1.privateKeyTweakMul(kInv, inv2Arr)
    counter++
  }
}

interface ECPair {
  privateKey: Uint8Array
  publicKey: Uint8Array
}

export const grindKeyPair = (
  wallet: BIP32Interface,
  fn: (keypair: ECPair, offset: number) => boolean,
  offsetStart = 0,
) => {
  const privateKey = Buffer.from(wallet.privateKey!)
  secp256k1.privateKeyTweakAdd(
    privateKey,
    bigIntToUint8Array(BigInt(offsetStart)),
  )
  let uncompressedPublicKey = secp256k1.publicKeyCreate(privateKey, false)
  const one = Buffer.alloc(32)
  one[31] = 1
  const generator = secp256k1.publicKeyCreate(one, false)
  let offset = offsetStart
  while (true) {
    const ecpair: ECPair = {
      privateKey,
      publicKey: secp256k1.publicKeyConvert(uncompressedPublicKey, true),
    }
    if (fn(ecpair, offset)) return ecpair
    secp256k1.privateKeyTweakAdd(privateKey, one)
    uncompressedPublicKey = secp256k1.publicKeyCombine(
      [uncompressedPublicKey, generator],
      false,
    )
    offset++
  }
}
