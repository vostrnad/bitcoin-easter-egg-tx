import * as bitcoin from 'bitcoinjs-lib'
import * as ecc from 'tiny-secp256k1'
import { bufferConcat, compactSize, hexToBuffer } from './buffer'

export const sum = (array: number[]): number =>
  array.reduce((prev, curr) => prev + curr, 0)

export const txidToHash = (txid: string) => hexToBuffer(txid).reverse()

export interface ScriptPathResult {
  leafHash: Buffer
  tapTweakHash: Buffer
  outputKey: Uint8Array
  tweakParity: 0 | 1
}

export const calculateScriptPath = (
  leafScript: Buffer,
  internalKey: Buffer,
  hashingPartners?: Buffer[],
): ScriptPathResult => {
  const leafHash = bitcoin.crypto.taggedHash(
    'TapLeaf',
    bufferConcat([0xc0, compactSize(leafScript.length), leafScript]),
  )
  let tapBranch = leafHash
  hashingPartners?.forEach((branch) => {
    tapBranch = bitcoin.crypto.taggedHash(
      'TapBranch',
      bufferConcat([branch, tapBranch].sort(Buffer.compare)),
    )
  })
  const tapTweakHash = bitcoin.crypto.taggedHash(
    'TapTweak',
    bufferConcat([internalKey, tapBranch]),
  )
  const tweak = ecc.xOnlyPointAddTweak(internalKey, tapTweakHash)!

  return {
    leafHash,
    tapTweakHash,
    outputKey: tweak.xOnlyPubkey,
    tweakParity: tweak.parity,
  }
}
