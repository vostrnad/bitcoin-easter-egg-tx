import { randomBytes } from 'crypto'
import { BIP32Interface } from 'bip32'
import * as bitcoin from 'bitcoinjs-lib'
import { hash256 } from 'bitcoinjs-lib/src/crypto'
import * as ecc from 'tiny-secp256k1'
import { bufferConcat } from './buffer'
import { signUnsafeLowR } from './custom-sign'
import { grindSignatureFaster, signLowR } from './grind'
import { getP2PKHOutput, getP2PKOutput, getP2WSHOutput } from './outputs'
import {
  getMultisigScript,
  getPubKeyHashScript,
  getPubKeyScript,
} from './script'
import { calculateScriptPath } from './utils'

export interface SignerCallback {
  (param: SignerCallbackParam): Buffer[]
}

export type WalletOrKey = BIP32Interface | Uint8Array

export interface SignerCallbackParam {
  signWith(
    wallet: WalletOrKey,
    sigHashType?: number,
    unsafeSig?: boolean,
  ): Buffer
}

const signWithWalletOrKey = (message: Buffer, wallet: WalletOrKey) => {
  return wallet instanceof Uint8Array
    ? Buffer.from(signLowR(message, wallet))
    : wallet.sign(message, true)
}

const signUnsafeWithWalletOrKey = (message: Buffer, wallet: WalletOrKey) => {
  return wallet instanceof Uint8Array
    ? Buffer.from(signUnsafeLowR(message, wallet))
    : Buffer.from(signUnsafeLowR(message, wallet.privateKey!))
}

const signSchnorrWithWalletOrKey = (message: Buffer, wallet: WalletOrKey) => {
  return wallet instanceof Uint8Array
    ? Buffer.from(ecc.signSchnorr(message, wallet))
    : wallet.signSchnorr(message)
}

export const grindP2PKInput = (
  wallet: BIP32Interface,
  tx: bitcoin.Transaction,
  index: number,
  fn: (signature: Buffer, i: number) => boolean,
  counterStart = 0,
) => {
  const sighashType = bitcoin.Transaction.SIGHASH_ALL
  const scriptCode = getP2PKOutput(wallet, false)
  const signatureHash = tx.hashForSignature(index, scriptCode, sighashType)
  const privkey = wallet.privateKey!

  grindSignatureFaster(
    signatureHash,
    privkey,
    (signature, i) => {
      const encodedSignature = bitcoin.script.signature.encode(
        Buffer.from(signature),
        sighashType,
      )
      tx.setInputScript(index, bitcoin.script.compile([encodedSignature]))
      return fn(encodedSignature, i)
    },
    counterStart,
  )
}

export const grindP2PKInputForTxHash = (
  wallet: BIP32Interface,
  tx: bitcoin.Transaction,
  index: number,
  signatureLength: number,
  fn: (hash: Buffer | undefined, i: number) => boolean,
  counterStart = 0,
) => {
  const sighashType = bitcoin.Transaction.SIGHASH_ALL
  const scriptCode = getP2PKOutput(wallet, false)
  const signatureHash = tx.hashForSignature(index, scriptCode, sighashType)
  const privkey = wallet.privateKey!

  const dummySig = randomBytes(signatureLength)
  tx.setInputScript(index, bitcoin.script.compile([dummySig]))
  const strippedTx = tx.toBuffer(undefined, undefined, false)
  const sigIndex = strippedTx.indexOf(dummySig)

  grindSignatureFaster(
    signatureHash,
    privkey,
    (signature, i) => {
      const encodedSignature = bitcoin.script.signature.encode(
        Buffer.from(signature),
        sighashType,
      )
      let hash: Buffer | undefined
      if (encodedSignature.length === signatureLength) {
        strippedTx.set(encodedSignature, sigIndex)
        hash = hash256(strippedTx)
      }
      if (!fn(hash, i)) {
        return false
      }
      tx.setInputScript(index, bitcoin.script.compile([encodedSignature]))
      return true
    },
    counterStart,
  )
}

export const signP2PKInputWithKey = (
  privateKey: Uint8Array,
  tx: bitcoin.Transaction,
  index: number,
  compressed = true,
) => {
  const sighashType = bitcoin.Transaction.SIGHASH_ALL
  const scriptCode = getPubKeyScript(
    Buffer.from(ecc.pointFromScalar(privateKey, compressed)!),
  )
  const signatureHash = tx.hashForSignature(index, scriptCode, sighashType)
  const signature = Buffer.from(signLowR(signatureHash, privateKey))
  tx.setInputScript(
    index,
    bitcoin.script.compile([
      bitcoin.script.signature.encode(signature, sighashType),
    ]),
  )
}

export const signP2PKInputWithWallet = (
  wallet: BIP32Interface,
  tx: bitcoin.Transaction,
  index: number,
  compressed = true,
) => {
  signP2PKInputWithKey(wallet.privateKey!, tx, index, compressed)
}

export const signP2PKHInputWithKey = (
  privateKey: Uint8Array,
  tx: bitcoin.Transaction,
  index: number,
) => {
  const publicKey = Buffer.from(ecc.pointFromScalar(privateKey)!)
  const sighashType = bitcoin.Transaction.SIGHASH_ALL
  const scriptCode = getPubKeyHashScript(bitcoin.crypto.hash160(publicKey))
  const signatureHash = tx.hashForSignature(index, scriptCode, sighashType)
  const signature = Buffer.from(signLowR(signatureHash, privateKey))
  tx.setInputScript(
    index,
    bitcoin.script.compile([
      bitcoin.script.signature.encode(signature, sighashType),
      publicKey,
    ]),
  )
}

export const signP2PKHInputWithWallet = (
  wallet: BIP32Interface,
  tx: bitcoin.Transaction,
  index: number,
) => {
  signP2PKHInputWithKey(wallet.privateKey!, tx, index)
}

export const signP2MSInput = (
  publicKeys: Buffer[],
  privateKeys: Buffer[],
  tx: bitcoin.Transaction,
  index: number,
  sighashFlags: number[] = [],
  unsafeSigs = false,
) => {
  const scriptCode = getMultisigScript(publicKeys, privateKeys.length)
  const signatures = privateKeys.map((privateKey, i) => {
    const sighashType = sighashFlags[i] ?? bitcoin.Transaction.SIGHASH_ALL
    const signatureHash = tx.hashForSignature(index, scriptCode, sighashType)
    const signature =
      unsafeSigs && i > 0
        ? signUnsafeLowR(signatureHash, privateKey)
        : Buffer.from(signLowR(signatureHash, privateKey))
    return bitcoin.script.signature.encode(signature, sighashType)
  })
  tx.setInputScript(
    index,
    bitcoin.script.compile([bitcoin.script.number.encode(0), ...signatures]),
  )
}

export const signP2MSInputWithWallet = (
  wallet: BIP32Interface,
  tx: bitcoin.Transaction,
  index: number,
  m: number,
  n: number,
) => {
  const publicKeys = Array.from({ length: n }).map(
    (_, i) => wallet.derive(i).publicKey,
  )
  const privateKeys = Array.from({ length: m }).map(
    (_, i) => wallet.derive(i).privateKey!,
  )
  signP2MSInput(publicKeys, privateKeys, tx, index)
}

export const signP2SHInput = (
  tx: bitcoin.Transaction,
  index: number,
  redeemScript: Buffer,
  signer: SignerCallback,
) => {
  const signWith = (
    wallet: WalletOrKey,
    sighashType?: number,
    unsafeSig?: boolean,
  ) => {
    sighashType ??= bitcoin.Transaction.SIGHASH_ALL
    const signatureHash = tx.hashForSignature(index, redeemScript, sighashType)
    const signature = unsafeSig
      ? signUnsafeWithWalletOrKey(signatureHash, wallet)
      : signWithWalletOrKey(signatureHash, wallet)
    return bitcoin.script.signature.encode(signature, sighashType)
  }
  tx.setInputScript(
    index,
    bitcoin.script.compile([...signer({ signWith }), redeemScript]),
  )
}

export const signWrappedP2WPKHInputWithKey = (
  privateKey: Uint8Array,
  tx: bitcoin.Transaction,
  index: number,
  value: number,
) => {
  const publicKey = Buffer.from(ecc.pointFromScalar(privateKey)!)
  const pubkeyHash = bitcoin.crypto.hash160(publicKey)
  const sighashType = bitcoin.Transaction.SIGHASH_ALL
  const scriptCode = getPubKeyHashScript(pubkeyHash)
  const signatureHash = tx.hashForWitnessV0(
    index,
    scriptCode,
    value,
    sighashType,
  )
  const signature = Buffer.from(signLowR(signatureHash, privateKey))
  tx.setInputScript(index, bufferConcat([0x16, 0x00, 0x14, pubkeyHash]))
  tx.setWitness(index, [
    bitcoin.script.signature.encode(signature, sighashType),
    publicKey,
  ])
}

export const signWrappedP2WPKHInputWithWallet = (
  wallet: BIP32Interface,
  tx: bitcoin.Transaction,
  index: number,
  value: number,
) => {
  signWrappedP2WPKHInputWithKey(wallet.privateKey!, tx, index, value)
}

export const signWrappedP2WSHInput = (
  tx: bitcoin.Transaction,
  index: number,
  value: number,
  witnessScript: Buffer,
  signer: SignerCallback,
) => {
  tx.setInputScript(
    index,
    bitcoin.script.compile([getP2WSHOutput(witnessScript)]),
  )
  signP2WSHInput(tx, index, value, witnessScript, signer)
}

export const signP2WPKHInput = (
  wallet: BIP32Interface,
  tx: bitcoin.Transaction,
  index: number,
  value: number,
) => {
  const sighashType = bitcoin.Transaction.SIGHASH_ALL
  const scriptCode = getP2PKHOutput(wallet)
  const signatureHash = tx.hashForWitnessV0(
    index,
    scriptCode,
    value,
    sighashType,
  )
  const signature = wallet.sign(signatureHash, true)
  tx.setWitness(index, [
    bitcoin.script.signature.encode(signature, sighashType),
    wallet.publicKey,
  ])
}

export const signP2WSHInput = (
  tx: bitcoin.Transaction,
  index: number,
  value: number,
  witnessScript: Buffer,
  signer: SignerCallback,
) => {
  const signWith = (wallet: WalletOrKey, sighashType?: number) => {
    sighashType ??= bitcoin.Transaction.SIGHASH_ALL
    const signatureHash = tx.hashForWitnessV0(
      index,
      witnessScript,
      value,
      sighashType,
    )
    const signature = signWithWalletOrKey(signatureHash, wallet)
    return bitcoin.script.signature.encode(signature, sighashType)
  }
  tx.setWitness(index, [...signer({ signWith }), witnessScript])
}

export const signP2TRKeyPathInput = (
  wallet: BIP32Interface,
  tx: bitcoin.Transaction,
  index: number,
  prevOutScripts: Buffer[],
  values: number[],
) => {
  const sighashType = bitcoin.Transaction.SIGHASH_DEFAULT
  const pubkey = wallet.publicKey.slice(1)
  const tweakedChildNode = wallet.tweak(
    bitcoin.crypto.taggedHash('TapTweak', pubkey),
  )
  const signatureHash = tx.hashForWitnessV1(
    index,
    prevOutScripts,
    values,
    sighashType,
  )
  const signature = tweakedChildNode.signSchnorr(signatureHash)
  tx.setWitness(index, [signature])
}

export const signP2TRScriptPathInput = (
  tx: bitcoin.Transaction,
  index: number,
  leafScript: Buffer,
  internalKey: Buffer,
  prevOutScripts: Buffer[],
  values: number[],
  hashingPartners: Buffer[],
  signer: SignerCallback,
) => {
  const signWith = (wallet: WalletOrKey, sighashType?: number) => {
    sighashType ??= bitcoin.Transaction.SIGHASH_DEFAULT
    const signatureHash = tx.hashForWitnessV1(
      index,
      prevOutScripts,
      values,
      sighashType,
      leafHash,
    )
    const signature = signSchnorrWithWalletOrKey(signatureHash, wallet)
    if (sighashType === bitcoin.Transaction.SIGHASH_DEFAULT) {
      return signature
    } else {
      return bufferConcat([signature, sighashType])
    }
  }
  const { leafHash, tweakParity } = calculateScriptPath(
    leafScript,
    internalKey,
    hashingPartners,
  )
  const controlBlock = bufferConcat([
    0xc0 | tweakParity,
    internalKey,
    ...hashingPartners,
  ])
  tx.setWitness(index, [...signer({ signWith }), leafScript, controlBlock])
}
