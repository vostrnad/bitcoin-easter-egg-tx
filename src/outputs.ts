import { BIP32Interface } from 'bip32'
import * as bitcoin from 'bitcoinjs-lib'
import * as ecc from 'tiny-secp256k1'
import { bufferConcat } from './buffer'
import { getMultisigScriptWithWallet } from './script'
import { calculateScriptPath } from './utils'

export const getP2PKOutput = (wallet: BIP32Interface, compressed = true) => {
  const pubkey = Buffer.from(ecc.pointCompress(wallet.publicKey, compressed))
  return bitcoin.payments.p2pk({ pubkey }).output!
}

const getP2PKHPayment = (wallet: BIP32Interface) => {
  const pubkey = wallet.publicKey
  return bitcoin.payments.p2pkh({ pubkey })
}

export const getP2PKHOutput = (wallet: BIP32Interface) => {
  return getP2PKHPayment(wallet).output!
}

export const getP2MSOutput = (wallet: BIP32Interface, m: number, n: number) => {
  return getMultisigScriptWithWallet(wallet, m, n)
}

export const getP2SHOutput = (redeemScript: Buffer) => {
  return bitcoin.payments.p2sh({ redeem: { output: redeemScript } }).output!
}

const getWrappedP2WPKHPayment = (pubkey: Buffer) => {
  return bitcoin.payments.p2sh({ redeem: bitcoin.payments.p2wpkh({ pubkey }) })
}

export const getWrappedP2WPKHOutput = (pubkey: Buffer) => {
  return getWrappedP2WPKHPayment(pubkey).output!
}

export const getWrappedP2WSHOutput = (witnessScript: Buffer) => {
  return bitcoin.payments.p2sh({
    redeem: bitcoin.payments.p2wsh({
      redeem: { output: witnessScript },
    }),
  }).output!
}

const getP2WPKHPayment = (wallet: BIP32Interface) => {
  const pubkey = wallet.publicKey
  return bitcoin.payments.p2wpkh({ pubkey })
}

export const getP2WPKHOutput = (wallet: BIP32Interface) => {
  return getP2WPKHPayment(wallet).output!
}

const getP2WSHPayment = (witnessScript: Buffer) => {
  return bitcoin.payments.p2wsh({ redeem: { output: witnessScript } })
}

export const getP2WSHOutput = (witnessScript: Buffer) => {
  return getP2WSHPayment(witnessScript).output!
}

export const getP2TRKeyPathOutput = (wallet: BIP32Interface) => {
  const pubkey = wallet.publicKey.slice(1)
  return bitcoin.payments.p2tr({ internalPubkey: pubkey }).output!
}

export const getP2TRScriptPathOutput = (
  leafScript: Buffer,
  internalKey: Buffer,
  hashingPartners?: Buffer[],
) => {
  const { outputKey } = calculateScriptPath(
    leafScript,
    internalKey,
    hashingPartners,
  )
  return bufferConcat([0x51, 0x20, outputKey])
}

export const getOpReturnOutput = (input: Array<string | Buffer>) => {
  const data = input.map((value) => {
    if (typeof value === 'string') {
      value = Buffer.from(value, 'utf8')
    }
    return value
  })
  return bitcoin.payments.embed({ data }).output!
}
