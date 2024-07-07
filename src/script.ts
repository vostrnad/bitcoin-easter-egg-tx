import { BIP32Interface } from 'bip32'
import * as bitcoin from 'bitcoinjs-lib'
import { bufferToHex } from './buffer'
import { SignerCallback } from './inputs'

const compile = (script: string) => {
  return bitcoin.script.fromASM(script.trim().replaceAll(/\s+/g, ' '))
}

export const getPubKeyScript = (publicKey: Buffer): Buffer => {
  return bitcoin.script.compile([publicKey, bitcoin.script.OPS.OP_CHECKSIG])
}

export const getPubKeyHashScript = (pubkeyHash: Buffer): Buffer => {
  return bitcoin.script.compile([
    bitcoin.script.OPS.OP_DUP,
    bitcoin.script.OPS.OP_HASH160,
    pubkeyHash,
    bitcoin.script.OPS.OP_EQUALVERIFY,
    bitcoin.script.OPS.OP_CHECKSIG,
  ])
}

export const getMultisigScript = (publicKeys: Buffer[], m: number): Buffer => {
  return bitcoin.script.compile([
    bitcoin.script.number.encode(m),
    ...publicKeys,
    bitcoin.script.number.encode(publicKeys.length),
    bitcoin.script.OPS.OP_CHECKMULTISIG,
  ])
}

export const getMultisigScriptWithWallet = (
  wallet: BIP32Interface,
  m: number,
  n: number,
): Buffer => {
  const publicKeys = Array.from(
    { length: n },
    (_, i) => wallet.derive(i).publicKey,
  )
  return getMultisigScript(publicKeys, m)
}

export const signMultisigScript = (
  privateKeys: Buffer[],
  sighashFlags: number[] = [],
  unsafeSigs = false,
): SignerCallback => {
  return ({ signWith }) => {
    const signatures = privateKeys.map((privateKey, i) =>
      signWith(privateKey, sighashFlags[i], unsafeSigs && i > 0),
    )
    return [bitcoin.script.number.encode(0), ...signatures]
  }
}

export const getMultisigTapscript = (
  publicKeys: Buffer[],
  m: number,
): Buffer => {
  return bitcoin.script.compile([
    ...publicKeys.flatMap((pubkey, i) => [
      pubkey,
      bitcoin.script.OPS[i === 0 ? 'OP_CHECKSIG' : 'OP_CHECKSIGADD'],
    ]),
    bitcoin.script.number.encode(m),
    bitcoin.script.OPS.OP_NUMEQUAL,
  ])
}

export const signMultisigTapscript = (
  wallet: BIP32Interface,
  m: number,
  n: number,
  sighashFlags: number[] = [],
): SignerCallback => {
  return ({ signWith }) => {
    return Array.from({ length: n }).map((_, i) =>
      i < m
        ? signWith(wallet.derive(n - 1 - i), sighashFlags[i])
        : bitcoin.script.number.encode(0),
    )
  }
}

export const getHTLCScript = (
  publicKey: Buffer,
  otherKeys: [Buffer, Buffer],
  paymentHash: Buffer,
): Buffer => {
  const publicKeyHash = bitcoin.crypto.hash160(publicKey)
  const script = compile(`
    OP_DUP
    OP_HASH160
    ${bufferToHex(publicKeyHash)}
    OP_EQUAL
    OP_IF
      OP_CHECKSIG
    OP_ELSE
      ${bufferToHex(otherKeys[0])}
      OP_SWAP
      OP_SIZE
      ${bufferToHex(bitcoin.script.number.encode(32))}
      OP_EQUAL
      OP_NOTIF
        OP_DROP
        ${bufferToHex(bitcoin.script.number.encode(2))}
        OP_SWAP
        ${bufferToHex(otherKeys[1])}
        ${bufferToHex(bitcoin.script.number.encode(2))}
        OP_CHECKMULTISIG
      OP_ELSE
        OP_HASH160
        ${bufferToHex(paymentHash)}
        OP_EQUALVERIFY
        OP_CHECKSIG
      OP_ENDIF
    OP_ENDIF
  `)
  return script
}

export const getLNCommitScript = (publicKeys: Buffer[]): Buffer => {
  const locktime = 42
  const script = compile(`
    OP_IF
      ${bufferToHex(publicKeys[0])}
    OP_ELSE
      ${bufferToHex(bitcoin.script.number.encode(locktime))}
      OP_CHECKSEQUENCEVERIFY
      OP_DROP
      ${bufferToHex(publicKeys[1])}
    OP_ENDIF
    OP_CHECKSIG
  `)
  return script
}

export const signLNCommitScript = (wallet: BIP32Interface): SignerCallback => {
  return ({ signWith }) => {
    const signature = signWith(
      wallet.derive(0),
      bitcoin.Transaction.SIGHASH_NONE,
    )
    return [signature, bitcoin.script.number.encode(1)]
  }
}
