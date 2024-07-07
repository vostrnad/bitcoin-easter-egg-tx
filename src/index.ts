import 'dotenv/config'
import bip32 from 'bip32'
import * as bip39 from 'bip39'
import * as bitcoin from 'bitcoinjs-lib'
import * as ecc from 'tiny-secp256k1'
import { bufferConcat, hexToBuffer } from './buffer'
import { ConsoleLine } from './console'
import {
  precomputeCustomK,
  signCustomK,
  signCustomKPrecomputed,
  signUnsafeLowR,
} from './custom-sign'
import { grindDERSignature, grindKeyPair } from './grind'
import {
  grindP2PKInputForTxHash,
  signP2TRKeyPathInput,
  signP2TRScriptPathInput,
} from './inputs'
import {
  getP2SHOutput,
  getP2TRKeyPathOutput,
  getP2WSHOutput,
  getWrappedP2WPKHOutput,
} from './outputs'
import { famousTxids, getTxParams, grinding } from './params'
import {
  getLNCommitScript,
  getMultisigScript,
  getPubKeyHashScript,
  getPubKeyScript,
  signMultisigTapscript,
} from './script'
import { sum, txidToHash } from './utils'

bitcoin.initEccLib(ecc)

const lowRNonces67 = process.env.LOW_R_NONCES_67!.split(',').map(hexToBuffer)
const lowRNonces68 = process.env.LOW_R_NONCES_68!.split(',').map(hexToBuffer)
const mnemonic = process.env.BIP39_MNEMONIC || ''
if (!bip39.validateMnemonic(mnemonic)) {
  throw new Error('Invalid mnemonic')
}
const seed = bip39.mnemonicToSeedSync(mnemonic)
const masterWallet = bip32(ecc).fromSeed(seed)
const inputWallet = masterWallet.deriveHardened(0)
const outputWallet = masterWallet.deriveHardened(1)
const bip86Wallet = masterWallet.derivePath("m/86'/0'/0'/0")

const params = getTxParams(masterWallet)

const fundingInputHash = txidToHash(
  '8534889029f7ff1bc40d89a836492ab354d5f43001b71def6b02d1bee1169ae1',
)

const fundingInputAmount = 231228
const fundingFeeRate = 24
const fundingLocktime = 839393

const fundingTx = new bitcoin.Transaction()
fundingTx.locktime = fundingLocktime
fundingTx.version = 2
fundingTx.addInput(fundingInputHash, 0, 0xfffffffd)
params.inputs.forEach((input) => {
  if (input.index !== undefined) {
    fundingTx.addOutput(input.scriptPubKey, input.amount)
  }
})
fundingTx.addOutput(getP2TRKeyPathOutput(bip86Wallet.derive(1)), 0) // 5, P2SH
fundingTx.addOutput(getP2TRKeyPathOutput(bip86Wallet.derive(2)), 0) // 6, P2WSH
fundingTx.addOutput(getP2TRKeyPathOutput(bip86Wallet.derive(3)), 0) // 7, change

const signFundingTx = () => {
  signP2TRKeyPathInput(
    bip86Wallet.derive(0),
    fundingTx,
    0,
    [
      hexToBuffer(
        '51209021271df6e60ad9f7be7e8936fa03458ab0f9cb825f64f2c4e50b64e0bbd7ee',
      ),
    ],
    [fundingInputAmount],
  )
}

signFundingTx()

const fundingTxP2sh = new bitcoin.Transaction()
fundingTxP2sh.version = 2
fundingTxP2sh.locktime = fundingLocktime
fundingTxP2sh.addInput(fundingTx.getHash(), 5, 0xfffffffd)
fundingTxP2sh.addOutput(params.inputs[3].scriptPubKey, params.inputs[3].amount)

const signFundingTxP2sh = () => {
  signP2TRKeyPathInput(
    bip86Wallet.derive(1),
    fundingTxP2sh,
    0,
    [getP2TRKeyPathOutput(bip86Wallet.derive(1))],
    [fundingTx.outs[5].value],
  )
}

signFundingTxP2sh()

const fundingTxP2wsh = new bitcoin.Transaction()
fundingTxP2wsh.version = 2
fundingTxP2wsh.locktime = fundingLocktime
fundingTxP2wsh.addInput(fundingTx.getHash(), 6, 0xfffffffd)
fundingTxP2wsh.addOutput(params.inputs[7].scriptPubKey, params.inputs[7].amount)

const signFundingTxP2wsh = () => {
  signP2TRKeyPathInput(
    bip86Wallet.derive(2),
    fundingTxP2wsh,
    0,
    [getP2TRKeyPathOutput(bip86Wallet.derive(2))],
    [fundingTx.outs[6].value],
  )
}

signFundingTxP2wsh()

fundingTx.outs[5].value =
  params.inputs[3].amount + fundingFeeRate * fundingTxP2sh.virtualSize()
fundingTx.outs[6].value =
  params.inputs[7].amount + fundingFeeRate * fundingTxP2wsh.virtualSize()

fundingTx.outs[7].value =
  fundingInputAmount -
  sum(fundingTx.outs.map((out) => out.value)) -
  fundingFeeRate * fundingTx.virtualSize()

signFundingTx()

fundingTxP2wsh.ins[0].hash = fundingTx.getHash()
fundingTxP2sh.ins[0].hash = fundingTx.getHash()

params.inputs[3].external = {
  txid: fundingTxP2sh.getId(),
  index: 0,
}

params.inputs[7].external = {
  txid: fundingTxP2wsh.getId(),
  index: 0,
}

const prevHash = fundingTx.getHash()

const tx = new bitcoin.Transaction()

// Sat Jan 03 2009 18:15:05 GMT+0000
tx.locktime = 1231006505

params.inputs.forEach((input) => {
  if (input.external) {
    tx.addInput(
      hexToBuffer(input.external.txid).reverse(),
      input.external.index,
      input.nSequence,
    )
  } else {
    tx.addInput(prevHash, input.index ?? 0, input.nSequence)
  }
})

const prevOutScripts = params.inputs.map((input) => input.scriptPubKey)
const prevValues = params.inputs.map((input) => input.amount)

params.outputs.forEach((output) => {
  tx.addOutput(output.scriptPubKey, output.amount)
})

const consoleLine = new ConsoleLine()

consoleLine.writeBase('Grinding P2SH 2: ')

grindKeyPair(
  inputWallet.derive(3).derive(0),
  ({ privateKey, publicKey }, offset) => {
    params.p2sh.privateKeys[0] = Buffer.from(privateKey)
    params.p2sh.publicKeys[0] = Buffer.from(publicKey)
    params.redeemScript = getMultisigScript(
      params.p2sh.publicKeys,
      params.p2sh.privateKeys.length,
    )
    const scriptPubKey = getP2SHOutput(params.redeemScript)
    params.inputs[3].scriptPubKey = scriptPubKey
    fundingTxP2sh.outs[0].script = scriptPubKey
    tx.ins[3].hash = fundingTxP2sh.getHash()
    params.inputs[3].external = {
      txid: fundingTxP2sh.getId(),
      index: 0,
    }
    prevOutScripts[3] = scriptPubKey
    const sighashType = params.p2sh.sighashFlags[1]
    const signatureHash = tx.hashForSignature(
      3,
      params.redeemScript,
      sighashType,
    )
    const signature = bitcoin.script.signature.encode(
      signUnsafeLowR(signatureHash, params.p2sh.privateKeys[1]),
      sighashType,
    )
    if (offset % 1000 === 0) consoleLine.update(offset)
    if (signature.length === grinding.signatures.p2sh2) {
      consoleLine.update(offset)
      return true
    }
    return false
  },
  grinding.offsets.p2sh2,
)

signFundingTxP2sh()

consoleLine.newline()

consoleLine.writeBase('Grinding P2WSH: ')

const p2wshNonce = lowRNonces67[0]
const p2wshNoncePrecompute = precomputeCustomK(p2wshNonce)

grindKeyPair(
  inputWallet.derive(7).derive(1),
  ({ publicKey }, offset) => {
    params.p2wsh.publicKeys[1] = Buffer.from(publicKey)
    params.witnessScript = getLNCommitScript(params.p2wsh.publicKeys)
    const scriptPubKey = getP2WSHOutput(params.witnessScript)
    params.inputs[7].scriptPubKey = scriptPubKey
    fundingTxP2wsh.outs[0].script = scriptPubKey
    tx.ins[7].hash = fundingTxP2wsh.getHash()
    params.inputs[7].external = {
      txid: fundingTxP2wsh.getId(),
      index: 0,
    }
    prevOutScripts[7] = scriptPubKey

    const sighashType = params.p2wsh.sighashFlag
    const signatureHash = tx.hashForWitnessV0(
      7,
      params.witnessScript,
      params.inputs[7].amount,
      sighashType,
    )
    const signature = bitcoin.script.signature.encode(
      signCustomKPrecomputed(
        signatureHash,
        params.p2wsh.privateKey,
        ...p2wshNoncePrecompute,
      ),
      sighashType,
    )
    if (offset % 1000 === 0) consoleLine.update(offset)
    if (signature.length === grinding.signatures.p2wsh) {
      consoleLine.update(offset)
      tx.setWitness(7, [
        signature,
        bitcoin.script.number.encode(1),
        params.witnessScript,
      ])
      return true
    }
    return false
  },
  grinding.offsets.p2wsh,
)

signFundingTxP2wsh()

consoleLine.newline()

consoleLine.writeBase('Grinding P2SH 3: ')

grindKeyPair(
  outputWallet.derive(3),
  ({ publicKey }, offset) => {
    const scriptPubKey = getWrappedP2WPKHOutput(Buffer.from(publicKey))
    params.outputs[3].scriptPubKey = scriptPubKey
    tx.outs[3].script = scriptPubKey
    const sighashType = params.p2sh.sighashFlags[2]
    const signatureHash = tx.hashForSignature(
      3,
      params.redeemScript,
      sighashType,
    )
    const signature = bitcoin.script.signature.encode(
      signUnsafeLowR(signatureHash, params.p2sh.privateKeys[2]),
      sighashType,
    )
    if (offset % 1000 === 0) consoleLine.update(offset)
    if (signature.length === grinding.signatures.p2sh3) {
      consoleLine.update(offset)
      return true
    }
    return false
  },
  grinding.offsets.p2sh3,
)

consoleLine.newline()

consoleLine.writeBase('Grinding wrapped P2WSH: ')

const wrappedP2wshNonce = lowRNonces67[1]
const wrappedP2wshNoncePrecompute = precomputeCustomK(wrappedP2wshNonce)
const wrappedP2wshPrivateKey = inputWallet.derive(5).derive(0).privateKey!

grindKeyPair(outputWallet.derive(5), ({ publicKey }, offset) => {
  const scriptPubKey = getP2WSHOutput(getPubKeyScript(Buffer.from(publicKey)))
  params.outputs[5].scriptPubKey = scriptPubKey
  tx.outs[5].script = scriptPubKey
  const sighashType = bitcoin.Transaction.SIGHASH_SINGLE
  const signatureHash = tx.hashForWitnessV0(
    5,
    params.wrappedWitnessScript,
    params.inputs[5].amount,
    sighashType,
  )
  const signature = bitcoin.script.signature.encode(
    signCustomKPrecomputed(
      signatureHash,
      wrappedP2wshPrivateKey,
      ...wrappedP2wshNoncePrecompute,
    ),
    sighashType,
  )
  if (offset % 1000 === 0) consoleLine.update(offset)
  if (signature.length === grinding.signatures.wrappedP2wsh) {
    consoleLine.update(offset)
    tx.setInputScript(
      5,
      bitcoin.script.compile([getP2WSHOutput(params.wrappedWitnessScript)]),
    )
    tx.setWitness(5, [
      signature,
      inputWallet.derive(5).derive(0).publicKey,
      params.wrappedWitnessScript,
    ])
    return true
  }
  return false
})

consoleLine.newline()

consoleLine.writeBase('Grinding P2MS 2 and P2WPKH: ')

const p2msScript = getMultisigScript(
  params.p2ms.publicKeys,
  params.p2ms.privateKeys.length,
)
const p2wpkhNonce = lowRNonces67[2]
const p2wpkhNoncePrecompute = precomputeCustomK(p2wpkhNonce)
const p2wpkhScriptCode = getPubKeyHashScript(
  bitcoin.crypto.hash160(inputWallet.derive(6).publicKey),
)
const p2wpkhPrivateKey = inputWallet.derive(6).privateKey!

grindKeyPair(
  outputWallet.derive(0),
  ({ publicKey }, offset) => {
    if (offset % 1000 === 0) consoleLine.update(offset)
    const scriptPubKey = getPubKeyScript(Buffer.from(publicKey))
    params.outputs[0].scriptPubKey = scriptPubKey
    tx.outs[0].script = scriptPubKey
    {
      const sighashType = params.p2ms.sighashFlags[1]
      const signatureHash = tx.hashForSignature(2, p2msScript, sighashType)
      const signature = bitcoin.script.signature.encode(
        signUnsafeLowR(signatureHash, params.p2ms.privateKeys[1]),
        sighashType,
      )
      if (signature.length !== grinding.signatures.p2ms2) {
        return false
      }
    }
    {
      const sighashType = bitcoin.Transaction.SIGHASH_ALL
      const signatureHash = tx.hashForWitnessV0(
        6,
        p2wpkhScriptCode,
        params.inputs[6].amount,
        sighashType,
      )
      const signature = bitcoin.script.signature.encode(
        signCustomKPrecomputed(
          signatureHash,
          p2wpkhPrivateKey,
          ...p2wpkhNoncePrecompute,
        ),
        sighashType,
      )
      if (signature.length !== grinding.signatures.p2wpkh) {
        return false
      }
      tx.setWitness(6, [signature, inputWallet.derive(6).publicKey])
    }
    consoleLine.update(offset)
    return true
  },
  grinding.offsets.p2ms2AndP2wpkh,
)

consoleLine.newline()

consoleLine.writeBase('Grinding P2PKH: ')

const p2pkhScriptcode = getPubKeyHashScript(
  bitcoin.crypto.hash160(inputWallet.derive(1).publicKey),
)
const p2pkhSighashType = bitcoin.Transaction.SIGHASH_NONE
const p2pkhSignatureHash = tx.hashForSignature(
  1,
  p2pkhScriptcode,
  p2pkhSighashType,
)

grindDERSignature(
  p2pkhSignatureHash,
  inputWallet.derive(1).privateKey!,
  p2pkhSighashType,
  (signature, counter) => {
    if (counter % 1000 === 0) consoleLine.update(counter)
    if (signature.length !== 70) {
      return false
    }
    consoleLine.update(counter)
    tx.setInputScript(
      1,
      bitcoin.script.compile([signature, inputWallet.derive(1).publicKey]),
    )
    return true
  },
)

consoleLine.newline()

consoleLine.writeBase('Grinding P2MS 1: ')

const p2ms1SighashType = params.p2ms.sighashFlags[0]
const p2ms1SignatureHash = tx.hashForSignature(2, p2msScript, p2ms1SighashType)

grindDERSignature(
  p2ms1SignatureHash,
  params.p2ms.privateKeys[0],
  p2ms1SighashType,
  (signature, counter) => {
    if (counter % 1000 === 0) consoleLine.update(counter)
    if (signature.length !== grinding.signatures.p2ms1) {
      return false
    }
    consoleLine.update(counter)
    const signatures = [signature]
    {
      const sighashType = params.p2ms.sighashFlags[1]
      const signatureHash = tx.hashForSignature(2, p2msScript, sighashType)
      signatures.push(
        bitcoin.script.signature.encode(
          signUnsafeLowR(signatureHash, params.p2ms.privateKeys[1]),
          sighashType,
        ),
      )
    }
    tx.setInputScript(
      2,
      bitcoin.script.compile([bitcoin.script.number.encode(0), ...signatures]),
    )
    return true
  },
  grinding.offsets.p2ms1,
)

consoleLine.newline()

// sign P2SH 1
{
  const p2sh1Nonce = lowRNonces68[0]
  const p2sh1SighashType = params.p2sh.sighashFlags[0]
  const p2sh1SignatureHash = tx.hashForSignature(
    3,
    params.redeemScript,
    p2sh1SighashType,
  )
  const p2sh1Signature = bitcoin.script.signature.encode(
    signCustomK(p2sh1SignatureHash, params.p2sh.privateKeys[0], p2sh1Nonce),
    p2sh1SighashType,
  )
  if (p2sh1Signature.length !== 68) {
    throw new Error(
      `Expected signature length 68, got ${p2sh1Signature.length}`,
    )
  }
  const signatures = [p2sh1Signature]
  params.p2sh.privateKeys.forEach((privateKey, i) => {
    if (i === 0) return
    const sighashType = params.p2sh.sighashFlags[i]
    const signatureHash = tx.hashForSignature(
      3,
      params.redeemScript,
      sighashType,
    )
    signatures.push(
      bitcoin.script.signature.encode(
        signUnsafeLowR(signatureHash, privateKey),
        sighashType,
      ),
    )
  })
  tx.setInputScript(
    3,
    bitcoin.script.compile([
      bitcoin.script.number.encode(0),
      ...signatures,
      params.redeemScript,
    ]),
  )
}

// sign wrapped P2WPKH 1
{
  const wrappedP2wpkhWallet = inputWallet.derive(4)
  const wrappedP2wpkhPrivateKey = wrappedP2wpkhWallet.privateKey!
  const wrappedP2wpkhPublicKey = wrappedP2wpkhWallet.publicKey
  const wrappedP2wpkhPublicKeyHash = bitcoin.crypto.hash160(
    wrappedP2wpkhPublicKey,
  )
  const wrappedP2wpkhNonce = lowRNonces67[3]
  const wrappedP2wpkhSighashType = bitcoin.Transaction.SIGHASH_NONE
  const wrappedP2wpkhSignatureHash = tx.hashForWitnessV0(
    4,
    getPubKeyHashScript(wrappedP2wpkhPublicKeyHash),
    params.inputs[4].amount,
    wrappedP2wpkhSighashType,
  )
  const wrappedP2wpkhSignature = bitcoin.script.signature.encode(
    signCustomK(
      wrappedP2wpkhSignatureHash,
      wrappedP2wpkhPrivateKey,
      wrappedP2wpkhNonce,
    ),
    wrappedP2wpkhSighashType,
  )
  if (wrappedP2wpkhSignature.length !== 67) {
    throw new Error(
      `Expected signature length 67, got ${wrappedP2wpkhSignature.length}`,
    )
  }
  tx.setInputScript(
    4,
    bufferConcat([0x16, 0x00, 0x14, wrappedP2wpkhPublicKeyHash]),
  )
  tx.setWitness(4, [wrappedP2wpkhSignature, wrappedP2wpkhPublicKey])
}

signP2TRKeyPathInput(inputWallet.derive(8), tx, 8, prevOutScripts, prevValues)
signP2TRScriptPathInput(
  tx,
  9,
  params.leafScript,
  params.taprootInternalKey,
  prevOutScripts,
  prevValues,
  famousTxids,
  signMultisigTapscript(inputWallet.derive(9), 5, 7, [
    bitcoin.Transaction.SIGHASH_DEFAULT,
    bitcoin.Transaction.SIGHASH_ALL,
    bitcoin.Transaction.SIGHASH_NONE,
    bitcoin.Transaction.SIGHASH_ALL | bitcoin.Transaction.SIGHASH_ANYONECANPAY,
    bitcoin.Transaction.SIGHASH_NONE | bitcoin.Transaction.SIGHASH_ANYONECANPAY,
  ]),
)
tx.ins[9].witness[4] = hexToBuffer(
  'a5781a0adaa80ab7f7f164172dd1a1cb127e523daa0d6949aba074a15c589f12dfb8183182afec9230cb7947b7422a4abc1bb78173550d66274ea19f6c9dd92c82',
)

consoleLine.writeBase('Grinding P2PK for TXID: ')

grindP2PKInputForTxHash(
  inputWallet.derive(0),
  tx,
  0,
  71,
  (hash, counter) => {
    if (
      hash &&
      hash.at(-1) === 0xb1 &&
      hash.at(-2) === 0x0c &&
      hash.at(-3) === 0x00 &&
      hash.at(-4) === 0x00 &&
      hash.at(-5) === 0x00
    ) {
      consoleLine.update(counter)
      return true
    }
    if (counter % 10000 === 0) {
      consoleLine.update(counter)
    }
    return false
  },
  grinding.offsets.p2pk,
)

consoleLine.newline()

console.log(tx.getId())
