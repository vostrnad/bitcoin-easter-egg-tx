import { BIP32Interface } from 'bip32'
import * as bitcoin from 'bitcoinjs-lib'
import { hexToBuffer } from './buffer'
import {
  getOpReturnOutput,
  getP2MSOutput,
  getP2PKHOutput,
  getP2PKOutput,
  getP2SHOutput,
  getP2TRKeyPathOutput,
  getP2TRScriptPathOutput,
  getP2WPKHOutput,
  getP2WSHOutput,
  getWrappedP2WPKHOutput,
  getWrappedP2WSHOutput,
} from './outputs'
import {
  getHTLCScript,
  getLNCommitScript,
  getMultisigScript,
  getMultisigTapscript,
  getPubKeyScript,
} from './script'

interface TxInOutBase {
  scriptPubKey: Buffer
  amount: number
}

interface TxInput extends TxInOutBase {
  nSequence: number
  external?: {
    txid: string
    index: number
  }
  index?: number
}

interface TxParams {
  inputs: TxInput[]
  outputs: TxInOutBase[]
  redeemScript: Buffer
  wrappedWitnessScript: Buffer
  witnessScript: Buffer
  leafScript: Buffer
  taprootInternalKey: Buffer
  p2ms: {
    publicKeys: Buffer[]
    privateKeys: Buffer[]
    sighashFlags: number[]
  }
  p2sh: {
    publicKeys: Buffer[]
    privateKeys: Buffer[]
    sighashFlags: number[]
  }
  p2wsh: {
    publicKeys: Buffer[]
    privateKey: Buffer
    sighashFlag: number
  }
}

export const getTxParams = (wallet: BIP32Interface): TxParams => {
  const inputWallet = wallet.deriveHardened(0)
  const outputWallet = wallet.deriveHardened(1)

  // white paper hash
  const taprootInternalKey = hexToBuffer(
    'b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553',
  )

  const p2ms: TxParams['p2ms'] = {
    publicKeys: [
      inputWallet.derive(2).derive(0).publicKey,
      inputWallet.derive(2).derive(1).publicKey,
      // genesis block key
      hexToBuffer(
        '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f',
      ),
    ],
    privateKeys: [
      inputWallet.derive(2).derive(0).privateKey!,
      inputWallet.derive(2).derive(1).privateKey!,
    ],
    sighashFlags: [
      bitcoin.Transaction.SIGHASH_SINGLE,
      bitcoin.Transaction.SIGHASH_ALL |
        bitcoin.Transaction.SIGHASH_ANYONECANPAY,
    ],
  }

  const p2sh: TxParams['p2sh'] = {
    publicKeys: [
      inputWallet.derive(3).derive(0).publicKey,
      inputWallet.derive(3).derive(1).publicKey,
      inputWallet.derive(3).derive(2).publicKey,
      // block 9 key
      hexToBuffer(
        '0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3',
      ),
      // Hal Finney first tx key
      hexToBuffer(
        '04ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c',
      ),
    ],
    privateKeys: [
      inputWallet.derive(3).derive(0).privateKey!,
      inputWallet.derive(3).derive(1).privateKey!,
      inputWallet.derive(3).derive(2).privateKey!,
    ],
    sighashFlags: [
      bitcoin.Transaction.SIGHASH_ALL,
      bitcoin.Transaction.SIGHASH_NONE |
        bitcoin.Transaction.SIGHASH_ANYONECANPAY,
      bitcoin.Transaction.SIGHASH_SINGLE |
        bitcoin.Transaction.SIGHASH_ANYONECANPAY,
    ],
  }

  const p2wsh: TxParams['p2wsh'] = {
    publicKeys: [
      inputWallet.derive(7).derive(0).publicKey,
      inputWallet.derive(7).derive(1).publicKey,
    ],
    privateKey: inputWallet.derive(7).derive(0).privateKey!,
    sighashFlag: bitcoin.Transaction.SIGHASH_NONE,
  }

  const redeemScript = getMultisigScript(
    p2sh.publicKeys,
    p2sh.privateKeys.length,
  )
  const wrappedWitnessScript = getHTLCScript(
    inputWallet.derive(5).derive(0).publicKey,
    [
      inputWallet.derive(5).derive(1).publicKey,
      inputWallet.derive(5).derive(2).publicKey,
    ],
    // pubkey hash of value overflow attacker
    hexToBuffer('46c3747322b220fdb925c9802f0e949c1feab999'),
  )
  const witnessScript = getLNCommitScript(p2wsh.publicKeys)
  const tapscriptPublicKeys = [
    // keys from 37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8
    hexToBuffer(
      '5f4237bd7dae576b34abc8a9c6fa4f0e4787c04234ca963e9e96c8f9b67b56d1',
    ),
    hexToBuffer(
      '5f4237bd7f93c69403a30c6b641f27ccf5201090152fcf1596474221307831c3',
    ),
    ...Array.from({ length: 5 }).map((_, index) =>
      inputWallet
        .derive(9)
        .derive(index + 2)
        .publicKey.slice(1),
    ),
  ]
  const leafScript = getMultisigTapscript(tapscriptPublicKeys, 5)

  return {
    redeemScript,
    wrappedWitnessScript,
    witnessScript,
    leafScript,
    taprootInternalKey,
    p2ms,
    p2sh,
    p2wsh,
    inputs: [
      {
        scriptPubKey: getP2PKOutput(inputWallet.derive(0), false),
        amount: 6102,
        nSequence: 20090103,
        external: {
          txid: 'd46a24962c1d7bd6e87d80570c6a53413eaf30d7fde7f52347f13645ae53969b',
          index: 0,
        },
      },
      {
        scriptPubKey: getP2PKHOutput(inputWallet.derive(1)),
        amount: 1913,
        nSequence: 20081031,
        index: 0,
      },
      {
        scriptPubKey: getMultisigScript(
          p2ms.publicKeys,
          p2ms.privateKeys.length,
        ),
        amount: 1971,
        nSequence: 19750504,
        index: 1,
      },
      {
        scriptPubKey: getP2SHOutput(redeemScript),
        amount: 2140,
        nSequence: 16,
      },
      {
        scriptPubKey: getWrappedP2WPKHOutput(inputWallet.derive(4).publicKey),
        amount: 5139,
        nSequence: 141,
        index: 2,
      },
      {
        scriptPubKey: getWrappedP2WSHOutput(wrappedWitnessScript),
        amount: 3220,
        nSequence: 0xdeadbeef,
        index: 3,
      },
      {
        scriptPubKey: getP2WPKHOutput(inputWallet.derive(6)),
        amount: 17144,
        nSequence: 21000000,
        index: 4,
      },
      {
        scriptPubKey: getP2WSHOutput(witnessScript),
        amount: 8149,
        nSequence: 0xf9beb4d9,
      },
      {
        scriptPubKey: hexToBuffer(
          '512071212ded0ff4c9b1b0c505d8012772e2dbe98a3cae7168377b950fb6b866a849',
        ),
        amount: 9001,
        nSequence: 341,
        external: {
          txid: '0020db02df125062ebae5bacd189ebff22577b2817c1872be79a0d3ba3982c41',
          index: 0,
        },
      },
      {
        scriptPubKey: getP2TRScriptPathOutput(
          leafScript,
          taprootInternalKey,
          famousTxids,
        ),
        amount: 19953,
        nSequence: 342,
        external: {
          txid: '795741ecf9c431b14b1c8d2dd017d3978fd4f6452e91edf416f31ef9971206b4',
          index: 0,
        },
      },
    ],
    outputs: [
      {
        scriptPubKey: getP2PKOutput(outputWallet.derive(0), true),
        amount: 576,
      },
      {
        scriptPubKey: getP2PKHOutput(outputWallet.derive(1)),
        amount: 546,
      },
      {
        scriptPubKey: getP2MSOutput(outputWallet.derive(2), 1, 1),
        amount: 582,
      },
      {
        scriptPubKey: getWrappedP2WPKHOutput(outputWallet.derive(3).publicKey),
        amount: 540,
      },
      {
        scriptPubKey: getP2WPKHOutput(outputWallet.derive(4)),
        amount: 294,
      },
      {
        scriptPubKey: getP2WSHOutput(
          getPubKeyScript(outputWallet.derive(5).publicKey),
        ),
        amount: 330,
      },
      {
        scriptPubKey: getP2TRKeyPathOutput(outputWallet.derive(6)),
        amount: 330,
      },
      {
        scriptPubKey: hexToBuffer('51024e73'),
        amount: 240,
      },
      {
        scriptPubKey: getOpReturnOutput([
          'Not your inputs, not your outputs.',
          hexToBuffer(''),
          hexToBuffer('01'),
          hexToBuffer('02'),
          hexToBuffer('03'),
          hexToBuffer('04'),
          hexToBuffer('05'),
          hexToBuffer('06'),
          hexToBuffer('07'),
          hexToBuffer('08'),
          hexToBuffer('09'),
          hexToBuffer('0a'),
          hexToBuffer('0b'),
          hexToBuffer('0c'),
          hexToBuffer('0d'),
          hexToBuffer('0e'),
          hexToBuffer('0f'),
          hexToBuffer('10'),
        ]),
        amount: 0,
      },
    ],
  }
}

export const famousTxids: Buffer[] = [
  '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
  'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16',
  '6f7cf9580f1c2dfb3c4d5d043cdbb128c640e3f20161245aa7372e9666168516',
  'a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d',
  'd5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599',
  'e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468',
  '29a3efd3ef04f9153d47a990bd7b048a4b2d213daaa5fb8ed670fb85f13bdbcf',
  '54e48e5f5c656b26c3bca14a8c95aa583d07ebe84dde3b7dd4a78f4e4186e713',
  'd29c9c0e8e4d2a9790922af73f0b8d51f0bd4bb19940d9cf910ead8fbe85bc9b',
  'bb41a757f405890fb0f5856228e23b715702d714d59bf2b1feb70d8b2b4e3e08',
  '9fdbcf0ef9d8d00f66e47917f67cc5d78aec1ac786e2abb8d2facb4e4790aad6',
  'cc455ae816e6cdafdb58d54e35d4f46d860047458eacf1c7405dc634631c570d',
  '8d31992805518fd62daa3bdd2a5c4fd2cd3054c9b3dca1d78055e9528cff6adc',
  '8f907925d2ebe48765103e6845c06f1f2bb77c6adc1cc002865865eb5cfd5c1c',
  'b10c007c60e14f9d087e0291d4d0c7869697c6681d979c6639dbd960792b4d41',
  '33e794d097969002ee05d336686fc03c9e15a597c1b9827669460fac98799036',
  '37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8',
  'fd456524104a6674693c29946543f8a0befccce5a352bda55ec8559fc630f5f3',
  '7393096d97bfee8660f4100ffd61874d62f9a65de9fb6acf740c4c386990ef73',
  '73be398c4bdc43709db7398106609eea2a7841aaf3a4fa2000dc18184faa2a7e',
  'b5a2af5845a8d3796308ff9840e567b14cf6bb158ff26c999e6f9a1f5448f9aa',
].map(hexToBuffer)

export const grinding = {
  signatures: {
    p2pkh: 70,
    p2ms1: 69,
    p2ms2: 59,
    p2sh1: 68,
    p2sh2: 58,
    p2sh3: 57,
    wrappedP2wpkh: 67,
    wrappedP2wsh: 66,
    p2wpkh: 65,
    p2wsh: 64,
  },
  offsets: {
    // p2sh2: 0,
    // p2wsh: 0,
    // p2sh3: 0,
    // p2ms2AndP2wpkh: 0,
    // p2ms1: 0,
    // p2pk: 0,

    // Actual offsets for b10c0000004da5a9d1d9b4ae32e09f0b3e62d21a5cce5428d4ad714fb444eb5d:
    p2sh2: 7762,
    p2wsh: 5688334,
    p2sh3: 29725118,
    p2ms2AndP2wpkh: 8805573,
    p2ms1: 35331,
    p2pk: 1677920702514,
  },
}
