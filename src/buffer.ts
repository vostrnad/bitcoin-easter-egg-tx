export const hexToBuffer = (hex: string): Buffer => Buffer.from(hex, 'hex')

export const bufferToHex = (buffer: Buffer): string => buffer.toString('hex')

export const bufferConcat = (list: Array<Uint8Array | number>): Buffer => {
  return Buffer.concat(
    list.map((value) => {
      if (typeof value === 'number') {
        value = Buffer.from([value])
      }
      return value
    }),
  )
}

export const compactSize = (size: number): Buffer => {
  let buffer: Buffer

  if (size <= 0xfc) {
    buffer = Buffer.from([size])
  } else if (size <= 0xffff) {
    buffer = Buffer.alloc(5)
    buffer[0] = 0xfd
    buffer.writeUInt16LE(size, 1)
  } else if (size <= 0xffffffff) {
    buffer = Buffer.alloc(9)
    buffer[0] = 0xfe
    buffer.writeUInt32LE(size, 1)
  } else {
    throw new Error('Compact size too large')
  }

  return buffer
}
