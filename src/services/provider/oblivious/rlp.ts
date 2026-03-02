/**
 * Minimal RLP (Recursive Length Prefix) decoder.
 * Implements only decoding — sufficient for proof verification.
 * Reference: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
 */

export type RLPItem = Uint8Array | RLPItem[];

export function decode(input: Uint8Array): RLPItem {
  const { item, consumed } = _decode(input, 0);
  if (consumed !== input.length) {
    throw new Error(`RLP: extra bytes after decode (consumed ${consumed} of ${input.length})`);
  }
  return item;
}

function _decode(data: Uint8Array, offset: number): { item: RLPItem; consumed: number } {
  if (offset >= data.length) {
    throw new Error("RLP: unexpected end of data");
  }

  const prefix = data[offset];

  // Single byte [0x00, 0x7f]
  if (prefix <= 0x7f) {
    return { item: data.subarray(offset, offset + 1), consumed: 1 };
  }

  // Short string [0x80, 0xb7]: length = prefix - 0x80
  if (prefix <= 0xb7) {
    const strLen = prefix - 0x80;
    const start = offset + 1;
    const end = start + strLen;
    if (end > data.length) throw new Error("RLP: string exceeds data");
    return { item: data.subarray(start, end), consumed: 1 + strLen };
  }

  // Long string [0xb8, 0xbf]: next (prefix - 0xb7) bytes are the length
  if (prefix <= 0xbf) {
    const lenOfLen = prefix - 0xb7;
    const strLen = readLength(data, offset + 1, lenOfLen);
    const start = offset + 1 + lenOfLen;
    const end = start + strLen;
    if (end > data.length) throw new Error("RLP: long string exceeds data");
    return { item: data.subarray(start, end), consumed: 1 + lenOfLen + strLen };
  }

  // Short list [0xc0, 0xf7]: total payload length = prefix - 0xc0
  if (prefix <= 0xf7) {
    const listLen = prefix - 0xc0;
    return decodeList(data, offset + 1, listLen, 1 + listLen);
  }

  // Long list [0xf8, 0xff]: next (prefix - 0xf7) bytes are the length
  const lenOfLen = prefix - 0xf7;
  const listLen = readLength(data, offset + 1, lenOfLen);
  return decodeList(data, offset + 1 + lenOfLen, listLen, 1 + lenOfLen + listLen);
}

function readLength(data: Uint8Array, offset: number, numBytes: number): number {
  if (offset + numBytes > data.length) throw new Error("RLP: length exceeds data");
  let len = 0;
  for (let i = 0; i < numBytes; i++) {
    len = len * 256 + data[offset + i];
  }
  return len;
}

function decodeList(
  data: Uint8Array,
  payloadStart: number,
  payloadLen: number,
  totalConsumed: number
): { item: RLPItem[]; consumed: number } {
  const items: RLPItem[] = [];
  let pos = payloadStart;
  const end = payloadStart + payloadLen;
  while (pos < end) {
    const { item, consumed } = _decode(data, pos);
    items.push(item);
    pos += consumed;
  }
  if (pos !== end) {
    throw new Error("RLP: list payload length mismatch");
  }
  return { item: items, consumed: totalConsumed };
}

/** Encode a single item (bytes or list) to RLP. Used for hashing nodes during verification. */
export function encode(input: RLPItem): Uint8Array {
  if (input instanceof Uint8Array) {
    return encodeBytes(input);
  }
  // It's a list
  const encodedItems = input.map(encode);
  const totalLen = encodedItems.reduce((s, e) => s + e.length, 0);
  const prefix = encodeLength(totalLen, 0xc0);
  const result = new Uint8Array(prefix.length + totalLen);
  result.set(prefix, 0);
  let offset = prefix.length;
  for (const enc of encodedItems) {
    result.set(enc, offset);
    offset += enc.length;
  }
  return result;
}

function encodeBytes(bytes: Uint8Array): Uint8Array {
  if (bytes.length === 1 && bytes[0] <= 0x7f) {
    return bytes;
  }
  const prefix = encodeLength(bytes.length, 0x80);
  const result = new Uint8Array(prefix.length + bytes.length);
  result.set(prefix, 0);
  result.set(bytes, prefix.length);
  return result;
}

function encodeLength(len: number, offset: number): Uint8Array {
  if (len < 56) {
    return new Uint8Array([offset + len]);
  }
  const hexLen = len.toString(16);
  const lenOfLen = Math.ceil(hexLen.length / 2);
  const firstByte = offset + 55 + lenOfLen;
  const result = new Uint8Array(1 + lenOfLen);
  result[0] = firstByte;
  for (let i = lenOfLen - 1; i >= 0; i--) {
    result[1 + i] = len & 0xff;
    len = Math.floor(len / 256);
  }
  return result;
}
