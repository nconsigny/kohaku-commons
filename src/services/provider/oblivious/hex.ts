/**
 * Hex encoding/decoding utilities.
 */

export function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) throw new Error(`Odd-length hex: ${hex}`);
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(h.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = "0x";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

export function padHex(hex: string, bytes: number): string {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  return "0x" + h.padStart(bytes * 2, "0");
}

export function stripLeadingZeros(hex: string): string {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const stripped = h.replace(/^0+/, "") || "0";
  return "0x" + stripped;
}

/** Convert hex quantity string to bigint. Handles "0x0", "0x2a", etc. */
export function hexToBigInt(hex: string): bigint {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h === "" || h === "0") return 0n;
  return BigInt("0x" + h);
}

export function bigIntToHex(n: bigint): string {
  if (n === 0n) return "0x0";
  return "0x" + n.toString(16);
}

export function hexToNumber(hex: string): number {
  return Number(hexToBigInt(hex));
}

/** Normalize an address to checksumless lowercase 0x-prefixed 40-char form. */
export function normalizeAddress(addr: string): string {
  const h = addr.startsWith("0x") ? addr.slice(2) : addr;
  return "0x" + h.toLowerCase().padStart(40, "0");
}

/** Normalize a 32-byte storage key. */
export function normalizeSlotKey(key: string): string {
  const h = key.startsWith("0x") ? key.slice(2) : key;
  return "0x" + h.toLowerCase().padStart(64, "0");
}
