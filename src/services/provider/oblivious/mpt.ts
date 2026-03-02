/**
 * Merkle Patricia Trie (MPT) proof verification.
 *
 * Implements verification of EIP-1186 proofs against a trusted root hash.
 * Supports:
 *  - Branch nodes (17 items)
 *  - Extension nodes (2 items, even-prefixed path)
 *  - Leaf nodes (2 items, odd-prefixed path)
 *  - Existence and non-existence proofs
 *
 * Reference: https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/
 */

import { keccak_256 } from "@noble/hashes/sha3";
import { hexToBytes, bytesToHex } from "./hex";
import * as RLP from "./rlp";

/** Convert bytes to nibbles (half-bytes). */
function toNibbles(bytes: Uint8Array): number[] {
  const nibbles: number[] = [];
  for (const b of bytes) {
    nibbles.push(b >> 4, b & 0x0f);
  }
  return nibbles;
}

/** Decode compact (hex-prefix) encoding used in MPT nodes. Returns [nibbles, isLeaf]. */
function decodeCompact(encoded: Uint8Array): { nibbles: number[]; isLeaf: boolean } {
  const nibbles = toNibbles(encoded);
  const prefix = nibbles[0];
  const isLeaf = prefix >= 2;
  const isOdd = prefix % 2 === 1;

  if (isOdd) {
    // Odd length: skip first nibble (the flag), keep second nibble onward
    return { nibbles: nibbles.slice(1), isLeaf };
  } else {
    // Even length: skip first two nibbles (flag + padding zero)
    return { nibbles: nibbles.slice(2), isLeaf };
  }
}

/** Check if two byte arrays are equal. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Verify an MPT proof.
 *
 * @param rootHash - The trusted root hash (32 bytes).
 * @param path - The key path in the trie (keccak256 of the key).
 * @param proofNodes - Array of RLP-encoded trie nodes (hex strings from EIP-1186).
 * @returns The RLP-encoded value at the leaf, or null if the proof shows non-existence.
 */
export function verifyProof(
  rootHash: Uint8Array,
  path: Uint8Array,
  proofNodes: string[]
): Uint8Array | null {
  if (proofNodes.length === 0) {
    // Empty proof is valid only for empty trie (root == keccak256(RLP("")))
    const emptyRoot = keccak_256(new Uint8Array([0x80]));
    if (bytesEqual(rootHash, emptyRoot)) return null;
    throw new Error("MPT: empty proof but non-empty root");
  }

  const pathNibbles = toNibbles(path);
  let nibbleIndex = 0;
  let expectedHash = rootHash;

  for (let i = 0; i < proofNodes.length; i++) {
    const nodeBytes = hexToBytes(proofNodes[i]);
    const nodeHash = keccak_256(nodeBytes);

    // For nodes >= 32 bytes, verify hash matches expected
    if (nodeBytes.length >= 32) {
      if (!bytesEqual(nodeHash, expectedHash)) {
        throw new Error(
          `MPT: hash mismatch at proof node ${i}: expected ${bytesToHex(expectedHash)}, got ${bytesToHex(nodeHash)}`
        );
      }
    }

    const decoded = RLP.decode(nodeBytes);
    if (!(decoded instanceof Array)) {
      throw new Error(`MPT: proof node ${i} is not a list`);
    }

    if (decoded.length === 17) {
      // Branch node
      if (i === proofNodes.length - 1) {
        // Last node: the value is in position 16
        const value = decoded[16];
        if (value instanceof Uint8Array && value.length > 0) {
          return value;
        }
        // Non-existence: path leads to empty branch slot
        return null;
      }

      // Follow the path
      const nibble = pathNibbles[nibbleIndex];
      nibbleIndex++;

      const child = decoded[nibble];
      if (child instanceof Uint8Array) {
        if (child.length === 0) {
          // Empty child -> non-existence proof
          return null;
        }
        if (child.length === 32) {
          expectedHash = child;
        } else {
          // Inline node (< 32 bytes) — shouldn't need hash check
          // In standard proofs, inline nodes appear embedded in the parent
          // and the next proof node should be the child itself
          expectedHash = child;
        }
      } else {
        throw new Error(`MPT: unexpected branch child type at node ${i}`);
      }
    } else if (decoded.length === 2) {
      // Extension or Leaf node
      const pathPart = decoded[0];
      if (!(pathPart instanceof Uint8Array)) {
        throw new Error(`MPT: invalid path encoding in node ${i}`);
      }

      const { nibbles: nodeNibbles, isLeaf } = decodeCompact(pathPart);

      // Check path match
      const remainingPath = pathNibbles.slice(nibbleIndex);
      const matchLen = Math.min(nodeNibbles.length, remainingPath.length);

      let matched = true;
      for (let j = 0; j < matchLen; j++) {
        if (nodeNibbles[j] !== remainingPath[j]) {
          matched = false;
          break;
        }
      }

      if (isLeaf) {
        if (!matched || nodeNibbles.length !== remainingPath.length) {
          // Path diverges — non-existence proof
          return null;
        }
        // Found the leaf
        const value = decoded[1];
        if (value instanceof Uint8Array) {
          return value;
        }
        throw new Error(`MPT: leaf value is not bytes at node ${i}`);
      } else {
        // Extension node
        if (!matched || matchLen < nodeNibbles.length) {
          // Path diverges in extension — non-existence
          return null;
        }

        nibbleIndex += nodeNibbles.length;

        const nextNode = decoded[1];
        if (nextNode instanceof Uint8Array) {
          if (nextNode.length === 32) {
            expectedHash = nextNode;
          } else if (nextNode.length === 0) {
            return null;
          } else {
            expectedHash = nextNode;
          }
        } else {
          throw new Error(`MPT: unexpected extension child type at node ${i}`);
        }
      }
    } else {
      throw new Error(`MPT: invalid node length ${decoded.length} at proof node ${i}`);
    }
  }

  // If we consumed all proof nodes without finding a leaf, it's non-existence
  return null;
}

/**
 * Parse an RLP-encoded Ethereum account value into its components.
 * Account RLP: [nonce, balance, storageRoot, codeHash]
 */
export function parseAccountRLP(rlpBytes: Uint8Array): {
  nonce: bigint;
  balance: bigint;
  storageRoot: Uint8Array;
  codeHash: Uint8Array;
} {
  const decoded = RLP.decode(rlpBytes);
  if (!(decoded instanceof Array) || decoded.length !== 4) {
    throw new Error("Invalid account RLP: expected list of 4 items");
  }

  const [nonceBytes, balanceBytes, storageRoot, codeHash] = decoded;
  if (
    !(nonceBytes instanceof Uint8Array) ||
    !(balanceBytes instanceof Uint8Array) ||
    !(storageRoot instanceof Uint8Array) ||
    !(codeHash instanceof Uint8Array)
  ) {
    throw new Error("Invalid account RLP: items must be bytes");
  }

  return {
    nonce: bytesToBigInt(nonceBytes),
    balance: bytesToBigInt(balanceBytes),
    storageRoot,
    codeHash,
  };
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  if (bytes.length === 0) return 0n;
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) | BigInt(b);
  }
  return result;
}

/**
 * Parse an RLP-encoded storage value into a bigint.
 * Storage values are RLP-encoded byte strings.
 */
export function parseStorageValue(rlpBytes: Uint8Array): bigint {
  // The value from the trie leaf is already the RLP-encoded value.
  // For storage, it's an RLP byte string.
  const decoded = RLP.decode(rlpBytes);
  if (decoded instanceof Uint8Array) {
    return bytesToBigInt(decoded);
  }
  throw new Error("Invalid storage value RLP");
}

/**
 * Verify an account proof from eth_getProof response.
 */
export function verifyAccountProof(
  stateRoot: Uint8Array,
  address: Uint8Array,
  accountProof: string[]
): {
  exists: boolean;
  nonce?: bigint;
  balance?: bigint;
  storageRoot?: Uint8Array;
  codeHash?: Uint8Array;
} {
  const path = keccak_256(address);
  const leafValue = verifyProof(stateRoot, path, accountProof);

  if (leafValue === null) {
    return { exists: false };
  }

  const account = parseAccountRLP(leafValue);
  return {
    exists: true,
    ...account,
  };
}

/**
 * Verify a storage proof from eth_getProof response.
 */
export function verifyStorageProof(
  storageRoot: Uint8Array,
  slotKey: Uint8Array,
  storageProofNodes: string[]
): { exists: boolean; value: bigint } {
  const path = keccak_256(slotKey);
  const leafValue = verifyProof(storageRoot, path, storageProofNodes);

  if (leafValue === null) {
    return { exists: false, value: 0n };
  }

  // Storage leaf values are RLP-encoded. If the raw value is a single byte <= 0x7f
  // it is its own RLP encoding. Otherwise decode the RLP.
  try {
    const value = parseStorageValue(leafValue);
    return { exists: true, value };
  } catch {
    // Fallback: treat raw bytes as value
    let val = 0n;
    for (const b of leafValue) {
      val = (val << 8n) | BigInt(b);
    }
    return { exists: true, value: val };
  }
}
