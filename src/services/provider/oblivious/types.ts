/**
 * Core types used throughout the execution client.
 */

/** EIP-1186 eth_getProof response. */
export interface EthGetProofResponse {
  address: string;
  balance: string;
  codeHash: string;
  nonce: string;
  storageHash: string;
  accountProof: string[];
  storageProof: StorageProofEntry[];
}

export interface StorageProofEntry {
  key: string;
  value: string;
  proof: string[];
}

/** Trusted block header — minimum fields required for verified execution. */
export interface TrustedHeader {
  number: bigint;
  stateRoot: string; // 0x-prefixed 32-byte hex
  timestamp: bigint;
  baseFeePerGas: bigint;
  gasLimit: bigint;
  coinbase: string; // 0x-prefixed 20-byte address
  prevRandao: string; // 0x-prefixed 32-byte hex
  chainId: bigint;
}

/** Verified account data extracted from proofs. */
export interface VerifiedAccount {
  address: string;
  nonce: bigint;
  balance: bigint;
  storageRoot: Uint8Array;
  codeHash: Uint8Array;
  code?: Uint8Array;
}

/** Configuration for the execution client. */
export interface ExecutionClientConfig {
  /** URL of the oblivious_node JSON-RPC server. */
  proofServerUrl: string;

  /** Optional fallback RPC for eth_getCode and unsupported methods. */
  fallbackRpcUrl?: string;

  /** Trusted header provider function. Returns trusted header for a given block tag. */
  trustedHeaderProvider?: TrustedHeaderProvider;

  /** Chain ID (default: 1 for mainnet). */
  chainId?: bigint;

  /**
   * Failure policy.
   * "fail-closed" (default): abort on proof failure.
   * "fallback": route to fallback RPC on failure (requires fallbackRpcUrl).
   */
  failurePolicy?: "fail-closed" | "fallback";
}

/** Interface for trusted header providers (e.g., Helios light client). */
export interface TrustedHeaderProvider {
  getHeader(blockTag: string | bigint): Promise<TrustedHeader>;
}

/** EIP-1193 request arguments. */
export interface EIP1193RequestArgs {
  method: string;
  params?: unknown[];
}

/** JSON-RPC request. */
export interface JsonRpcRequest {
  jsonrpc: "2.0";
  method: string;
  params: unknown[];
  id: number;
}

/** JSON-RPC response. */
export interface JsonRpcResponse<T = unknown> {
  jsonrpc: "2.0";
  id: number;
  result?: T;
  error?: { code: number; message: string; data?: unknown };
}

/** eth_call transaction parameters. */
export interface CallParams {
  from?: string;
  to: string;
  data?: string;
  value?: string;
  gas?: string;
  gasPrice?: string;
  maxFeePerGas?: string;
  maxPriorityFeePerGas?: string;
}

/** Empty code hash constant — keccak256 of empty bytes. */
export const EMPTY_CODE_HASH = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfae0187f7ccd04";

/** Empty trie root — keccak256(RLP("")) */
export const EMPTY_TRIE_ROOT = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";
