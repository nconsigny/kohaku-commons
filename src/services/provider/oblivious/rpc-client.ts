/**
 * JSON-RPC transport client for communicating with oblivious_node.
 *
 * Handles:
 *  - HTTP(S) JSON-RPC 2.0 POST requests
 *  - eth_getProof calls with proper parameter formatting
 *  - Request ID management
 *  - Error handling and typed responses
 */

import type {
  JsonRpcRequest,
  JsonRpcResponse,
  EthGetProofResponse,
} from "./types";
import { normalizeSlotKey } from "./hex";

let _nextId = 1;
function nextId(): number {
  return _nextId++;
}

/**
 * Send a JSON-RPC 2.0 request.
 */
export async function jsonRpcCall<T = unknown>(
  url: string,
  method: string,
  params: unknown[]
): Promise<T> {
  const request: JsonRpcRequest = {
    jsonrpc: "2.0",
    method,
    params,
    id: nextId(),
  };

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    throw new Error(`RPC HTTP error: ${response.status} ${response.statusText}`);
  }

  const json: JsonRpcResponse<T> = await response.json();

  if (json.error) {
    const err = new Error(`RPC error ${json.error.code}: ${json.error.message}`);
    (err as any).code = json.error.code;
    (err as any).data = json.error.data;
    throw err;
  }

  if (json.result === undefined) {
    throw new Error("RPC response missing result");
  }

  return json.result;
}

/**
 * Fetch an EIP-1186 proof from the oblivious_node server.
 *
 * Per spec section 4.2: uses explicit blockNumber (not "latest") to prevent
 * header/proof mismatch races.
 *
 * @param url - Proof server URL
 * @param address - 0x-prefixed Ethereum address
 * @param storageKeys - Array of 0x-prefixed 32-byte storage keys
 * @param blockNumber - Explicit block number to query
 */
export async function fetchProof(
  url: string,
  address: string,
  storageKeys: string[],
  blockNumber: bigint
): Promise<EthGetProofResponse> {
  // oblivious_node expects blockNumber as a plain u64, not hex
  // oblivious_node requires storage keys to be exactly 64 hex chars (32 bytes)
  const normalizedKeys = storageKeys.map(normalizeSlotKey);
  const result = await jsonRpcCall<EthGetProofResponse>(
    url,
    "eth_getProof",
    [address, normalizedKeys, Number(blockNumber)]
  );

  return result;
}

/**
 * Fetch code bytes from a fallback RPC via eth_getCode.
 *
 * @param url - RPC URL (can be the proof server if it supports eth_getCode, or a fallback)
 * @param address - 0x-prefixed address
 * @param blockNumber - Block number (hex-encoded for standard RPCs)
 */
export async function fetchCode(
  url: string,
  address: string,
  blockNumber: bigint
): Promise<string> {
  const blockHex = "0x" + blockNumber.toString(16);
  return jsonRpcCall<string>(url, "eth_getCode", [address, blockHex]);
}

/**
 * Pass-through any JSON-RPC method to a fallback provider.
 */
export async function fallbackCall<T = unknown>(
  url: string,
  method: string,
  params: unknown[]
): Promise<T> {
  return jsonRpcCall<T>(url, method, params);
}
