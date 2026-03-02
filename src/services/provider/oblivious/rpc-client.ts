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
 * Fetch an EIP-1186 proof from the proof server.
 *
 * Per spec section 4.2: uses explicit blockNumber (not "latest") to prevent
 * header/proof mismatch races.
 *
 * Block number format:
 *  - oblivious_node expects a plain u64 integer
 *  - standard geth/erigon expects a hex string ("0x...")
 *
 * The function tries the oblivious_node format first (integer). If the server
 * rejects it (e.g., standard geth), it retries with hex string format.
 */
let _useHexBlockNumber = false;

export async function fetchProof(
  url: string,
  address: string,
  storageKeys: string[],
  blockNumber: bigint
): Promise<EthGetProofResponse> {
  const normalizedKeys = storageKeys.map(normalizeSlotKey);
  const blockParam = _useHexBlockNumber
    ? "0x" + blockNumber.toString(16)
    : Number(blockNumber);

  try {
    return await jsonRpcCall<EthGetProofResponse>(
      url,
      "eth_getProof",
      [address, normalizedKeys, blockParam]
    );
  } catch (err: any) {
    // If oblivious_node format (integer) fails, switch to hex for this session
    if (!_useHexBlockNumber && err.message?.includes("cannot unmarshal")) {
      _useHexBlockNumber = true;
      const hexBlock = "0x" + blockNumber.toString(16);
      return jsonRpcCall<EthGetProofResponse>(
        url,
        "eth_getProof",
        [address, normalizedKeys, hexBlock]
      );
    }
    throw err;
  }
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
