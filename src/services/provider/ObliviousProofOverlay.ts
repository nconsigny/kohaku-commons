/**
 * ObliviousProofOverlay — Composable privacy layer for Kohaku wallet providers.
 *
 * Helios/Colibri provide INTEGRITY (trusted stateRoot via consensus verification).
 * oblivious_node provides PRIVACY (server can't learn what you're querying).
 * Local EVM provides VERIFIED EXECUTION (correct results without trusting anyone).
 *
 * These are NOT alternatives — they're layers in the same stack:
 *
 *   ┌───────────────────────────────────────────────────────┐
 *   │  ObliviousProofOverlay                                │
 *   │    • Gets trusted header from inner provider          │
 *   │    • Fetches proofs from oblivious_node (PRIVATE)     │
 *   │    • Verifies proofs against trusted stateRoot        │
 *   │    • Executes EVM locally on verified state           │
 *   ├───────────────────────────────────────────────────────┤
 *   │  Inner provider (Helios | Colibri | JsonRpc)          │
 *   │    • Provides trusted headers (INTEGRITY)             │
 *   │    • Serves eth_getCode (code bytes)                  │
 *   │    • Handles all non-verifiable methods                │
 *   └───────────────────────────────────────────────────────┘
 */

import { JsonRpcProvider, Network } from 'ethers'

import { VerifiedStateBackend } from './oblivious/verified-state'
import { executeCall } from './oblivious/evm'
import { hexToBytes, bytesToHex, bigIntToHex } from './oblivious/hex'
import { fetchProof } from './oblivious/rpc-client'
import { verifyAccountProof, verifyStorageProof } from './oblivious/mpt'
import { EMPTY_CODE_HASH } from './oblivious/types'
import type { TrustedHeader, CallParams } from './oblivious/types'

const PRIVACY_ROUTED_METHODS = new Set([
  'eth_call',
  'eth_getBalance',
  'eth_getTransactionCount',
  'eth_getStorageAt',
  'eth_getCode',
  'eth_getProof'
])

function shouldBypass(method: string, params: any[] | undefined): boolean {
  if (method === 'eth_call') {
    if (Array.isArray(params) && params.length >= 3 && params[2] && typeof params[2] === 'object') {
      return true
    }
  }
  return false
}

export interface ObliviousOverlayOptions {
  proofServerUrl: string
  failurePolicy?: 'fail-closed' | 'fallback'
}

export class ObliviousProofOverlay extends JsonRpcProvider {
  readonly #inner: JsonRpcProvider
  readonly #proofServerUrl: string
  readonly #failurePolicy: 'fail-closed' | 'fallback'
  readonly #chainId: bigint

  constructor(inner: JsonRpcProvider, chainId: bigint | number, options: ObliviousOverlayOptions) {
    const rpcUrl = (inner as any)?._getConnection?.()?.url ?? 'http://localhost:8545'
    const staticNetwork = Network.from(Number(chainId))
    super(rpcUrl, staticNetwork, { staticNetwork })

    this.#inner = inner
    this.#proofServerUrl = options.proofServerUrl
    this.#failurePolicy = options.failurePolicy ?? 'fail-closed'
    this.#chainId = BigInt(chainId)
  }

  override async send(
    method: string,
    params: Array<any> | Record<string, any> = []
  ): Promise<any> {
    const paramArray = Array.isArray(params) ? params : [params]

    if (!PRIVACY_ROUTED_METHODS.has(method) || shouldBypass(method, paramArray)) {
      return this.#inner.send(method, params)
    }

    try {
      return await this.#handlePrivate(method, paramArray)
    } catch (error) {
      if (this.#failurePolicy === 'fallback') {
        return this.#inner.send(method, params)
      }
      throw error
    }
  }

  override destroy(): void {
    this.#inner.destroy()
    super.destroy()
  }

  async #handlePrivate(method: string, params: any[]): Promise<any> {
    switch (method) {
      case 'eth_call':
        return this.#privateEthCall(params)
      case 'eth_getBalance':
        return this.#privateGetBalance(params)
      case 'eth_getTransactionCount':
        return this.#privateGetTransactionCount(params)
      case 'eth_getStorageAt':
        return this.#privateGetStorageAt(params)
      case 'eth_getCode':
        return this.#privateGetCode(params)
      case 'eth_getProof':
        return this.#privateGetProof(params)
      default:
        return this.#inner.send(method, params)
    }
  }

  async #getTrustedHeader(blockTag: string): Promise<TrustedHeader> {
    const tag = blockTag === 'latest' ? 'latest' : blockTag
    const block = await this.#inner.send('eth_getBlockByNumber', [tag, false])

    return {
      number: BigInt(block.number),
      stateRoot: block.stateRoot,
      timestamp: BigInt(block.timestamp),
      baseFeePerGas: block.baseFeePerGas ? BigInt(block.baseFeePerGas) : 0n,
      gasLimit: BigInt(block.gasLimit),
      coinbase: block.miner,
      prevRandao: block.mixHash ?? block.prevRandao ?? '0x' + '0'.repeat(64),
      chainId: this.#chainId
    }
  }

  async #privateEthCall(params: any[]): Promise<string> {
    const [txObj, blockTag] = params
    const header = await this.#getTrustedHeader(blockTag ?? 'latest')
    const stateRoot = hexToBytes(header.stateRoot)

    const innerUrl = (this.#inner as any)?._getConnection?.()?.url ?? ''

    const state = new VerifiedStateBackend(
      stateRoot,
      header.number,
      this.#proofServerUrl,
      innerUrl
    )

    const callParams: CallParams = {
      from: txObj.from,
      to: txObj.to,
      data: txObj.data ?? txObj.input,
      value: txObj.value,
      gas: txObj.gas ?? txObj.gasLimit
    }

    const result = await executeCall(callParams, header, state)

    if (!result.success) {
      const error = new Error(result.error ?? 'execution reverted')
      ;(error as any).data = bytesToHex(result.returnData)
      ;(error as any).code = 'CALL_EXCEPTION'
      throw error
    }

    return bytesToHex(result.returnData)
  }

  async #privateGetBalance(params: any[]): Promise<string> {
    const [address, blockTag] = params
    const header = await this.#getTrustedHeader(blockTag ?? 'latest')
    const stateRoot = hexToBytes(header.stateRoot)

    const proof = await fetchProof(this.#proofServerUrl, address, [], header.number)
    const result = verifyAccountProof(stateRoot, hexToBytes(address), proof.accountProof)

    if (!result.exists) return '0x0'
    return bigIntToHex(result.balance!)
  }

  async #privateGetTransactionCount(params: any[]): Promise<string> {
    const [address, blockTag] = params
    const header = await this.#getTrustedHeader(blockTag ?? 'latest')
    const stateRoot = hexToBytes(header.stateRoot)

    const proof = await fetchProof(this.#proofServerUrl, address, [], header.number)
    const result = verifyAccountProof(stateRoot, hexToBytes(address), proof.accountProof)

    if (!result.exists) return '0x0'
    return bigIntToHex(result.nonce!)
  }

  async #privateGetStorageAt(params: any[]): Promise<string> {
    const [address, slot, blockTag] = params
    const header = await this.#getTrustedHeader(blockTag ?? 'latest')
    const stateRoot = hexToBytes(header.stateRoot)

    const proof = await fetchProof(this.#proofServerUrl, address, [slot], header.number)
    const accountResult = verifyAccountProof(stateRoot, hexToBytes(address), proof.accountProof)

    if (!accountResult.exists || proof.storageProof.length === 0) {
      return '0x' + '0'.repeat(64)
    }

    const sp = proof.storageProof[0]
    const storageResult = verifyStorageProof(accountResult.storageRoot!, hexToBytes(slot), sp.proof)
    return '0x' + storageResult.value.toString(16).padStart(64, '0')
  }

  async #privateGetCode(params: any[]): Promise<string> {
    const [address, blockTag] = params
    const header = await this.#getTrustedHeader(blockTag ?? 'latest')
    const stateRoot = hexToBytes(header.stateRoot)

    const proof = await fetchProof(this.#proofServerUrl, address, [], header.number)
    const accountResult = verifyAccountProof(stateRoot, hexToBytes(address), proof.accountProof)

    if (!accountResult.exists) return '0x'
    if (bytesToHex(accountResult.codeHash!) === EMPTY_CODE_HASH) return '0x'

    const code: string = await this.#inner.send('eth_getCode', [address, blockTag ?? 'latest'])
    const codeBytes = hexToBytes(code)

    const { keccak_256 } = await import('@noble/hashes/sha3')
    const computedHash = bytesToHex(keccak_256(codeBytes))

    if (computedHash !== bytesToHex(accountResult.codeHash!)) {
      throw new Error(
        `Code verification failed for ${address}: ` +
          `expected ${bytesToHex(accountResult.codeHash!)}, got ${computedHash}`
      )
    }

    return code
  }

  async #privateGetProof(params: any[]): Promise<any> {
    const [address, storageKeys, blockTag] = params
    const header = await this.#getTrustedHeader(blockTag ?? 'latest')
    const stateRoot = hexToBytes(header.stateRoot)

    const proof = await fetchProof(
      this.#proofServerUrl,
      address,
      storageKeys ?? [],
      header.number
    )

    verifyAccountProof(stateRoot, hexToBytes(address), proof.accountProof)

    return proof
  }
}

export function wrapWithOblivious(
  inner: JsonRpcProvider,
  chainId: bigint | number,
  options: ObliviousOverlayOptions
): ObliviousProofOverlay {
  return new ObliviousProofOverlay(inner, chainId, options)
}

export function isObliviousSupportedChain(chainId?: bigint | number): boolean {
  if (!chainId) return false
  const supported = [1, 11155111] // mainnet + sepolia
  return supported.includes(Number(chainId))
}
