/**
 * Verified State Backend.
 *
 * Implements spec sections 7.2, 8, and 9:
 *  - Fetches account/storage proofs from oblivious_node via eth_getProof
 *  - Verifies proofs locally against a trusted stateRoot
 *  - Caches verified results keyed by (stateRoot, address) / (stateRoot, address, slot)
 *  - Verifies code bytes against codeHash from verified account proof
 *  - Supports SLOAD batching within a microtask (spec section 9.2)
 */

import { keccak_256 } from "@noble/hashes/sha3";
import { hexToBytes, bytesToHex, normalizeAddress, normalizeSlotKey } from "./hex";
import { verifyAccountProof, verifyStorageProof } from "./mpt";
import { fetchProof, fetchCode } from "./rpc-client";
import type { VerifiedAccount, EthGetProofResponse } from "./types";
import { EMPTY_CODE_HASH } from "./types";

interface PendingSlotRequest {
  slotKey: string;
  resolve: (value: bigint) => void;
  reject: (error: Error) => void;
}

export class VerifiedStateBackend {
  private stateRoot: Uint8Array;
  private blockNumber: bigint;
  private proofServerUrl: string;
  private codeSourceUrl: string;

  // Caches keyed by normalized address
  private accountCache = new Map<string, VerifiedAccount>();
  // Cache keyed by "address:slotKey"
  private storageCache = new Map<string, bigint>();
  // Cache keyed by codeHash hex
  private codeCache = new Map<string, Uint8Array>();

  // Batching: pending SLOAD requests per address
  private pendingSlots = new Map<string, PendingSlotRequest[]>();
  private batchTimerSet = new Set<string>();

  constructor(
    stateRoot: Uint8Array,
    blockNumber: bigint,
    proofServerUrl: string,
    codeSourceUrl: string
  ) {
    this.stateRoot = stateRoot;
    this.blockNumber = blockNumber;
    this.proofServerUrl = proofServerUrl;
    this.codeSourceUrl = codeSourceUrl;
  }

  /**
   * Get verified account data (spec: get_account_basic).
   * On cache miss: fetches eth_getProof(address, [], blockNumber) and verifies.
   */
  async getAccountBasic(address: string): Promise<VerifiedAccount> {
    const addr = normalizeAddress(address);
    const cached = this.accountCache.get(addr);
    if (cached) return cached;

    const proof = await fetchProof(
      this.proofServerUrl,
      addr,
      [],
      this.blockNumber
    );

    const verified = this.verifyAndCacheAccount(addr, proof);
    return verified;
  }

  /**
   * Get verified storage value (spec: get_storage).
   * On miss: fetches eth_getProof(address, [slotKey], blockNumber) and verifies.
   * Uses microtask batching for multiple slots on the same address.
   */
  async getStorage(address: string, slotKey: string): Promise<bigint> {
    const addr = normalizeAddress(address);
    const slot = normalizeSlotKey(slotKey);
    const cacheKey = `${addr}:${slot}`;

    const cached = this.storageCache.get(cacheKey);
    if (cached !== undefined) return cached;

    // Use batching: queue the request and flush on next microtask
    return new Promise<bigint>((resolve, reject) => {
      if (!this.pendingSlots.has(addr)) {
        this.pendingSlots.set(addr, []);
      }
      this.pendingSlots.get(addr)!.push({ slotKey: slot, resolve, reject });

      if (!this.batchTimerSet.has(addr)) {
        this.batchTimerSet.add(addr);
        // Flush on next microtask (spec section 9.2)
        queueMicrotask(() => this.flushPendingSlots(addr));
      }
    });
  }

  /**
   * Get verified code bytes (spec: get_code).
   * Ensures account is verified first (to know codeHash), then fetches and verifies code.
   */
  async getCode(address: string): Promise<Uint8Array> {
    const account = await this.getAccountBasic(address);

    const codeHashHex = bytesToHex(account.codeHash);

    // EOA / no code
    if (codeHashHex === EMPTY_CODE_HASH) {
      return new Uint8Array(0);
    }

    // Check code cache
    const cached = this.codeCache.get(codeHashHex);
    if (cached) return cached;

    // Fetch code from code source
    const codeHex = await fetchCode(
      this.codeSourceUrl,
      normalizeAddress(address),
      this.blockNumber
    );

    const codeBytes = hexToBytes(codeHex);

    // Verify: keccak256(code) == codeHash (spec section 5.4)
    const computedHash = keccak_256(codeBytes);
    if (bytesToHex(computedHash) !== codeHashHex) {
      throw new Error(
        `Code verification failed for ${address}: ` +
        `expected codeHash ${codeHashHex}, got ${bytesToHex(computedHash)}`
      );
    }

    this.codeCache.set(codeHashHex, codeBytes);
    account.code = codeBytes;
    return codeBytes;
  }

  /** Flush all pending SLOAD requests for an address into one eth_getProof call. */
  private async flushPendingSlots(address: string): Promise<void> {
    this.batchTimerSet.delete(address);
    const pending = this.pendingSlots.get(address);
    this.pendingSlots.delete(address);

    if (!pending || pending.length === 0) return;

    // Deduplicate slots
    const slotMap = new Map<string, PendingSlotRequest[]>();
    for (const req of pending) {
      if (!slotMap.has(req.slotKey)) {
        slotMap.set(req.slotKey, []);
      }
      slotMap.get(req.slotKey)!.push(req);
    }

    const uniqueSlots = [...slotMap.keys()];

    // Check cache for already-resolved slots
    const uncachedSlots: string[] = [];
    for (const slot of uniqueSlots) {
      const cacheKey = `${address}:${slot}`;
      const cached = this.storageCache.get(cacheKey);
      if (cached !== undefined) {
        for (const req of slotMap.get(slot)!) {
          req.resolve(cached);
        }
      } else {
        uncachedSlots.push(slot);
      }
    }

    if (uncachedSlots.length === 0) return;

    try {
      // Single batched eth_getProof call (spec section 9.2)
      const proof = await fetchProof(
        this.proofServerUrl,
        address,
        uncachedSlots,
        this.blockNumber
      );

      // Verify and cache account if not already cached
      if (!this.accountCache.has(address)) {
        this.verifyAndCacheAccount(address, proof);
      }

      const account = this.accountCache.get(address)!;

      // Verify each storage proof
      for (const sp of proof.storageProof) {
        const slot = normalizeSlotKey(sp.key);
        const slotKeyBytes = hexToBytes(slot);

        const verified = verifyStorageProof(
          account.storageRoot,
          slotKeyBytes,
          sp.proof
        );

        const cacheKey = `${address}:${slot}`;
        this.storageCache.set(cacheKey, verified.value);

        // Resolve waiting requests
        const reqs = slotMap.get(slot);
        if (reqs) {
          for (const req of reqs) {
            req.resolve(verified.value);
          }
        }
      }

      // Any slots requested but not in response → non-existence (value = 0)
      for (const slot of uncachedSlots) {
        const cacheKey = `${address}:${slot}`;
        if (!this.storageCache.has(cacheKey)) {
          this.storageCache.set(cacheKey, 0n);
          const reqs = slotMap.get(slot);
          if (reqs) {
            for (const req of reqs) {
              req.resolve(0n);
            }
          }
        }
      }
    } catch (error) {
      // Reject all pending requests
      for (const slot of uncachedSlots) {
        const reqs = slotMap.get(slot);
        if (reqs) {
          for (const req of reqs) {
            req.reject(error instanceof Error ? error : new Error(String(error)));
          }
        }
      }
    }
  }

  /** Verify an eth_getProof response and cache the account. */
  private verifyAndCacheAccount(
    address: string,
    proof: EthGetProofResponse
  ): VerifiedAccount {
    const addrBytes = hexToBytes(address);

    // Verify account proof against trusted stateRoot (spec section 5.2)
    const result = verifyAccountProof(
      this.stateRoot,
      addrBytes,
      proof.accountProof
    );

    if (!result.exists) {
      // Non-existent account: zero nonce, zero balance, empty storage/code
      const emptyAccount: VerifiedAccount = {
        address,
        nonce: 0n,
        balance: 0n,
        storageRoot: hexToBytes(
          "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        ),
        codeHash: hexToBytes(EMPTY_CODE_HASH),
      };
      this.accountCache.set(address, emptyAccount);
      return emptyAccount;
    }

    // Cross-check: verified values from proof must match response fields (spec section 5.2 step 4)
    const responseBalance = BigInt(proof.balance);
    const responseNonce = BigInt(proof.nonce);
    const responseStorageHash = proof.storageHash.toLowerCase();
    const responseCodeHash = proof.codeHash.toLowerCase();

    if (result.balance !== responseBalance) {
      throw new Error(
        `Account proof balance mismatch for ${address}: ` +
        `proof says ${result.balance}, response says ${responseBalance}`
      );
    }
    if (result.nonce !== responseNonce) {
      throw new Error(
        `Account proof nonce mismatch for ${address}: ` +
        `proof says ${result.nonce}, response says ${responseNonce}`
      );
    }
    if (bytesToHex(result.storageRoot!) !== responseStorageHash) {
      throw new Error(
        `Account proof storageHash mismatch for ${address}: ` +
        `proof says ${bytesToHex(result.storageRoot!)}, response says ${responseStorageHash}`
      );
    }
    if (bytesToHex(result.codeHash!) !== responseCodeHash) {
      throw new Error(
        `Account proof codeHash mismatch for ${address}: ` +
        `proof says ${bytesToHex(result.codeHash!)}, response says ${responseCodeHash}`
      );
    }

    const account: VerifiedAccount = {
      address,
      nonce: result.nonce!,
      balance: result.balance!,
      storageRoot: result.storageRoot!,
      codeHash: result.codeHash!,
    };

    this.accountCache.set(address, account);
    return account;
  }

  /** Clear all caches. */
  clear(): void {
    this.accountCache.clear();
    this.storageCache.clear();
    // Keep code cache — it's keyed by codeHash which is immutable
  }

  /** Get cache statistics for debugging. */
  stats(): { accounts: number; storageSlots: number; codeEntries: number } {
    return {
      accounts: this.accountCache.size,
      storageSlots: this.storageCache.size,
      codeEntries: this.codeCache.size,
    };
  }
}
