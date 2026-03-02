/**
 * Local EVM execution engine.
 *
 * This module provides a minimal EVM interpreter for executing eth_call locally
 * using verified state from the VerifiedStateBackend.
 *
 * Architecture:
 *  - Phase 1 uses a portable TypeScript EVM that supports the most critical opcodes
 *    needed for typical eth_call (view functions, balanceOf, etc.)
 *  - The design is pluggable: when revm-wasm becomes available, the EVMEngine
 *    interface can be swapped without changing the provider layer.
 *
 * All state reads (SLOAD, BALANCE, EXTCODESIZE, etc.) go through the
 * VerifiedStateBackend, ensuring every value is backed by a verified proof.
 */

import { keccak_256 } from "@noble/hashes/sha3";
import { hexToBytes, bytesToHex, hexToBigInt } from "./hex";
import type { VerifiedStateBackend } from "./verified-state";
import type { TrustedHeader, CallParams } from "./types";

const MAX_STACK = 1024;
const MAX_CALL_DEPTH = 256;

/** Result of EVM execution. */
export interface EVMResult {
  success: boolean;
  returnData: Uint8Array;
  gasUsed: bigint;
  error?: string;
}

interface EVMContext {
  address: string;        // Current executing contract address
  caller: string;         // msg.sender
  origin: string;         // tx.origin
  callValue: bigint;      // msg.value
  callData: Uint8Array;   // msg.data
  gas: bigint;
  code: Uint8Array;
  header: TrustedHeader;
  state: VerifiedStateBackend;
  depth: number;
  readOnly: boolean;      // STATICCALL context
}

type Stack = bigint[];

/**
 * Execute an eth_call locally using verified state.
 *
 * Implements spec section 8.1 execution flow.
 */
export async function executeCall(
  params: CallParams,
  header: TrustedHeader,
  state: VerifiedStateBackend
): Promise<EVMResult> {
  const from = params.from || "0x0000000000000000000000000000000000000000";
  const to = params.to;
  const value = params.value ? hexToBigInt(params.value) : 0n;
  const data = params.data ? hexToBytes(params.data) : new Uint8Array(0);

  // Gas: use provided or default to block gas limit
  let gas = header.gasLimit;
  if (params.gas) gas = hexToBigInt(params.gas);

  // Fetch code for the target
  const code = await state.getCode(to);

  if (code.length === 0) {
    // EOA or empty contract — return empty
    return { success: true, returnData: new Uint8Array(0), gasUsed: 0n };
  }

  const ctx: EVMContext = {
    address: to,
    caller: from,
    origin: from,
    callValue: value,
    callData: data,
    gas,
    code,
    header,
    state,
    depth: 0,
    readOnly: false,
  };

  return executeContext(ctx);
}

async function executeContext(ctx: EVMContext): Promise<EVMResult> {
  const stack: Stack = [];
  const memory = new EVMMemory();
  let pc = 0;
  let gasUsed = 0n;
  let returnData: Uint8Array = new Uint8Array(0);
  let lastReturnData: Uint8Array = new Uint8Array(0);

  const push = (val: bigint) => {
    if (stack.length >= MAX_STACK) throw new Error("Stack overflow");
    stack.push(val & ((1n << 256n) - 1n));
  };

  const pop = (): bigint => {
    if (stack.length === 0) throw new Error("Stack underflow");
    return stack.pop()!;
  };

  const peek = (n: number): bigint => {
    if (stack.length <= n) throw new Error("Stack underflow");
    return stack[stack.length - 1 - n];
  };

  const useGas = (amount: bigint) => {
    gasUsed += amount;
    if (gasUsed > ctx.gas) throw new Error("Out of gas");
  };

  const u256 = (val: bigint): bigint => val & ((1n << 256n) - 1n);
  const toSigned = (val: bigint): bigint => {
    if (val >= (1n << 255n)) return val - (1n << 256n);
    return val;
  };

  try {
    while (pc < ctx.code.length) {
      const op = ctx.code[pc];
      pc++;

      switch (op) {
        // 0x00: STOP
        case 0x00:
          return { success: true, returnData: new Uint8Array(0), gasUsed };

        // 0x01-0x0b: Arithmetic
        case 0x01: { useGas(3n); const [a, b] = [pop(), pop()]; push(u256(a + b)); break; }
        case 0x02: { useGas(5n); const [a, b] = [pop(), pop()]; push(u256(a * b)); break; }
        case 0x03: { useGas(3n); const [a, b] = [pop(), pop()]; push(u256(a - b)); break; }
        case 0x04: { useGas(5n); const [a, b] = [pop(), pop()]; push(b === 0n ? 0n : u256(a / b)); break; }
        case 0x05: { // SDIV
          useGas(5n);
          const [a, b] = [toSigned(pop()), toSigned(pop())];
          push(b === 0n ? 0n : u256(a / b));
          break;
        }
        case 0x06: { useGas(5n); const [a, b] = [pop(), pop()]; push(b === 0n ? 0n : u256(a % b)); break; }
        case 0x07: { // SMOD
          useGas(5n);
          const [a, b] = [toSigned(pop()), toSigned(pop())];
          push(b === 0n ? 0n : u256(a % b));
          break;
        }
        case 0x08: { // ADDMOD
          useGas(8n);
          const [a, b, N] = [pop(), pop(), pop()];
          push(N === 0n ? 0n : (a + b) % N);
          break;
        }
        case 0x09: { // MULMOD
          useGas(8n);
          const [a, b, N] = [pop(), pop(), pop()];
          push(N === 0n ? 0n : (a * b) % N);
          break;
        }
        case 0x0a: { // EXP
          useGas(10n);
          const [base, exp] = [pop(), pop()];
          let byteLen = 0n;
          let tmp = exp;
          while (tmp > 0n) { byteLen++; tmp >>= 8n; }
          useGas(50n * byteLen);
          push(u256(modPow(base, exp, 1n << 256n)));
          break;
        }
        case 0x0b: { // SIGNEXTEND
          useGas(5n);
          const [b, x] = [pop(), pop()];
          if (b < 31n) {
            const bit = Number(b) * 8 + 7;
            const mask = (1n << BigInt(bit)) - 1n;
            if ((x >> BigInt(bit)) & 1n) {
              push(u256(x | ~mask));
            } else {
              push(x & mask);
            }
          } else {
            push(x);
          }
          break;
        }

        // 0x10-0x1d: Comparison & Bitwise
        case 0x10: { useGas(3n); push(pop() < pop() ? 1n : 0n); break; }
        case 0x11: { useGas(3n); push(pop() > pop() ? 1n : 0n); break; }
        case 0x12: { useGas(3n); push(toSigned(pop()) < toSigned(pop()) ? 1n : 0n); break; }
        case 0x13: { useGas(3n); push(toSigned(pop()) > toSigned(pop()) ? 1n : 0n); break; }
        case 0x14: { useGas(3n); push(pop() === pop() ? 1n : 0n); break; }
        case 0x15: { useGas(3n); push(pop() === 0n ? 1n : 0n); break; }
        case 0x16: { useGas(3n); push(pop() & pop()); break; }
        case 0x17: { useGas(3n); push(pop() | pop()); break; }
        case 0x18: { useGas(3n); push(pop() ^ pop()); break; }
        case 0x19: { useGas(3n); push(u256(~pop())); break; }
        case 0x1a: { // BYTE
          useGas(3n);
          const [i, x] = [pop(), pop()];
          push(i >= 32n ? 0n : (x >> (248n - i * 8n)) & 0xffn);
          break;
        }
        case 0x1b: { useGas(3n); const [shift, val] = [pop(), pop()]; push(shift >= 256n ? 0n : u256(val << shift)); break; }
        case 0x1c: { useGas(3n); const [shift, val] = [pop(), pop()]; push(shift >= 256n ? 0n : val >> shift); break; }
        case 0x1d: { // SAR
          useGas(3n);
          const [shift, val] = [pop(), pop()];
          const signed = toSigned(val);
          if (shift >= 256n) {
            push(signed < 0n ? u256(-1n) : 0n);
          } else {
            push(u256(signed >> shift));
          }
          break;
        }

        // 0x20: KECCAK256
        case 0x20: {
          useGas(30n);
          const [offset, size] = [pop(), pop()];
          const data = memory.read(Number(offset), Number(size));
          useGas(6n * BigInt(Math.ceil(Number(size) / 32)));
          const hash = keccak_256(data);
          push(bytesToBigInt(hash));
          break;
        }

        // 0x30: ADDRESS
        case 0x30: { useGas(2n); push(addressToBigInt(ctx.address)); break; }
        // 0x31: BALANCE — verified state read
        case 0x31: {
          useGas(2600n);
          const addr = bigIntToAddress(pop());
          const account = await ctx.state.getAccountBasic(addr);
          push(account.balance);
          break;
        }
        // 0x32: ORIGIN
        case 0x32: { useGas(2n); push(addressToBigInt(ctx.origin)); break; }
        // 0x33: CALLER
        case 0x33: { useGas(2n); push(addressToBigInt(ctx.caller)); break; }
        // 0x34: CALLVALUE
        case 0x34: { useGas(2n); push(ctx.callValue); break; }
        // 0x35: CALLDATALOAD
        case 0x35: {
          useGas(3n);
          const i = Number(pop());
          let val = 0n;
          for (let j = 0; j < 32; j++) {
            val <<= 8n;
            if (i + j < ctx.callData.length) val |= BigInt(ctx.callData[i + j]);
          }
          push(val);
          break;
        }
        // 0x36: CALLDATASIZE
        case 0x36: { useGas(2n); push(BigInt(ctx.callData.length)); break; }
        // 0x37: CALLDATACOPY
        case 0x37: {
          useGas(3n);
          const [destOffset, offset, size] = [Number(pop()), Number(pop()), Number(pop())];
          useGas(3n * BigInt(Math.ceil(size / 32)));
          const data = new Uint8Array(size);
          for (let i = 0; i < size; i++) {
            data[i] = offset + i < ctx.callData.length ? ctx.callData[offset + i] : 0;
          }
          memory.write(destOffset, data);
          break;
        }
        // 0x38: CODESIZE
        case 0x38: { useGas(2n); push(BigInt(ctx.code.length)); break; }
        // 0x39: CODECOPY
        case 0x39: {
          useGas(3n);
          const [destOffset, offset, size] = [Number(pop()), Number(pop()), Number(pop())];
          useGas(3n * BigInt(Math.ceil(size / 32)));
          const data = new Uint8Array(size);
          for (let i = 0; i < size; i++) {
            data[i] = offset + i < ctx.code.length ? ctx.code[offset + i] : 0;
          }
          memory.write(destOffset, data);
          break;
        }
        // 0x3a: GASPRICE
        case 0x3a: { useGas(2n); push(0n); break; } // eth_call has effective gas price 0
        // 0x3b: EXTCODESIZE — verified state read
        case 0x3b: {
          useGas(2600n);
          const addr = bigIntToAddress(pop());
          const code = await ctx.state.getCode(addr);
          push(BigInt(code.length));
          break;
        }
        // 0x3c: EXTCODECOPY — verified state read
        case 0x3c: {
          useGas(2600n);
          const addr = bigIntToAddress(pop());
          const [destOffset, offset, size] = [Number(pop()), Number(pop()), Number(pop())];
          useGas(3n * BigInt(Math.ceil(size / 32)));
          const code = await ctx.state.getCode(addr);
          const data = new Uint8Array(size);
          for (let i = 0; i < size; i++) {
            data[i] = offset + i < code.length ? code[offset + i] : 0;
          }
          memory.write(destOffset, data);
          break;
        }
        // 0x3d: RETURNDATASIZE
        case 0x3d: { useGas(2n); push(BigInt(lastReturnData.length)); break; }
        // 0x3e: RETURNDATACOPY
        case 0x3e: {
          useGas(3n);
          const [destOffset, offset, size] = [Number(pop()), Number(pop()), Number(pop())];
          if (offset + size > lastReturnData.length) {
            throw new Error("RETURNDATACOPY out of bounds");
          }
          useGas(3n * BigInt(Math.ceil(size / 32)));
          memory.write(destOffset, lastReturnData.subarray(offset, offset + size));
          break;
        }
        // 0x3f: EXTCODEHASH — verified state read
        case 0x3f: {
          useGas(2600n);
          const addr = bigIntToAddress(pop());
          const account = await ctx.state.getAccountBasic(addr);
          push(bytesToBigInt(account.codeHash));
          break;
        }

        // 0x40: BLOCKHASH (returns 0 for simplicity in eth_call)
        case 0x40: { useGas(20n); pop(); push(0n); break; }
        // 0x41: COINBASE
        case 0x41: { useGas(2n); push(addressToBigInt(ctx.header.coinbase)); break; }
        // 0x42: TIMESTAMP
        case 0x42: { useGas(2n); push(ctx.header.timestamp); break; }
        // 0x43: NUMBER
        case 0x43: { useGas(2n); push(ctx.header.number); break; }
        // 0x44: PREVRANDAO (post-merge DIFFICULTY replacement)
        case 0x44: { useGas(2n); push(hexToBigInt(ctx.header.prevRandao)); break; }
        // 0x45: GASLIMIT
        case 0x45: { useGas(2n); push(ctx.header.gasLimit); break; }
        // 0x46: CHAINID
        case 0x46: { useGas(2n); push(ctx.header.chainId); break; }
        // 0x47: SELFBALANCE — verified state read
        case 0x47: {
          useGas(5n);
          const account = await ctx.state.getAccountBasic(ctx.address);
          push(account.balance);
          break;
        }
        // 0x48: BASEFEE
        case 0x48: { useGas(2n); push(ctx.header.baseFeePerGas); break; }

        // 0x50: POP
        case 0x50: { useGas(2n); pop(); break; }
        // 0x51: MLOAD
        case 0x51: {
          useGas(3n);
          const offset = Number(pop());
          push(bytesToBigInt(memory.read(offset, 32)));
          break;
        }
        // 0x52: MSTORE
        case 0x52: {
          useGas(3n);
          const [offset, val] = [Number(pop()), pop()];
          memory.write(offset, bigIntToBytes32(val));
          break;
        }
        // 0x53: MSTORE8
        case 0x53: {
          useGas(3n);
          const [offset, val] = [Number(pop()), pop()];
          memory.write(offset, new Uint8Array([Number(val & 0xffn)]));
          break;
        }
        // 0x54: SLOAD — verified state read (critical path)
        case 0x54: {
          useGas(2100n);
          const key = pop();
          const slotHex = "0x" + key.toString(16).padStart(64, "0");
          const value = await ctx.state.getStorage(ctx.address, slotHex);
          push(value);
          break;
        }
        // 0x55: SSTORE — not supported in eth_call (read-only)
        case 0x55: {
          if (ctx.readOnly) throw new Error("SSTORE in static context");
          // For eth_call, we can implement ephemeral storage if needed
          useGas(5000n);
          pop(); pop(); // Discard key and value for now
          break;
        }
        // 0x56: JUMP
        case 0x56: {
          useGas(8n);
          const dest = Number(pop());
          if (dest >= ctx.code.length || ctx.code[dest] !== 0x5b) {
            throw new Error(`Invalid JUMP destination: ${dest}`);
          }
          pc = dest + 1; // skip JUMPDEST
          break;
        }
        // 0x57: JUMPI
        case 0x57: {
          useGas(10n);
          const [dest, cond] = [Number(pop()), pop()];
          if (cond !== 0n) {
            if (dest >= ctx.code.length || ctx.code[dest] !== 0x5b) {
              throw new Error(`Invalid JUMPI destination: ${dest}`);
            }
            pc = dest + 1;
          }
          break;
        }
        // 0x58: PC
        case 0x58: { useGas(2n); push(BigInt(pc - 1)); break; }
        // 0x59: MSIZE
        case 0x59: { useGas(2n); push(BigInt(memory.size())); break; }
        // 0x5a: GAS
        case 0x5a: { useGas(2n); push(ctx.gas - gasUsed); break; }
        // 0x5b: JUMPDEST
        case 0x5b: { useGas(1n); break; }

        // 0x5f: PUSH0 (EIP-3855, Shanghai)
        case 0x5f: { useGas(2n); push(0n); break; }

        // 0x60-0x7f: PUSHn
        default: {
          if (op >= 0x60 && op <= 0x7f) {
            useGas(3n);
            const n = op - 0x5f;
            let val = 0n;
            for (let i = 0; i < n; i++) {
              val <<= 8n;
              if (pc < ctx.code.length) {
                val |= BigInt(ctx.code[pc]);
                pc++;
              }
            }
            push(val);
            break;
          }

          // 0x80-0x8f: DUPn
          if (op >= 0x80 && op <= 0x8f) {
            useGas(3n);
            const n = op - 0x80;
            push(peek(n));
            break;
          }

          // 0x90-0x9f: SWAPn
          if (op >= 0x90 && op <= 0x9f) {
            useGas(3n);
            const n = op - 0x90 + 1;
            const topIdx = stack.length - 1;
            const swapIdx = stack.length - 1 - n;
            if (swapIdx < 0) throw new Error("Stack underflow on SWAP");
            [stack[topIdx], stack[swapIdx]] = [stack[swapIdx], stack[topIdx]];
            break;
          }

          // 0xa0-0xa4: LOG0-LOG4 (no-op in eth_call)
          if (op >= 0xa0 && op <= 0xa4) {
            useGas(375n);
            const topicCount = op - 0xa0;
            const [offset, size] = [Number(pop()), Number(pop())];
            useGas(8n * BigInt(size));
            for (let i = 0; i < topicCount; i++) { pop(); useGas(375n); }
            memory.read(offset, size); // expand memory
            break;
          }

          // 0xf1: CALL
          if (op === 0xf1) {
            useGas(100n);
            const callGas = pop();
            const addr = bigIntToAddress(pop());
            const callValue = pop();
            const argsOffset = Number(pop());
            const argsSize = Number(pop());
            const retOffset = Number(pop());
            const retSize = Number(pop());

            if (ctx.depth >= MAX_CALL_DEPTH) {
              push(0n);
              break;
            }

            try {
              const callData = memory.read(argsOffset, argsSize);
              const callCode = await ctx.state.getCode(addr);

              if (callCode.length === 0) {
                push(1n);
                lastReturnData = new Uint8Array(0);
                break;
              }

              const subCtx: EVMContext = {
                address: addr,
                caller: ctx.address,
                origin: ctx.origin,
                callValue,
                callData,
                gas: callGas > ctx.gas - gasUsed ? ctx.gas - gasUsed : callGas,
                code: callCode,
                header: ctx.header,
                state: ctx.state,
                depth: ctx.depth + 1,
                readOnly: false,
              };
              const result = await executeContext(subCtx);
              lastReturnData = result.returnData;
              gasUsed += result.gasUsed;

              if (result.success) {
                memory.write(retOffset, new Uint8Array(result.returnData.buffer, result.returnData.byteOffset, Math.min(retSize, result.returnData.length)));
                push(1n);
              } else {
                push(0n);
              }
            } catch {
              push(0n);
              lastReturnData = new Uint8Array(0);
            }
            break;
          }

          // 0xf3: RETURN
          if (op === 0xf3) {
            const [offset, size] = [Number(pop()), Number(pop())];
            const retBytes = memory.read(offset, size);
            return { success: true, returnData: retBytes, gasUsed };
          }

          // 0xf4: DELEGATECALL
          if (op === 0xf4) {
            useGas(100n);
            const callGas = pop();
            const addr = bigIntToAddress(pop());
            const argsOffset = Number(pop());
            const argsSize = Number(pop());
            const retOffset = Number(pop());
            const retSize = Number(pop());

            if (ctx.depth >= MAX_CALL_DEPTH) {
              push(0n);
              break;
            }

            try {
              const callData = memory.read(argsOffset, argsSize);
              const callCode = await ctx.state.getCode(addr);

              if (callCode.length === 0) {
                push(1n);
                lastReturnData = new Uint8Array(0);
                break;
              }

              const subCtx: EVMContext = {
                address: ctx.address, // keep current address
                caller: ctx.caller,   // keep current caller
                origin: ctx.origin,
                callValue: ctx.callValue,
                callData,
                gas: callGas > ctx.gas - gasUsed ? ctx.gas - gasUsed : callGas,
                code: callCode,
                header: ctx.header,
                state: ctx.state,
                depth: ctx.depth + 1,
                readOnly: ctx.readOnly,
              };
              const result = await executeContext(subCtx);
              lastReturnData = result.returnData;
              gasUsed += result.gasUsed;

              if (result.success) {
                memory.write(retOffset, new Uint8Array(result.returnData.buffer, result.returnData.byteOffset, Math.min(retSize, result.returnData.length)));
                push(1n);
              } else {
                push(0n);
              }
            } catch {
              push(0n);
              lastReturnData = new Uint8Array(0);
            }
            break;
          }

          // 0xfa: STATICCALL
          if (op === 0xfa) {
            useGas(100n);
            const callGas = pop();
            const addr = bigIntToAddress(pop());
            const argsOffset = Number(pop());
            const argsSize = Number(pop());
            const retOffset = Number(pop());
            const retSize = Number(pop());

            if (ctx.depth >= MAX_CALL_DEPTH) {
              push(0n);
              break;
            }

            try {
              const callData = memory.read(argsOffset, argsSize);
              const callCode = await ctx.state.getCode(addr);

              if (callCode.length === 0) {
                push(1n);
                lastReturnData = new Uint8Array(0);
                break;
              }

              const subCtx: EVMContext = {
                address: addr,
                caller: ctx.address,
                origin: ctx.origin,
                callValue: 0n,
                callData,
                gas: callGas > ctx.gas - gasUsed ? ctx.gas - gasUsed : callGas,
                code: callCode,
                header: ctx.header,
                state: ctx.state,
                depth: ctx.depth + 1,
                readOnly: true,
              };
              const result = await executeContext(subCtx);
              lastReturnData = result.returnData;
              gasUsed += result.gasUsed;

              if (result.success) {
                memory.write(retOffset, new Uint8Array(result.returnData.buffer, result.returnData.byteOffset, Math.min(retSize, result.returnData.length)));
                push(1n);
              } else {
                push(0n);
              }
            } catch {
              push(0n);
              lastReturnData = new Uint8Array(0);
            }
            break;
          }

          // 0xfd: REVERT
          if (op === 0xfd) {
            const [offset, size] = [Number(pop()), Number(pop())];
            const revBytes = memory.read(offset, size);
            return { success: false, returnData: revBytes, gasUsed, error: "Revert" };
          }

          // 0xfe: INVALID
          if (op === 0xfe) {
            return { success: false, returnData: new Uint8Array(0), gasUsed, error: "INVALID opcode" };
          }

          // 0xff: SELFDESTRUCT (no-op in eth_call)
          if (op === 0xff) {
            useGas(5000n);
            pop();
            return { success: true, returnData: new Uint8Array(0), gasUsed };
          }

          return {
            success: false,
            returnData: new Uint8Array(0),
            gasUsed,
            error: `Unsupported opcode: 0x${op.toString(16).padStart(2, "0")} at pc=${pc - 1}`,
          };
        }
      }
    }

    return { success: true, returnData, gasUsed };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return { success: false, returnData: new Uint8Array(0), gasUsed, error: msg };
  }
}

/** EVM memory with automatic expansion. */
class EVMMemory {
  private data = new Uint8Array(0);

  read(offset: number, size: number): Uint8Array {
    if (size === 0) return new Uint8Array(0);
    this.expand(offset + size);
    return new Uint8Array(this.data.subarray(offset, offset + size));
  }

  write(offset: number, data: Uint8Array): void {
    if (data.length === 0) return;
    this.expand(offset + data.length);
    this.data.set(data, offset);
  }

  size(): number {
    return this.data.length;
  }

  private expand(needed: number): void {
    if (needed <= this.data.length) return;
    // Round up to 32-byte words
    const newSize = Math.ceil(needed / 32) * 32;
    const newData = new Uint8Array(newSize);
    newData.set(this.data);
    this.data = newData;
  }
}

// Helper functions

function bytesToBigInt(bytes: Uint8Array): bigint {
  if (bytes.length === 0) return 0n;
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) | BigInt(b);
  }
  return result;
}

function bigIntToBytes32(val: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let v = val;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

function addressToBigInt(addr: string): bigint {
  const h = addr.startsWith("0x") ? addr.slice(2) : addr;
  return BigInt("0x" + h.padStart(40, "0"));
}

function bigIntToAddress(val: bigint): string {
  return "0x" + (val & ((1n << 160n) - 1n)).toString(16).padStart(40, "0");
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}
