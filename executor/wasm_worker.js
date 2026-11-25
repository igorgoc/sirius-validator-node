/**
 * Sirius SuperContract V2 — Synchronous WASM Execution Worker
 * Bridges synchronous WebAssembly `env` host imports to the asynchronous
 * `supercontract_server.proto` bi-directional gRPC stream using SharedArrayBuffer + Atomics.
 */

const { parentPort, workerData } = require('worker_threads');
const fs = require('fs');

const {
  wasmModule,
  fileToCall,
  functionToCall,
  parametersHex,
  poexSecretDataPrefix,
  executionGasLimit,
  downloadGasLimit,
  callMode,
  sharedBuffer,
} = workerData;

// Shared memory layout:
// control[0]: state (0 = idle, 1 = waiting for main thread response, 2 = response ready, -1 = error)
// control[1]: payload byte length
const control = new Int32Array(sharedBuffer, 0, 2);
const dataBuffer = new Uint8Array(sharedBuffer, 8);

const callParamsBuffer = Buffer.from(parametersHex || '', 'hex');

let executionGasConsumed = 1n; // Base invocation cost = 1 gas (matches Milestone 1 spec)
let downloadGasConsumed = 0n;
let capturedAggregatedTransaction = null;

const execGasLimitBig = BigInt(executionGasLimit || '0');
const dlGasLimitBig = BigInt(downloadGasLimit || '0');

function consumeExecutionGas(amount) {
  const delta = BigInt(amount);
  if (delta < 0n) {
    throw new Error('NegativeGasDeltaForbidden');
  }
  executionGasConsumed += delta;
  if (execGasLimitBig > 0n && executionGasConsumed > execGasLimitBig) {
    throw new Error('OutOfExecutionGas');
  }
}

function consumeDownloadGas(amount) {
  const delta = BigInt(amount);
  if (delta < 0n) {
    throw new Error('NegativeGasDeltaForbidden');
  }
  downloadGasConsumed += delta;
  if (dlGasLimitBig > 0n && downloadGasConsumed > dlGasLimitBig) {
    throw new Error('OutOfDownloadGas');
  }
}

const HOST_CALL_TIMEOUT_MS = 15000;

/**
 * Synchronously sends a protobuf server_message to the gRPC stream on the main thread
 * and blocks the WASM worker via Atomics.wait() until the C++ Executor replies.
 */
function rpcHostCall(serverMessage) {
  Atomics.store(control, 0, 1);
  parentPort.postMessage({ type: 'host_call', serverMessage });

  // Block WASM thread until main thread receives gRPC reply from Executor (15s safety timeout)
  const waitResult = Atomics.wait(control, 0, 1, HOST_CALL_TIMEOUT_MS);
  if (waitResult === 'timed-out') {
    Atomics.store(control, 0, 0);
    throw new Error(`Host RPC timeout after ${HOST_CALL_TIMEOUT_MS}ms`);
  }

  const status = Atomics.load(control, 0);
  const byteLen = Math.min(Math.max(0, Atomics.load(control, 1)), dataBuffer.byteLength);
  const rawJson = Buffer.from(dataBuffer.buffer, dataBuffer.byteOffset, byteLen).toString('utf8');
  Atomics.store(control, 0, 0);

  if (status === -1) {
    throw new Error(`Host RPC error: ${rawJson || 'stream closed'}`);
  }
  return JSON.parse(rawJson);
}

let memory;

function assertWasmBounds(ptr, len) {
  const start = Number(ptr);
  const length = Number(len);
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(length) || start < 0 || length < 0 || start + length > memory.buffer.byteLength) {
    throw new Error(`WASM memory out-of-bounds access (ptr=${start}, len=${length}, mem=${memory.buffer.byteLength})`);
  }
}

function readStringFromWasm(ptr, len) {
  assertWasmBounds(ptr, len);
  return Buffer.from(memory.buffer, Number(ptr), Number(len)).toString('utf8');
}

function writeBytesToWasm(ptr, buf) {
  assertWasmBounds(ptr, buf.length);
  const dest = new Uint8Array(memory.buffer, Number(ptr), buf.length);
  dest.set(buf);
}

const STREAM_BUFFER_SIZE = 16384n;

const importObject = {
  env: {
    // =========================================================================
    // 1. Blockchain Host API (blockchain_vm.proto)
    // =========================================================================
    buffer_size: () => {
      return STREAM_BUFFER_SIZE;
    },

    get_block_height: () => {
      consumeExecutionGas(10);
      const res = rpcHostCall({ get_block_height: {} });
      return BigInt(res.get_block_height_return?.height || 0);
    },

    get_block_hash: (ptr) => {
      consumeExecutionGas(15);
      const res = rpcHostCall({ get_block_hash: {} });
      const hashBuf = Buffer.from(res.get_block_hash_return?.hash || '', 'base64');
      const padded = Buffer.alloc(32);
      hashBuf.copy(padded, 0, 0, Math.min(32, hashBuf.length));
      writeBytesToWasm(ptr, padded);
    },

    get_block_time: () => {
      consumeExecutionGas(10);
      const res = rpcHostCall({ get_block_time: {} });
      return BigInt(res.get_block_time_return?.timestamp || 0);
    },

    get_block_generation_time: () => {
      consumeExecutionGas(10);
      const res = rpcHostCall({ get_block_generation_time: {} });
      return BigInt(res.get_block_generation_time_return?.delta || 15000);
    },

    get_transaction_hash: (ptr) => {
      consumeExecutionGas(15);
      const res = rpcHostCall({ get_transaction_hash: {} });
      const hashBuf = Buffer.from(res.get_transaction_hash_return?.hash || '', 'base64');
      const padded = Buffer.alloc(32);
      hashBuf.copy(padded, 0, 0, Math.min(32, hashBuf.length));
      writeBytesToWasm(ptr, padded);
    },

    get_caller_public_key: (ptr) => {
      consumeExecutionGas(15);
      const res = rpcHostCall({ get_caller_public_key: {} });
      const keyBuf = Buffer.from(res.get_caller_public_key_return?.public_key || '', 'base64');
      const padded = Buffer.alloc(32);
      keyBuf.copy(padded, 0, 0, Math.min(32, keyBuf.length));
      writeBytesToWasm(ptr, padded);
    },

    get_contract_public_key: (ptr) => {
      consumeExecutionGas(15);
      const res = rpcHostCall({ get_contract_public_key: {} });
      const keyBuf = Buffer.from(res.get_contract_public_key_return?.public_key || '', 'base64');
      const padded = Buffer.alloc(32);
      keyBuf.copy(padded, 0, 0, Math.min(32, keyBuf.length));
      writeBytesToWasm(ptr, padded);
    },

    get_execution_payment: () => {
      consumeExecutionGas(10);
      const res = rpcHostCall({ get_execution_payment: {} });
      return BigInt(res.get_execution_payment_return?.amount || 0);
    },

    get_download_payment: () => {
      consumeExecutionGas(10);
      const res = rpcHostCall({ get_download_payment: {} });
      return BigInt(res.get_download_payment_return?.amount || 0);
    },

    get_call_params_length: () => {
      consumeExecutionGas(5);
      return BigInt(callParamsBuffer.length);
    },

    get_call_params: (ptr) => {
      consumeExecutionGas(5 + callParamsBuffer.length);
      if (callParamsBuffer.length > 0) {
        writeBytesToWasm(ptr, callParamsBuffer);
      }
      return BigInt(callParamsBuffer.length);
    },

    get_service_payments: (ptr) => {
      consumeExecutionGas(20);
      const res = rpcHostCall({ get_service_payments: {} });
      const maxPayments = Math.floor(Number(STREAM_BUFFER_SIZE) / 16);
      const payments = (res.get_service_payments_return?.payments || []).slice(0, maxPayments);
      assertWasmBounds(ptr, payments.length * 16);
      const memView = new DataView(memory.buffer);
      let offset = Number(ptr);
      for (const p of payments) {
        memView.setBigUint64(offset, BigInt(p.mosaic_id), true);
        memView.setBigUint64(offset + 8, BigInt(p.amount), true);
        offset += 16;
      }
      return BigInt(payments.length);
    },

    set_transaction: (ptr, len) => {
      assertWasmBounds(ptr, len);
      consumeExecutionGas(50 + Number(len));
      const buffer = Buffer.from(memory.buffer, Number(ptr), Number(len));
      if (buffer.length < 10) {
        throw new Error('Malformed AggregateTransaction buffer (< 10 bytes)');
      }
      let offset = 0;
      const maxFee = buffer.readBigUInt64LE(offset);
      offset += 8;
      const embeddedCount = buffer.readUInt16LE(offset);
      offset += 2;

      const transactions = [];
      for (let i = 0; i < embeddedCount; i++) {
        if (offset + 8 > buffer.length) {
          throw new Error('Truncated EmbeddedTransaction header in set_transaction');
        }
        const entityType = buffer.readUInt16LE(offset);
        offset += 2;
        const version = buffer.readUInt32LE(offset);
        offset += 4;
        const payloadSize = buffer.readUInt16LE(offset);
        offset += 2;
        if (offset + payloadSize > buffer.length) {
          throw new Error('Truncated EmbeddedTransaction payload in set_transaction');
        }
        const payload = buffer.subarray(offset, offset + payloadSize);
        offset += payloadSize;

        transactions.push({
          entity_type: entityType,
          version: version,
          payload: Buffer.from(payload).toString('base64'),
        });
      }

      capturedAggregatedTransaction = {
        max_fee: maxFee.toString(),
        transactions,
      };
    },

    // =========================================================================
    // 2. Storage & File Persistence Host API (storage_vm.proto)
    // =========================================================================
    open_file: (pathPtr, pathLen, modePtr, modeLen) => {
      const filePath = readStringFromWasm(pathPtr, pathLen);
      const mode = readStringFromWasm(modePtr, modeLen);
      consumeExecutionGas(25);
      const res = rpcHostCall({ open_file: { path: filePath, mode } });
      const ret = res.open_file_return;
      if (!ret || !ret.success) {
        return -1n;
      }
      return BigInt(ret.identifier);
    },

    write_file_stream: (identifier, bufPtr, bufLen) => {
      const chunk = Buffer.from(memory.buffer, Number(bufPtr), Number(bufLen));
      consumeExecutionGas(20 + chunk.length);
      const res = rpcHostCall({
        write_file_stream: {
          identifier: identifier.toString(),
          buffer: chunk.toString('base64'),
        },
      });
      const ret = res.write_file_stream_return;
      if (!ret || !ret.success) {
        return -1n;
      }
      return BigInt(ret.num_bytes_written);
    },

    read_file_stream: (identifier, ptrToWrite) => {
      consumeExecutionGas(20);
      const res = rpcHostCall({
        read_file_stream: {
          identifier: identifier.toString(),
        },
      });
      const ret = res.read_file_stream_return;
      if (!ret || !ret.success) {
        return -1n;
      }
      const chunk = Buffer.from(ret.buffer || '', 'base64');
      consumeDownloadGas(chunk.length);
      if (chunk.length > 0) {
        writeBytesToWasm(ptrToWrite, chunk);
      }
      return BigInt(chunk.length);
    },

    flush: (identifier) => {
      consumeExecutionGas(15);
      const res = rpcHostCall({
        flush: { identifier: identifier.toString() },
      });
      return res.flush_return?.success ? 1 : 0;
    },

    close_file: (identifier) => {
      consumeExecutionGas(10);
      const res = rpcHostCall({
        close_file: { identifier: identifier.toString() },
      });
      return res.close_file_return?.success ? 1 : 0;
    },

    path_exists: (pathPtr, pathLen) => {
      const p = readStringFromWasm(pathPtr, pathLen);
      consumeExecutionGas(15);
      const res = rpcHostCall({ path_exist: { path: p } });
      return res.path_exist_return?.exist ? 1 : 0;
    },

    is_file: (pathPtr, pathLen) => {
      const p = readStringFromWasm(pathPtr, pathLen);
      consumeExecutionGas(15);
      const res = rpcHostCall({ is_file: { path: p } });
      const ret = res.is_file_return;
      if (!ret || !ret.success) {
        return -1;
      }
      return ret.is_file ? 1 : 0;
    },

    file_size: (pathPtr, pathLen) => {
      const p = readStringFromWasm(pathPtr, pathLen);
      consumeExecutionGas(15);
      const res = rpcHostCall({ file_size: { path: p } });
      const ret = res.file_size_return;
      if (!ret || !ret.success) {
        return -1n;
      }
      return BigInt(ret.file_size);
    },

    create_dir: (pathPtr, pathLen) => {
      const p = readStringFromWasm(pathPtr, pathLen);
      consumeExecutionGas(25);
      const res = rpcHostCall({ create_dir: { path: p } });
      return res.create_dir_return?.success ? 1 : 0;
    },

    move_filesystem_entry: (newPtr, newLen, oldPtr, oldLen) => {
      const newPath = readStringFromWasm(newPtr, newLen);
      const oldPath = readStringFromWasm(oldPtr, oldLen);
      consumeExecutionGas(30);
      const res = rpcHostCall({
        move_filesystem_entry: { old_path: oldPath, new_path: newPath },
      });
      return res.move_filesystem_entry_return?.success ? 1 : 0;
    },

    remove_filesystem_entry: (pathPtr, pathLen) => {
      const p = readStringFromWasm(pathPtr, pathLen);
      consumeExecutionGas(25);
      const res = rpcHostCall({ remove_filesystem_entry: { path: p } });
      return res.remove_filesystem_entry_return?.success ? 1 : 0;
    },

    create_dir_iterator: (pathPtr, pathLen, recursive) => {
      const p = readStringFromWasm(pathPtr, pathLen);
      consumeExecutionGas(25);
      const res = rpcHostCall({
        create_dir_iterator: { path: p, recursive: Boolean(recursive) },
      });
      const ret = res.create_dir_iterator_return;
      if (!ret || !ret.success) {
        return -1n;
      }
      return BigInt(ret.identifier);
    },

    destroy_dir_iterator: (identifier) => {
      consumeExecutionGas(10);
      const res = rpcHostCall({
        destroy_dir_iterator: { identifier: identifier.toString() },
      });
      return res.destroy_dir_iterator_return?.success ? 1 : 0;
    },

    has_next_dir_iterator: (identifier) => {
      consumeExecutionGas(10);
      const res = rpcHostCall({
        has_next_iterator: { identifier: identifier.toString() },
      });
      return res.has_next_iterator_return?.has_next ? 1 : 0;
    },

    next_dir_iterator: (identifier, ptrToWrite) => {
      consumeExecutionGas(15);
      const res = rpcHostCall({
        next_dir_iterator: { identifier: identifier.toString() },
      });
      const ret = res.next_dir_iterator_return;
      if (!ret || !ret.success) {
        return 0;
      }
      const nameBytes = Buffer.from(ret.name || '', 'utf8');
      const base = Number(ptrToWrite);
      assertWasmBounds(base, 6 + nameBytes.length);
      const memView = new DataView(memory.buffer);
      memView.setUint32(base, Number(ret.depth || 0), true);
      memView.setUint16(base + 4, nameBytes.length, true);
      writeBytesToWasm(base + 6, nameBytes);
      return 1;
    },

    // =========================================================================
    // 3. Internet Oracle Host API (internet_vm.proto)
    // =========================================================================
    open_connection: (urlPtr, urlLen, softRevocationMode) => {
      const url = readStringFromWasm(urlPtr, urlLen);
      consumeExecutionGas(40);
      const res = rpcHostCall({
        open_connection: { url, soft_revocation_mode: Boolean(softRevocationMode) },
      });
      const ret = res.open_connection_return;
      if (!ret || !ret.success) {
        return -1n;
      }
      return BigInt(ret.identifier);
    },

    read_from_internet: (identifier, ptrToWrite) => {
      consumeExecutionGas(30);
      const res = rpcHostCall({
        read_connection_stream: { identifier: identifier.toString() },
      });
      const ret = res.read_connection_stream_return;
      if (!ret || !ret.success) {
        return -1n;
      }
      const chunk = Buffer.from(ret.buffer || '', 'base64');
      consumeDownloadGas(chunk.length);
      if (chunk.length > 0) {
        writeBytesToWasm(ptrToWrite, chunk);
      }
      return BigInt(chunk.length);
    },

    close_connection: (identifier) => {
      consumeExecutionGas(10);
      const res = rpcHostCall({
        close_connection: { identifier: identifier.toString() },
      });
      return res.close_connection_return?.success ? 1 : 0;
    },
  },
};

async function executeWasm() {
  try {
    let instance;
    if (wasmModule) {
      instance = await WebAssembly.instantiate(wasmModule, importObject);
    } else {
      if (!fs.existsSync(fileToCall)) {
        throw new Error(`WASM file not found: ${fileToCall}`);
      }
      const wasmBytes = fs.readFileSync(fileToCall);
      const res = await WebAssembly.instantiate(wasmBytes, importObject);
      instance = res.instance;
    }
    memory = instance.exports.memory;

    const fnName = functionToCall || 'run';
    const entrypoint = instance.exports[fnName];
    if (typeof entrypoint !== 'function') {
      throw new Error(`Exported function '${fnName}' not found in WASM module`);
    }

    const rawReturn = entrypoint();
    const returnVal = Number(rawReturn) >>> 0;

    // Deterministic Proof-of-Execution (PoEx) calculation
    const prefixBig = BigInt(poexSecretDataPrefix || 0);
    const poexSecretData = (prefixBig ^ (executionGasConsumed * 0x9e3779b97f4a7c15n) ^ BigInt(returnVal)) & 0xffffffffffffffffn;

    parentPort.postMessage({
      type: 'execution_complete',
      returns: {
        success: true,
        execution_gas_consumed: executionGasConsumed.toString(),
        download_gas_consumed: downloadGasConsumed.toString(),
        poex_secret_data: poexSecretData.toString(),
        return_val: returnVal,
        transaction: capturedAggregatedTransaction,
      },
    });
  } catch (err) {
    parentPort.postMessage({
      type: 'execution_complete',
      returns: {
        success: false,
        execution_gas_consumed: executionGasConsumed.toString(),
        download_gas_consumed: downloadGasConsumed.toString(),
        poex_secret_data: String(poexSecretDataPrefix || 0),
        return_val: 0,
        error: err.message,
      },
    });
  }
}

executeWasm();
