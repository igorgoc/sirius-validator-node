/**
 * Sirius SuperContract V2 — Production Standalone gRPC Virtual Machine Server
 * Implements `supercontractserver.SupercontractServer` (`supercontract_server.proto`)
 * for an independent validator node (e.g. running on an independent VPS or container).
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Worker } = require('worker_threads');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

const ROOT_DIR = path.resolve(__dirname, '..');
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT_DIR, 'data');
const DRIVES_DIR = path.join(DATA_DIR, 'drives');
const CONTRACTS_DIR = process.env.CONTRACTS_DIR || path.join(ROOT_DIR, 'contracts');
const PROTO_DIR = path.join(__dirname, 'proto');
const PROTO_PATH = path.join(PROTO_DIR, 'supercontract_server.proto');

function verifyVmAuthMetadata(callOrStream) {
  const expectedToken = process.env.SIRIUS_VM_AUTH_TOKEN;
  if (!expectedToken) return true; // Open mode if token is not configured
  const metaVals = callOrStream && callOrStream.metadata ? callOrStream.metadata.get('x-sirius-vm-token') : [];
  const provided = String((metaVals && metaVals[0]) || '');
  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(String(expectedToken), 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function validateWasmFileToCall(filePath) {
  if (!filePath || typeof filePath !== 'string') {
    throw new Error('Missing file_to_call path');
  }
  let resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    const candidate = path.join(CONTRACTS_DIR, path.basename(filePath));
    if (fs.existsSync(candidate)) {
      resolved = candidate;
    }
  }

  if (!fs.existsSync(resolved)) {
    throw new Error(`Security rejection: WASM binary does not exist at ${resolved}`);
  }

  const allowedHashesRaw = process.env.SIRIUS_ALLOWED_WASM_SHA256;
  if (allowedHashesRaw) {
    const allowedSet = new Set(
      allowedHashesRaw
        .split(',')
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)
    );
    if (allowedSet.size > 0) {
      const actualHash = crypto.createHash('sha256').update(fs.readFileSync(resolved)).digest('hex').toLowerCase();
      if (!allowedSet.has(actualHash)) {
        throw new Error(`Security rejection: WASM SHA-256 (${actualHash}) is not in SIRIUS_ALLOWED_WASM_SHA256 allowlist`);
      }
    }
  }
  return resolved;
}

const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});

const supercontractProto = grpc.loadPackageDefinition(packageDefinition);
const supercontractserver = supercontractProto.supercontractserver;

// In-memory LRU cache of pre-compiled WebAssembly.Module instances
const wasmModuleCache = new Map();
async function getCompiledWasmModule(wasmPath) {
  const stats = fs.statSync(wasmPath);
  const cacheKey = `${wasmPath}:${stats.mtimeMs}:${stats.size}`;
  if (wasmModuleCache.has(cacheKey)) {
    return wasmModuleCache.get(cacheKey);
  }
  const wasmBuffer = fs.readFileSync(wasmPath);
  const compiledModule = await WebAssembly.compile(wasmBuffer);
  wasmModuleCache.set(cacheKey, compiledModule);
  return compiledModule;
}

function prepareServerMessage(msg) {
  const clone = { ...msg };
  if (clone.storage_read && clone.storage_read.drive_key) {
    clone.storage_read.drive_key = Buffer.from(clone.storage_read.drive_key, 'hex');
  }
  if (clone.storage_save && clone.storage_save.drive_key) {
    clone.storage_save.drive_key = Buffer.from(clone.storage_save.drive_key, 'hex');
  }
  return clone;
}

function createSupercontractService(nodeName, bindAddress) {
  return {
    Ping: (call, callback) => {
      if (!verifyVmAuthMetadata(call)) {
        return callback({ code: grpc.status.UNAUTHENTICATED, details: 'Unauthorized: invalid VM auth token' });
      }
      callback(null, {
        message: `PONG from ${nodeName} (uptime: ${Math.floor(process.uptime())}s)`,
      });
    },

    ExecuteCall: (stream) => {
      if (!verifyVmAuthMetadata(stream)) {
        stream.emit('error', { code: grpc.status.UNAUTHENTICATED, details: 'Unauthorized: invalid VM auth token' });
        return;
      }

      let worker = null;
      let sharedBuffer = null;
      let control = null;
      let dataBuffer = null;

      stream.on('data', async (clientMsg) => {
        if (clientMsg.execute_call) {
          const execReq = clientMsg.execute_call;
          console.log(`[${nodeName} VM] ⚡ ExecuteCall started: file=${path.basename(execReq.file_to_call)} fn=${execReq.function_to_call} gasLimit=${execReq.execution_gas_limit}`);

          let validatedWasmPath;
          try {
            validatedWasmPath = validateWasmFileToCall(execReq.file_to_call);
          } catch (valErr) {
            console.error(`[${nodeName} VM] Rejection:`, valErr.message);
            stream.write({
              returns: {
                success: false,
                execution_gas_consumed: '0',
                download_gas_consumed: '0',
                poex_secret_data: '0',
                return_val: 101, // ErrorCode::InvalidParameters
              },
            });
            stream.end();
            return;
          }

          sharedBuffer = new SharedArrayBuffer(1024 * 1024 * 4); // 4MB shared memory
          control = new Int32Array(sharedBuffer, 0, 2);
          dataBuffer = new Uint8Array(sharedBuffer, 8);

          const paramsHex = Buffer.isBuffer(execReq.parameters)
            ? execReq.parameters.toString('hex')
            : (execReq.parameters ? Buffer.from(execReq.parameters).toString('hex') : '');

          let wasmModule = null;
          try {
            wasmModule = await getCompiledWasmModule(validatedWasmPath);
          } catch (compErr) {
            console.warn(`[${nodeName} VM] Notice: Precompiled WASM cache fallback:`, compErr.message);
          }

          worker = new Worker(path.join(__dirname, 'wasm_worker.js'), {
            workerData: {
              wasmModule,
              fileToCall: validatedWasmPath,
              functionToCall: execReq.function_to_call,
              parametersHex: paramsHex,
              poexSecretDataPrefix: execReq.poex_secret_data_prefix || '0',
              executionGasLimit: execReq.execution_gas_limit || '0',
              downloadGasLimit: execReq.download_gas_limit || '0',
              callMode: execReq.call_mode || 0,
              sharedBuffer,
            },
          });

          worker.on('message', (msg) => {
            if (msg.type === 'host_call') {
              const outbound = prepareServerMessage(msg.serverMessage);
              stream.write(outbound);
            } else if (msg.type === 'execution_complete') {
              const ret = msg.returns;
              const protoReturns = {
                success: Boolean(ret.success),
                execution_gas_consumed: String(ret.execution_gas_consumed || '0'),
                download_gas_consumed: String(ret.download_gas_consumed || '0'),
                poex_secret_data: String(ret.poex_secret_data || '0'),
                return_val: Number(ret.return_val || 0),
              };

              if (ret.transaction) {
                protoReturns.transaction = {
                  max_fee: String(ret.transaction.max_fee || '0'),
                  transactions: (ret.transaction.transactions || []).map((tx) => ({
                    entity_type: Number(tx.entity_type),
                    version: Number(tx.version),
                    payload: Buffer.from(tx.payload, 'base64'),
                  })),
                };
              }

              console.log(`[${nodeName} VM] ✅ ExecuteCall complete: success=${protoReturns.success} return=${protoReturns.return_val} gas=${protoReturns.execution_gas_consumed} poex=${protoReturns.poex_secret_data}`);
              stream.write({ returns: protoReturns });
              stream.end();
            } else if (msg.type === 'error') {
              console.error(`[${nodeName} VM] ❌ Worker execution error:`, msg.error);
              stream.write({
                returns: {
                  success: false,
                  execution_gas_consumed: '0',
                  download_gas_consumed: '0',
                  poex_secret_data: '0',
                  return_val: 104, // ErrorCode::ContractExecutionError
                },
              });
              stream.end();
            }
          });

          worker.on('error', (err) => {
            console.error(`[${nodeName} VM] Worker thread crash:`, err);
            stream.write({
              returns: {
                success: false,
                execution_gas_consumed: '0',
                download_gas_consumed: '0',
                poex_secret_data: '0',
                return_val: 104,
              },
            });
            stream.end();
          });
        } else {
          // Handle client responses for host calls (storage read, drive saves)
          let payloadBytes = Buffer.alloc(0);
          let isError = false;

          if (clientMsg.storage_read) {
            payloadBytes = clientMsg.storage_read.content || Buffer.alloc(0);
          } else if (clientMsg.storage_save) {
            payloadBytes = Buffer.alloc(0);
          } else if (clientMsg.error) {
            isError = true;
          }

          if (control && dataBuffer) {
            if (isError) {
              Atomics.store(control, 1, 0);
              Atomics.store(control, 0, -1);
            } else {
              const maxCopy = Math.min(payloadBytes.length, dataBuffer.length);
              payloadBytes.copy(dataBuffer, 0, 0, maxCopy);
              Atomics.store(control, 1, maxCopy);
              Atomics.store(control, 0, 2); // Response ready
            }
            Atomics.notify(control, 0, 1);
          }
        }
      });

      function abortWorker() {
        if (control) {
          Atomics.store(control, 1, 0);
          Atomics.store(control, 0, -1);
          Atomics.notify(control, 0, 1);
        }
        if (worker) {
          const w = worker;
          worker = null;
          w.terminate().catch(() => {});
        }
      }

      stream.on('end', abortWorker);
      stream.on('error', (err) => {
        console.error(`[${nodeName} VM] Stream error:`, err.message);
        abortWorker();
      });
    },
  };
}

function startVmServer(port, nodeName, bindHost = process.env.SIRIUS_VM_BIND_HOST || '0.0.0.0') {
  return new Promise((resolve, reject) => {
    const bindAddress = `${bindHost}:${port}`;
    const server = new grpc.Server();
    server.addService(
      supercontractserver.SupercontractServer.service,
      createSupercontractService(nodeName, bindAddress)
    );
    server.bindAsync(bindAddress, grpc.ServerCredentials.createInsecure(), (err, boundPort) => {
      if (err) {
        return reject(err);
      }
      console.log(`================================================================================`);
      console.log(`🚀 Sirius SuperContract Validator Node [${nodeName}] Online`);
      console.log(`   Listening on:   ${bindHost}:${boundPort}`);
      console.log(`   Contracts Dir:  ${CONTRACTS_DIR}`);
      console.log(`   Data/Drive Dir: ${DRIVES_DIR}`);
      console.log(`================================================================================`);
      resolve(server);
    });
  });
}

if (require.main === module) {
  const port = parseInt(process.argv[2] || process.env.VM_PORT || '5051', 10);
  const nodeName = process.argv[3] || process.env.NODE_NAME || `node-${port}`;
  setInterval(() => {}, 60000);
  startVmServer(port, nodeName).catch((err) => {
    console.error(`Failed to start VM server on port ${port}:`, err);
    process.exit(1);
  });
}

module.exports = { startVmServer, supercontractserver, verifyVmAuthMetadata, validateWasmFileToCall };
