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
const PROTO_DIR = __dirname;
const PROTO_PATH = path.join(PROTO_DIR, 'proto/supercontract_server.proto');
const DRIVE_KEY_HEX = process.env.DRIVE_KEY_HEX || 'bd1d100a98c34f62e170a8395b4498dc1e730286f5a12c489b37d01562f0cb23';

let xpxSdk = null;
function getXpxSdk() {
  if (!xpxSdk) {
    try {
      xpxSdk = require('tsjs-xpx-chain-sdk');
    } catch (_) {
      xpxSdk = require(path.resolve(ROOT_DIR, 'node_modules/tsjs-xpx-chain-sdk'));
    }
  }
  return xpxSdk;
}

const nodeValidatorCache = new Map();
function getOrInitNodeValidatorAccount(nodeName) {
  if (nodeValidatorCache.has(nodeName)) {
    return nodeValidatorCache.get(nodeName);
  }
  const sdk = getXpxSdk();
  const networkType = Number(process.env.SIRIUS_NETWORK_TYPE || (String(process.env.SIRIUS_NETWORK || '').toLowerCase() === 'mainnet' ? 184 : 168));
  const envSpecificKey = process.env[`SIRIUS_VALIDATOR_PRIVATE_KEY_${String(nodeName).toUpperCase().replace(/[^A-Z0-9]/g, '_')}`];
  const envGenericKey = process.env.SIRIUS_VALIDATOR_PRIVATE_KEY;
  const rawEnvKey = (envSpecificKey || envGenericKey || '').trim();

  if (rawEnvKey && /^[0-9a-fA-F]{64}$/.test(rawEnvKey)) {
    const acc = sdk.Account.createFromPrivateKey(rawEnvKey, networkType, 1);
    nodeValidatorCache.set(nodeName, acc);
    return acc;
  }

  const keyFile = path.join(DATA_DIR, 'validator_key.json');
  if (fs.existsSync(keyFile)) {
    const data = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
    if (data && data.privateKey && /^[0-9a-fA-F]{64}$/.test(data.privateKey)) {
      const acc = sdk.Account.createFromPrivateKey(data.privateKey, networkType, 1);
      nodeValidatorCache.set(nodeName, acc);
      return acc;
    }
  }

  const acc = sdk.Account.generateNewAccount(networkType);
  try {
    fs.mkdirSync(path.dirname(keyFile), { recursive: true, mode: 0o700 });
    fs.writeFileSync(
      keyFile,
      JSON.stringify(
        {
          nodeName,
          networkType,
          address: acc.address.plain(),
          publicKey: acc.publicKey,
          privateKey: acc.privateKey,
          createdAt: new Date().toISOString(),
        },
        null,
        2
      ),
      { mode: 0o600 }
    );
  } catch (e) {
    console.warn(`[${nodeName} VM] Warning persisting validator key:`, e.message);
  }
  nodeValidatorCache.set(nodeName, acc);
  return acc;
}

function readNodeDriveBalances(ownerKeyHex) {
  try {
    const balancesPath = path.join(DRIVES_DIR, DRIVE_KEY_HEX, 'drive', 'markets', 'balances.json');
    if (!fs.existsSync(balancesPath)) return null;
    const data = JSON.parse(fs.readFileSync(balancesPath, 'utf8'));
    if (!data || !Array.isArray(data.accounts)) return null;
    const norm = String(ownerKeyHex || '').toLowerCase();
    const entry = data.accounts.find((a) => Buffer.from(a.pubkey || []).toString('hex').toLowerCase() === norm);
    return entry || null;
  } catch (_) {
    return null;
  }
}

function verifyAndCosignOnNode(nodeName, req) {
  const sdk = getXpxSdk();
  const {
    TransactionMapping,
    TransactionType,
    CosignatureTransaction,
  } = sdk;

  const action = String(req.action || '').trim().toUpperCase();
  const payloadHex = String(req.aggregate_payload_hex || '').trim();
  const generationHash = String(req.generation_hash || '').trim();
  const callerPub = String(req.caller_public_key || '').trim().toUpperCase();
  const tradingPub = String(req.trading_account_public_key || '').trim().toUpperCase();
  const clusterPub = String(req.validator_cluster_public_key || process.env.SIRIUS_VALIDATOR_CLUSTER_PUBKEY || '').trim().toUpperCase();

  if (!payloadHex || !generationHash) {
    throw new Error('Missing aggregate_payload_hex or generation_hash');
  }

  let metadata = {};
  if (req.metadata_json) {
    try {
      metadata = JSON.parse(req.metadata_json);
    } catch (_) {
      throw new Error('Malformed metadata_json');
    }
  }

  const tx = TransactionMapping.createFromPayload(payloadHex);
  if (tx.type !== TransactionType.AGGREGATE_COMPLETE_V1 && tx.type !== TransactionType.AGGREGATE_COMPLETE) {
    throw new Error(`Rejected tx type ${tx.type}: only AGGREGATE_COMPLETE_V1 permitted`);
  }
  if (!Array.isArray(tx.innerTransactions) || tx.innerTransactions.length === 0) {
    throw new Error('Rejected aggregate transaction with 0 inner transactions');
  }

  if (action === 'ACTIVATE_TRADING_ACCOUNT') {
    if (tx.innerTransactions.length !== 1) {
      throw new Error(`ACTIVATE_TRADING_ACCOUNT must contain exactly 1 inner transaction (got ${tx.innerTransactions.length})`);
    }
    const inner = tx.innerTransactions[0];
    if (inner.type !== TransactionType.MODIFY_MULTISIG_ACCOUNT) {
      throw new Error(`Expected MODIFY_MULTISIG_ACCOUNT (16725), got ${inner.type}`);
    }
    if (!inner.signer || inner.signer.publicKey.toUpperCase() !== tradingPub) {
      throw new Error('ModifyMultisigAccount signer does not match trading_account_public_key');
    }
    if (inner.minApprovalDelta !== 2 || inner.minRemovalDelta !== 2) {
      throw new Error(`Security rejection: minApprovalDelta and minRemovalDelta must both be 2 (got ${inner.minApprovalDelta}/${inner.minRemovalDelta})`);
    }
    if (!Array.isArray(inner.modifications) || inner.modifications.length !== 2) {
      throw new Error('Security rejection: Trading Account must have exactly 2 cosignatories (User + ValidatorCluster)');
    }
    const modPks = inner.modifications.map((m) => {
      if (m.type !== 0) {
        throw new Error('Security rejection: Only Add cosignatory modifications are permitted during activation');
      }
      return m.cosignatoryPublicAccount.publicKey.toUpperCase();
    });
    if (!modPks.includes(callerPub) || !clusterPub || !modPks.includes(clusterPub)) {
      throw new Error('Security rejection: Modifications must strictly include [UserMainPublicKey, ValidatorClusterPublicKey]');
    }
  } else if (action === 'WITHDRAWAL') {
    if (!tradingPub || !callerPub) {
      throw new Error('Missing caller_public_key or trading_account_public_key for WITHDRAWAL');
    }
    const expectedRecipientRaw = String(metadata.recipientAddress || '').replace(/[- ]/g, '').toUpperCase();
    const maxFreeAtomic = metadata.maxWithdrawableAtomic ? BigInt(metadata.maxWithdrawableAtomic) : null;
    const feeCollectorAddr = String(metadata.feeCollectorAddress || '').replace(/[- ]/g, '').toUpperCase();
    let totalOutgoingByMosaic = new Map();

    for (const inner of tx.innerTransactions) {
      if (inner.type !== TransactionType.TRANSFER) {
        throw new Error(`Security rejection: WITHDRAWAL aggregate may ONLY contain TRANSFER transactions (got ${inner.type})`);
      }
      if (!inner.signer || inner.signer.publicKey.toUpperCase() !== tradingPub) {
        throw new Error('Security rejection: All withdrawal transfers must originate from trading_account_public_key');
      }
      const recipObj = inner.recipient || inner.recipientAddress;
      const recipAddr = recipObj && typeof recipObj.plain === 'function' ? recipObj.plain().replace(/[- ]/g, '').toUpperCase() : '';
      if (expectedRecipientRaw && recipAddr !== expectedRecipientRaw && (!feeCollectorAddr || recipAddr !== feeCollectorAddr)) {
        throw new Error(`Security rejection: Transfer recipient ${recipAddr} does not match approved recipient ${expectedRecipientRaw}`);
      }
      for (const m of (inner.mosaics || [])) {
        const mHex = m.id.toHex().toUpperCase();
        const amt = BigInt(m.amount.compact ? m.amount.compact() : m.amount);
        totalOutgoingByMosaic.set(mHex, (totalOutgoingByMosaic.get(mHex) || 0n) + amt);
      }
    }

    if (maxFreeAtomic !== null && metadata.mosaicHex) {
      const mKey = String(metadata.mosaicHex).toUpperCase();
      const outAmt = totalOutgoingByMosaic.get(mKey) || 0n;
      if (outAmt > maxFreeAtomic) {
        throw new Error(`Security rejection on ${nodeName}: requested withdrawal ${outAmt} exceeds verified free balance ${maxFreeAtomic}`);
      }
    }

    const driveAcc = readNodeDriveBalances(callerPub);
    if (driveAcc && metadata.onChainBalanceAtomic && metadata.mosaicIdDecimal) {
      const mDec = String(metadata.mosaicIdDecimal);
      const lockedInDrive = BigInt((driveAcc.locked && driveAcc.locked[mDec]) || '0');
      const onChainAmt = BigInt(metadata.onChainBalanceAtomic);
      const driveFree = onChainAmt > lockedInDrive ? onChainAmt - lockedInDrive : 0n;
      const requested = metadata.requestedAmountAtomic ? BigInt(metadata.requestedAmountAtomic) : 0n;
      if (requested > driveFree) {
        throw new Error(`BFT lock check rejected on ${nodeName}: ${requested} > free ${driveFree} (locked=${lockedInDrive})`);
      }
    }
  } else if (action === 'SETTLEMENT') {
    const allowedSigners = new Set(
      (Array.isArray(metadata.allowedSigners) ? metadata.allowedSigners : []).map((s) => String(s).toUpperCase())
    );
    for (const inner of tx.innerTransactions) {
      if (inner.type !== TransactionType.TRANSFER) {
        throw new Error(`Security rejection: SETTLEMENT aggregate may only contain TRANSFER transactions (got ${inner.type})`);
      }
      const signerPk = inner.signer ? inner.signer.publicKey.toUpperCase() : '';
      if (allowedSigners.size > 0 && !allowedSigners.has(signerPk)) {
        throw new Error(`Security rejection: Unexpected settlement inner signer ${signerPk}`);
      }
    }
  } else {
    throw new Error(`Unsupported cosign action: ${action}`);
  }

  const validatorAcc = getOrInitNodeValidatorAccount(nodeName);
  const cosig = CosignatureTransaction.signTransactionPayload(validatorAcc, payloadHex, generationHash);
  return {
    approved: true,
    error: '',
    node_name: nodeName,
    signer_public_key: cosig.signer,
    parent_hash: cosig.parentHash,
    signature: cosig.signature,
  };
}

function verifyVmAuthMetadata(callOrStream, bindAddress = '') {
  const expectedToken = process.env.SIRIUS_VM_AUTH_TOKEN;
  const isLoopbackOnly = bindAddress.startsWith('127.0.0.1') || bindAddress.startsWith('localhost');
  if (!expectedToken) {
    if (process.env.NODE_ENV === 'production' || (!isLoopbackOnly && bindAddress)) {
      console.error('[SECURITY] Rejected unauthenticated call: SIRIUS_VM_AUTH_TOKEN is required when exposed to non-loopback network');
      return false;
    }
    return true; // Dev mode on loopback only
  }
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

  // Strict path containment & extension validation
  const contractsRoot = CONTRACTS_DIR.endsWith(path.sep) ? CONTRACTS_DIR : CONTRACTS_DIR + path.sep;
  if (!resolved.startsWith(contractsRoot)) {
    throw new Error(`Security rejection: WASM binary (${filePath}) must reside inside authorized contracts directory: ${CONTRACTS_DIR}`);
  }
  if (!resolved.endsWith('.wasm')) {
    throw new Error(`Security rejection: Only .wasm WebAssembly binaries are permitted`);
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

function normalizeClientMessage(msg) {
  if (Array.isArray(msg)) {
    return msg.map((item) => {
      if (Buffer.isBuffer(item)) return item.toString('base64');
      if (item && typeof item === 'object') return normalizeClientMessage(item);
      return item;
    });
  }
  const out = {};
  for (const [k, v] of Object.entries(msg)) {
    if (Buffer.isBuffer(v)) {
      out[k] = v.toString('base64');
    } else if (Array.isArray(v)) {
      out[k] = normalizeClientMessage(v);
    } else if (v && typeof v === 'object') {
      out[k] = normalizeClientMessage(v);
    } else {
      out[k] = v;
    }
  }
  return out;
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
      if (!verifyVmAuthMetadata(call, bindAddress)) {
        return callback({ code: grpc.status.UNAUTHENTICATED, details: 'Unauthorized: invalid VM auth token' });
      }
      let validatorPublicKey = '';
      try {
        validatorPublicKey = getOrInitNodeValidatorAccount(nodeName).publicKey;
      } catch (_) {}
      callback(null, {
        message: `PONG from ${nodeName} (uptime: ${Math.floor(process.uptime())}s)`,
        validator_public_key: validatorPublicKey,
        node_name: nodeName,
      });
    },

    CosignTransaction: (call, callback) => {
      if (!verifyVmAuthMetadata(call, bindAddress)) {
        return callback({ code: grpc.status.UNAUTHENTICATED, details: 'Unauthorized: invalid VM auth token' });
      }
      try {
        const reply = verifyAndCosignOnNode(nodeName, call.request || {});
        console.log(`[${nodeName} VM] ✍️ BFT Cosigned ${call.request.action} (${reply.signer_public_key.slice(0, 12)}...)`);
        callback(null, reply);
      } catch (err) {
        console.warn(`[${nodeName} VM] ⛔ CosignTransaction rejected (${call.request && call.request.action}): ${err.message}`);
        callback(null, {
          approved: false,
          error: err.message,
          node_name: nodeName,
          signer_public_key: '',
          parent_hash: '',
          signature: '',
        });
      }
    },

    ExecuteCall: (stream) => {
      if (!verifyVmAuthMetadata(stream, bindAddress)) {
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
          // 2. Host call reply from C++ Executor / Gateway -> wake up blocked WASM worker via Atomics.notify()
          if (worker && control) {
            const normalized = normalizeClientMessage(clientMsg);
            const jsonBytes = Buffer.from(JSON.stringify(normalized), 'utf8');
            if (jsonBytes.length > dataBuffer.length) {
              const errBytes = Buffer.from('IPC response exceeded SharedArrayBuffer capacity', 'utf8');
              const copyLen = Math.min(errBytes.length, dataBuffer.length);
              errBytes.copy(dataBuffer, 0, 0, copyLen);
              Atomics.store(control, 1, copyLen);
              Atomics.store(control, 0, -1);
            } else {
              jsonBytes.copy(dataBuffer, 0);
              Atomics.store(control, 1, jsonBytes.length);
              Atomics.store(control, 0, 2); // 2 = response ready
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

module.exports = {
  startVmServer,
  supercontractserver,
  verifyVmAuthMetadata,
  validateWasmFileToCall,
  getOrInitNodeValidatorAccount,
  verifyAndCosignOnNode,
};
