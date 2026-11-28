/**
 * Sirius SuperContract V2 — Production gRPC Virtual Machine Server
 * Implements `supercontractserver.SupercontractServer` (`supercontract_server.proto`)
 * for a single validator node (e.g. 127.0.0.1:5051, 5052, 5053).
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Worker } = require('worker_threads');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const { createGrpcServerCredentials } = require('./grpc_tls');

const ROOT_DIR = path.resolve(__dirname, '..');
const CLUSTER_DIR = path.join(ROOT_DIR, 'cluster');
const CONTRACTS_DIR = path.join(ROOT_DIR, 'contracts');
const PROTO_DIR = path.join(__dirname, 'proto');
const PROTO_PATH = path.join(PROTO_DIR, 'supercontract_server.proto');
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

  const keyFile = path.join(CLUSTER_DIR, nodeName, 'validator_key.json');
  if (fs.existsSync(keyFile)) {
    const data = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
    if (data && data.privateKey && /^[0-9a-fA-F]{64}$/.test(data.privateKey)) {
      const acc = sdk.Account.createFromPrivateKey(data.privateKey, networkType, 1);
      nodeValidatorCache.set(nodeName, acc);
      return acc;
    }
  }

  const isMainnet = networkType === 184 || String(process.env.SIRIUS_NETWORK || '').toLowerCase() === 'mainnet';
  const clusterSeed = (process.env.SIRIUS_CLUSTER_SEED || '').trim() || (!isMainnet ? DRIVE_KEY_HEX : '');
  let acc;
  if (clusterSeed && !process.env.SIRIUS_DISABLE_DETERMINISTIC_KEYS) {
    const derivedPriv = crypto
      .createHash('sha256')
      .update(`${clusterSeed}:sirius-clob:${networkType}:validator:${nodeName}`)
      .digest('hex')
      .toUpperCase();
    acc = sdk.Account.createFromPrivateKey(derivedPriv, networkType, 1);
  } else {
    acc = sdk.Account.generateNewAccount(networkType);
  }
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

function readNodeDriveBalances(nodeName, ownerKeyHex) {
  try {
    const balancesPath = path.join(CLUSTER_DIR, nodeName, 'data', 'drives', DRIVE_KEY_HEX, 'drive', 'markets', 'balances.json');
    if (!fs.existsSync(balancesPath)) return null;
    const raw = fs.readFileSync(balancesPath, 'utf8');
    const safeRaw = raw.replace(/:\s*(\d{10,})/g, ':"$1"');
    const data = JSON.parse(safeRaw);
    const list = Array.isArray(data.entries) ? data.entries : (Array.isArray(data.accounts) ? data.accounts : null);
    if (!list) return null;
    const norm = String(ownerKeyHex || '').toLowerCase();
    const locked = {};
    let matched = false;
    for (const e of list) {
      const pkHex = e.pubkey_hex
        ? String(e.pubkey_hex).toLowerCase()
        : Buffer.from(e.pubkey || []).toString('hex').toLowerCase();
      if (pkHex !== norm) continue;
      matched = true;
      if (e.locked && typeof e.locked === 'object') {
        Object.assign(locked, e.locked);
      } else if (e.mosaic_id !== undefined) {
        const mDec = String(e.mosaic_id);
        locked[mDec] = (BigInt(locked[mDec] || '0') + BigInt(e.locked_amount || '0')).toString();
      }
    }
    return matched ? { locked } : null;
  } catch (_) {
    return null;
  }
}

function getCanonicalL1Urls(networkType) {
  const isMainnet = Number(networkType) === 184;
  const envUrl = (process.env.SIRIUS_NODE_URL || '').trim().replace(/\/+$/, '');
  const defaults = isMainnet
    ? ['https://betelgeuse.xpxsirius.io', 'https://arcturus.xpxsirius.io', 'https://aldebaran.xpxsirius.io']
    : ['https://api-2.testnet2.xpxsirius.io', 'https://api-1.testnet2.xpxsirius.io'];
  return Array.from(new Set([envUrl, ...defaults].filter(Boolean)));
}

async function fetchSiriusL1Mosaics(publicKeyHex, networkType) {
  const sdk = getXpxSdk();
  const addr = sdk.Address.createFromPublicKey(String(publicKeyHex), Number(networkType)).plain();
  const urls = getCanonicalL1Urls(networkType);
  let lastErr = null;
  for (const baseUrl of urls) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3500);
    try {
      const res = await fetch(`${baseUrl}/account/${addr}`, { signal: controller.signal });
      clearTimeout(timer);
      if (res.status === 404) {
        return new Map();
      }
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const json = await res.json();
      const map = new Map();
      const mosaics = (json && json.account && Array.isArray(json.account.mosaics)) ? json.account.mosaics : [];
      for (const m of mosaics) {
        let hex = '';
        if (Array.isArray(m.id) && m.id.length === 2) {
          const lo = (m.id[0] >>> 0).toString(16).padStart(8, '0');
          const hi = (m.id[1] >>> 0).toString(16).padStart(8, '0');
          hex = (hi + lo).toUpperCase();
        } else if (typeof m.id === 'string') {
          hex = m.id.toUpperCase().replace(/^0X/, '');
        }
        let amt = 0n;
        if (Array.isArray(m.amount) && m.amount.length === 2) {
          amt = BigInt(m.amount[0] >>> 0) + (BigInt(m.amount[1] >>> 0) << 32n);
        } else if (m.amount !== undefined) {
          amt = BigInt(m.amount);
        }
        if (hex) map.set(hex, amt);
      }
      return map;
    } catch (err) {
      clearTimeout(timer);
      lastErr = err;
    }
  }
  throw new Error(`L1 verification failed for ${addr}: ${lastErr ? lastErr.message : 'unreachable'}`);
}

function getMosaicSpecForAsset(networkType) {
  const isMainnet = Number(networkType) === 184;
  return {
    XPX: isMainnet ? '402B2F579FAEBC59' : '13BFC518E40549D7',
    USDT: isMainnet ? '7525381A171D1E44' : '4430AEFEF7E15D0C',
    BNB: isMainnet ? '1E5C5FADEC7B34DD' : '3CC1D3CE7447B6F9',
    WASM_DEC_BY_HEX: isMainnet
      ? {
          '402B2F579FAEBC59': '992621222383397347',
          '7525381A171D1E44': '1157755757097881655',
          '1E5C5FADEC7B34DD': '2187725993354835165',
        }
      : {
          '13BFC518E40549D7': '992621222383397347',
          '4430AEFEF7E15D0C': '1157755757097881655',
          '3CC1D3CE7447B6F9': '2187725993354835165',
        },
  };
}

function parseDecimalToBigIntValidator(valStr, decimals) {
  const clean = String(valStr ?? '').trim();
  if (!clean || clean.length > 40 || !/^\d+(\.\d+)?$/.test(clean)) {
    throw new Error(`Security rejection: invalid decimal value '${clean.slice(0, 32)}'`);
  }
  const [intPart, fracPart = ''] = clean.split('.');
  const paddedFrac = (fracPart + '0'.repeat(decimals)).slice(0, decimals);
  return BigInt(intPart + paddedFrac);
}

// Per-node persistent cumulative order-outflow tracker to block split-settlement replay/over-drain
const validatorOrderOutflowCaches = new Map();
// Per-node persistent tradingPub -> ownerPub ownership registry (blocks compromised-Gateway cross-account hijacking)
const validatorOwnerRegistryCaches = new Map();
// Per-node cosign serialization queue (prevents concurrent TOCTOU races on outflows & ownership checks)
const nodeCosignQueues = new Map();

function withNodeCosignLock(nodeName, fn) {
  const prev = nodeCosignQueues.get(nodeName) || Promise.resolve();
  const next = prev.then(fn, fn);
  nodeCosignQueues.set(nodeName, next.catch(() => {}));
  return next;
}

function getValidatorOwnerRegistryFile(nodeName) {
  return path.join(CLUSTER_DIR, nodeName, 'trading_account_owners.json');
}

function loadValidatorOwnerRegistry(nodeName) {
  if (validatorOwnerRegistryCaches.has(nodeName)) {
    return validatorOwnerRegistryCaches.get(nodeName);
  }
  const map = new Map();
  const fp = getValidatorOwnerRegistryFile(nodeName);
  try {
    if (fs.existsSync(fp)) {
      const raw = JSON.parse(fs.readFileSync(fp, 'utf8'));
      if (raw && typeof raw === 'object') {
        for (const [k, v] of Object.entries(raw)) {
          if (typeof v === 'string' && /^[0-9A-Fa-f]{64}$/.test(k) && /^[0-9A-Fa-f]{64}$/.test(v)) {
            map.set(k.toUpperCase(), v.toUpperCase());
          }
        }
      }
    }
  } catch (_) {}
  validatorOwnerRegistryCaches.set(nodeName, map);
  return map;
}

function saveValidatorOwnerRegistry(nodeName, map) {
  try {
    const obj = {};
    for (const [k, v] of map.entries()) {
      obj[k] = v;
    }
    const fp = getValidatorOwnerRegistryFile(nodeName);
    fs.mkdirSync(path.dirname(fp), { recursive: true, mode: 0o700 });
    const tmp = `${fp}.tmp.${process.pid}.${Date.now()}`;
    fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, fp);
  } catch (_) {}
}

/**
 * Cryptographically verifies on the Validator Node itself that `tradingPub` is genuinely owned
 * by `claimedOwnerPub` (prevents a compromised Gateway from mapping a victim's tradingPub to an
 * attacker's ownerPub on SETTLEMENT or WITHDRAWAL).
 */
async function verifyTradingAccountOwnershipOnNode(nodeName, tradingPub, claimedOwnerPub, networkType) {
  const tPub = String(tradingPub || '').trim().toUpperCase();
  const oPub = String(claimedOwnerPub || '').trim().toUpperCase();
  if (!/^[0-9A-F]{64}$/.test(tPub) || !/^[0-9A-F]{64}$/.test(oPub)) {
    throw new Error(`Security rejection on ${nodeName}: invalid tradingPub or ownerPub for ownership verification`);
  }
  if (tPub === oPub) {
    throw new Error(`Security rejection on ${nodeName}: trading account public key cannot equal owner public key`);
  }

  const registry = loadValidatorOwnerRegistry(nodeName);
  const existingOwner = registry.get(tPub);
  if (existingOwner) {
    if (existingOwner !== oPub) {
      throw new Error(
        `Security rejection on ${nodeName}: Trading Account ${tPub.slice(0, 12)}... is bound to a different owner (${existingOwner.slice(0, 12)}... != ${oPub.slice(0, 12)}...)`
      );
    }
    return true;
  }

  // Not yet in local node cache -> independently verify directly on Sirius L1!
  const sdk = getXpxSdk();
  const { Address } = sdk;
  const tradingAddr = Address.createFromPublicKey(tPub, Number(networkType)).plain().replace(/[- ]/g, '').toUpperCase();
  const nodes = getCanonicalL1Urls(networkType);
  let anyNodeResponded = false;

  for (const baseUrl of nodes) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      const msRes = await fetch(`${baseUrl}/account/${tradingAddr}/multisig`, { signal: controller.signal });
      clearTimeout(timer);
      if (msRes.status === 404) {
        anyNodeResponded = true;
        break;
      }
      if (!msRes.ok) continue;
      anyNodeResponded = true;
      const msJson = await msRes.json();
      const ms = msJson && msJson.multisig;
      const cosigs = Array.isArray(ms && ms.cosignatories) ? ms.cosignatories.map((c) => String(c).toUpperCase()) : [];

      // Case A: Legacy 2-of-2 Trading Account -> ownerPub MUST be an on-chain L1 cosignatory!
      if (ms && Number(ms.minApproval) >= 2) {
        if (cosigs.includes(oPub)) {
          registry.set(tPub, oPub);
          saveValidatorOwnerRegistry(nodeName, registry);
          return true;
        }
        throw new Error(
          `Security rejection on ${nodeName}: claimed owner ${oPub.slice(0, 12)}... is NOT a cosignatory of 2-of-2 Trading Account ${tPub.slice(0, 12)}... on Sirius L1`
        );
      }

      // Case B: Instant BFT Trading Account (minApproval === 1) -> verify L1 activation tx containing
      // 0-mosaic Transfer signed by claimedOwnerPub with message "SiriusCLOB:ACTIVATE_BFT:<claimedOwnerPub>"!
      if (ms && Number(ms.minApproval) === 1) {
        const expectedMemoHex = Buffer.from(`SiriusCLOB:ACTIVATE_BFT:${oPub}`, 'utf8').toString('hex').toUpperCase();
        const txCtrl = new AbortController();
        const txTimer = setTimeout(() => txCtrl.abort(), 5000);
        try {
          const txRes = await fetch(`${baseUrl}/account/${tradingAddr}/transactions/confirmed?pageSize=25`, { signal: txCtrl.signal });
          clearTimeout(txTimer);
          if (txRes.ok) {
            const txList = await txRes.json();
            const items = Array.isArray(txList) ? txList : (Array.isArray(txList && txList.data) ? txList.data : []);
            for (const item of items) {
              const outer = item && item.transaction;
              if (!outer || String(outer.signer || '').toUpperCase() !== oPub) continue;
              const inners = Array.isArray(outer.transactions) ? outer.transactions : [];
              for (const innWrap of inners) {
                const inn = innWrap && innWrap.transaction;
                if (!inn || String(inn.signer || '').toUpperCase() !== oPub) continue;
                const payloadHex = String((inn.message && inn.message.payload) || '').toUpperCase();
                if (payloadHex === expectedMemoHex) {
                  registry.set(tPub, oPub);
                  saveValidatorOwnerRegistry(nodeName, registry);
                  return true;
                }
              }
            }
          }
        } catch (_) {
          clearTimeout(txTimer);
        }
        throw new Error(
          `Security rejection on ${nodeName}: no Sirius L1 Instant BFT ownership proof found for Trading Account ${tPub.slice(0, 12)}... -> owner ${oPub.slice(0, 12)}...`
        );
      }
      break;
    } catch (err) {
      clearTimeout(timer);
      if (err && /Security rejection/.test(err.message)) throw err;
    }
  }

  if (!anyNodeResponded && process.env.SIRIUS_VALIDATOR_OFFLINE_FALLBACK === 'true') {
    return true;
  }
  throw new Error(
    `Security rejection on ${nodeName}: unable to verify ownership of Trading Account ${tPub.slice(0, 12)}... for owner ${oPub.slice(0, 12)}...`
  );
}

function getValidatorOutflowFile(nodeName) {
  return path.join(CLUSTER_DIR, nodeName, 'cosigned_order_outflows.json');
}

function loadValidatorOrderOutflows(nodeName) {
  if (validatorOrderOutflowCaches.has(nodeName)) {
    return validatorOrderOutflowCaches.get(nodeName);
  }
  const map = new Map();
  const fp = getValidatorOutflowFile(nodeName);
  try {
    if (fs.existsSync(fp)) {
      const raw = JSON.parse(fs.readFileSync(fp, 'utf8'));
      if (raw && typeof raw === 'object') {
        for (const [k, v] of Object.entries(raw)) {
          if (v && typeof v === 'object') {
            map.set(k, {
              outXpx: BigInt(v.outXpx || '0'),
              outQuote: BigInt(v.outQuote || '0'),
              settlementIds: new Set(Array.isArray(v.settlementIds) ? v.settlementIds : []),
              updatedAt: Number(v.updatedAt || 0),
            });
          }
        }
      }
    }
  } catch (_) {}
  validatorOrderOutflowCaches.set(nodeName, map);
  return map;
}

function saveValidatorOrderOutflows(nodeName, map) {
  try {
    // Prune entries older than 7 days to keep file compact
    const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
    const obj = {};
    for (const [k, v] of map.entries()) {
      if (v.updatedAt && v.updatedAt < cutoff) continue;
      obj[k] = {
        outXpx: v.outXpx.toString(),
        outQuote: v.outQuote.toString(),
        settlementIds: Array.from(v.settlementIds).slice(-50),
        updatedAt: v.updatedAt || Date.now(),
      };
    }
    const fp = getValidatorOutflowFile(nodeName);
    fs.mkdirSync(path.dirname(fp), { recursive: true, mode: 0o700 });
    const tmp = `${fp}.tmp.${process.pid}.${Date.now()}`;
    fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, fp);
  } catch (_) {}
}

function verifySingleSignedOrderContext(nodeName, expectedSignerPub, ctx, networkType) {
  if (!ctx || !ctx.signature) {
    throw new Error(`Security rejection on ${nodeName}: missing signed orderContext for SETTLEMENT`);
  }
  const sigHex = String(ctx.signature || '').trim();
  if (!/^[0-9a-fA-F]{128}$/.test(sigHex)) {
    throw new Error(`Security rejection on ${nodeName}: malformed orderContext signature`);
  }
  const sdk = getXpxSdk();
  const { KeyPair, DerivationScheme } = sdk;
  const signerPub = String(ctx.publicKey || expectedSignerPub || '').toUpperCase();
  if (!signerPub || !/^[0-9A-F]{64}$/.test(signerPub)) {
    throw new Error(`Security rejection on ${nodeName}: invalid orderContext publicKey`);
  }
  if (expectedSignerPub && signerPub !== expectedSignerPub.toUpperCase()) {
    throw new Error(`Security rejection on ${nodeName}: orderContext publicKey ${signerPub} does not match expected owner ${expectedSignerPub}`);
  }
  const domainSep = `${networkType}:SiriusCLOB-v1`;
  const normPair = String(ctx.pair || 'XPX/USDT').trim().toUpperCase().replace('_', '/');
  if (!/^XPX\/(USDT|BNB)$/.test(normPair)) {
    throw new Error(`Security rejection on ${nodeName}: unsupported orderContext pair '${normPair}'`);
  }
  const normSide = String(ctx.side || '').toLowerCase() === 'sell' ? 'sell' : 'buy';
  const normType = String(ctx.type || '') === 'PostOnly' ? 'PostOnly' : (String(ctx.type || '') === 'Market' ? 'Market' : 'Limit');
  const msg = `${domainSep}:ORDER:${normPair}:${normSide}:${normType}:${String(ctx.price)}:${String(ctx.amount)}:${ctx.nonce}:${ctx.expiry}`;

  const sigValid = KeyPair.verify(
    Buffer.from(signerPub, 'hex'),
    Buffer.from(msg, 'utf8'),
    Buffer.from(sigHex, 'hex'),
    DerivationScheme.Ed25519Sha3
  );
  if (!sigValid) {
    throw new Error(`Security rejection on ${nodeName}: forged or invalid user order signature in settlement`);
  }
  const orderAmtAtomic = parseDecimalToBigIntValidator(ctx.amount, 6);
  if (orderAmtAtomic <= 0n) {
    throw new Error(`Security rejection on ${nodeName}: orderContext amount must be > 0`);
  }
  const limitPriceTicks = parseDecimalToBigIntValidator(ctx.price, 8);
  const fingerprint = `${signerPub}:${String(ctx.nonce)}:${sigHex.slice(0, 16)}`;
  return { signerPub, normPair, normSide, normType, orderAmtAtomic, limitPriceTicks, fingerprint };
}

function verifySingleParticipantSettlement(nodeName, tx, expectedSignerPub, participantTradingPub, ctx, networkType, settlementId, outflowMap) {
  const primary = verifySingleSignedOrderContext(nodeName, expectedSignerPub, ctx, networkType);
  const verifiedOrders = [primary];

  // Support multi-order sweeps from the same Maker (every additional order MUST pass full Ed25519 verification)
  if (Array.isArray(ctx.additionalOrderContexts)) {
    const seenFp = new Set([primary.fingerprint]);
    for (const extraCtx of ctx.additionalOrderContexts.slice(0, 16)) {
      if (!extraCtx || !extraCtx.signature) continue;
      const v = verifySingleSignedOrderContext(nodeName, primary.signerPub, extraCtx, networkType);
      if (v.normPair !== primary.normPair || v.normSide !== primary.normSide) continue;
      if (seenFp.has(v.fingerprint)) continue;
      seenFp.add(v.fingerprint);
      verifiedOrders.push(v);
    }
  }

  const sdk = getXpxSdk();
  const { Address } = sdk;
  const { normPair, normSide } = primary;
  const tradingPubUpper = String(participantTradingPub || '').toUpperCase();
  const tradingAddr = Address.createFromPublicKey(tradingPubUpper, Number(networkType)).plain().replace(/[- ]/g, '').toUpperCase();
  const specs = getMosaicSpecForAsset(networkType);
  const xpxHex = specs.XPX;
  const quoteSym = normPair.endsWith('/BNB') ? 'BNB' : 'USDT';
  const quoteHex = quoteSym === 'BNB' ? specs.BNB : specs.USDT;

  const outByHex = new Map();
  const inByHex = new Map();
  for (const inner of tx.innerTransactions) {
    const sPub = inner.signer ? inner.signer.publicKey.toUpperCase() : '';
    const recipObj = inner.recipient || inner.recipientAddress;
    const rAddr = recipObj && typeof recipObj.plain === 'function' ? recipObj.plain().replace(/[- ]/g, '').toUpperCase() : '';
    if (sPub === tradingPubUpper && rAddr === tradingAddr) {
      throw new Error(`Security rejection on ${nodeName}: refused self-transfer loop on Trading Account ${tradingPubUpper}`);
    }
    for (const m of (inner.mosaics || [])) {
      const mHex = m.id.toHex().toUpperCase();
      const amt = m.amount && typeof m.amount.toHex === 'function'
        ? BigInt('0x' + m.amount.toHex())
        : BigInt(m.amount.compact ? m.amount.compact() : m.amount);
      if (amt <= 0n) {
        throw new Error(`Security rejection on ${nodeName}: settlement transfer mosaic amount must be > 0`);
      }
      if (sPub === tradingPubUpper) outByHex.set(mHex, (outByHex.get(mHex) || 0n) + amt);
      if (rAddr === tradingAddr) inByHex.set(mHex, (inByHex.get(mHex) || 0n) + amt);
    }
  }

  const PRICE_SCALE = 100_000_000n;
  const outXpx = outByHex.get(xpxHex) || 0n;
  const outQuote = outByHex.get(quoteHex) || 0n;
  const inXpx = inByHex.get(xpxHex) || 0n;
  const inQuote = inByHex.get(quoteHex) || 0n;

  for (const [hex] of outByHex.entries()) {
    if (hex !== xpxHex && hex !== quoteHex) {
      throw new Error(`Security rejection on ${nodeName}: unexpected mosaic ${hex} leaving Trading Account`);
    }
  }

  const updates = [];
  if (normSide === 'buy') {
    if (outXpx > 0n) {
      throw new Error(`Security rejection on ${nodeName}: BUY settlement cannot send XPX out of Trading Account`);
    }
    let totalAvailQuoteCap = 0n;
    let maxAllowedPriceTicks = 0n;
    let remQuoteToAlloc = outQuote;
    for (const vo of verifiedOrders) {
      const maxQuoteBase = (vo.orderAmtAtomic * vo.limitPriceTicks + PRICE_SCALE - 1n) / PRICE_SCALE;
      const maxQuoteWithFee = (maxQuoteBase * 102n) / 100n + 1000n;
      const prevAcc = outflowMap ? outflowMap.get(vo.fingerprint) : null;
      const alreadyCounted = Boolean(settlementId && prevAcc && prevAcc.settlementIds.has(String(settlementId)));
      const usedQuote = (prevAcc && !alreadyCounted) ? prevAcc.outQuote : 0n;
      const avail = maxQuoteWithFee > usedQuote ? maxQuoteWithFee - usedQuote : 0n;
      totalAvailQuoteCap += avail;
      if (vo.limitPriceTicks > maxAllowedPriceTicks) maxAllowedPriceTicks = vo.limitPriceTicks;
      if (remQuoteToAlloc > 0n && avail > 0n) {
        const take = remQuoteToAlloc < avail ? remQuoteToAlloc : avail;
        updates.push({ fingerprint: vo.fingerprint, outXpx: 0n, outQuote: take });
        remQuoteToAlloc -= take;
      }
    }
    if (outQuote > totalAvailQuoteCap) {
      throw new Error(`Security rejection on ${nodeName}: BUY quote outflow ${outQuote} exceeds signed limit ${totalAvailQuoteCap}`);
    }
    if (outQuote > 0n && inXpx === 0n) {
      throw new Error(`Security rejection on ${nodeName}: BUY settlement sends quote without delivering XPX`);
    }
    if (inXpx > 0n && outQuote > 0n) {
      const maxCostForFill = ((inXpx * maxAllowedPriceTicks + PRICE_SCALE - 1n) / PRICE_SCALE) * 102n / 100n + 1000n;
      if (outQuote > maxCostForFill) {
        throw new Error(`Security rejection on ${nodeName}: BUY execution cost ${outQuote} exceeds signed limit price`);
      }
    }
  } else {
    if (outQuote > 0n) {
      throw new Error(`Security rejection on ${nodeName}: SELL settlement cannot send quote out of Trading Account`);
    }
    let totalAvailXpxCap = 0n;
    let minAllowedPriceTicks = null;
    let remXpxToAlloc = outXpx;
    for (const vo of verifiedOrders) {
      const maxXpxWithFee = (vo.orderAmtAtomic * 102n) / 100n + 1000n;
      const prevAcc = outflowMap ? outflowMap.get(vo.fingerprint) : null;
      const alreadyCounted = Boolean(settlementId && prevAcc && prevAcc.settlementIds.has(String(settlementId)));
      const usedXpx = (prevAcc && !alreadyCounted) ? prevAcc.outXpx : 0n;
      const avail = maxXpxWithFee > usedXpx ? maxXpxWithFee - usedXpx : 0n;
      totalAvailXpxCap += avail;
      if (minAllowedPriceTicks === null || vo.limitPriceTicks < minAllowedPriceTicks) {
        minAllowedPriceTicks = vo.limitPriceTicks;
      }
      if (remXpxToAlloc > 0n && avail > 0n) {
        const take = remXpxToAlloc < avail ? remXpxToAlloc : avail;
        updates.push({ fingerprint: vo.fingerprint, outXpx: take, outQuote: 0n });
        remXpxToAlloc -= take;
      }
    }
    if (outXpx > totalAvailXpxCap) {
      throw new Error(`Security rejection on ${nodeName}: SELL XPX outflow ${outXpx} exceeds signed amount ${totalAvailXpxCap}`);
    }
    if (outXpx > 0n && inQuote === 0n) {
      throw new Error(`Security rejection on ${nodeName}: SELL settlement sends XPX without delivering ${quoteSym}`);
    }
    if (outXpx > 0n && minAllowedPriceTicks && minAllowedPriceTicks > 0n) {
      const expectedQuoteRaw = (outXpx * minAllowedPriceTicks) / PRICE_SCALE;
      if (expectedQuoteRaw >= 100n && inQuote < (expectedQuoteRaw * 97n) / 100n) {
        throw new Error(`Security rejection on ${nodeName}: SELL quote received ${inQuote} below signed limit floor`);
      }
    }
  }

  return updates;
}

async function verifySettlementAgainstOrderContext(nodeName, tx, callerPub, tradingPub, metadata, networkType) {
  if (!tradingPub || !/^[0-9A-F]{64}$/.test(tradingPub)) {
    throw new Error(`Security rejection on ${nodeName}: missing or invalid trading_account_public_key for SETTLEMENT`);
  }
  const rootCtx = metadata && metadata.orderContext;
  if (!rootCtx || !rootCtx.signature) {
    throw new Error(`Security rejection on ${nodeName}: missing signed orderContext for SETTLEMENT`);
  }

  const settlementId = metadata && metadata.settlementId ? String(metadata.settlementId) : '';
  const outflowMap = loadValidatorOrderOutflows(nodeName);
  const verifiedUpdates = [];

  // 1. Always verify primary participant (Taker / callerPub) order signature & flows, then bind-check ownership on node/L1
  verifiedUpdates.push(
    ...verifySingleParticipantSettlement(nodeName, tx, callerPub, tradingPub, rootCtx, networkType, settlementId, outflowMap)
  );
  // CRITICAL: Independently verify on the Validator Node that tradingPub belongs to callerPub
  await verifyTradingAccountOwnershipOnNode(nodeName, tradingPub, callerPub, networkType);

  // 2. Multi-participant BFT Zero-Trust Verification (Option 1 Instant DEX + P2P):
  // Independently verify EVERY OTHER non-Vault Trading Account that has an outflow in this aggregate!
  const vaultPubUpper = String((metadata && metadata.vaultPublicKey) || '').toUpperCase();
  const tradingToOwner = (metadata && metadata.participantTradingMap && typeof metadata.participantTradingMap === 'object')
    ? metadata.participantTradingMap
    : {};
  const pContexts = (rootCtx && rootCtx.participantContexts && typeof rootCtx.participantContexts === 'object')
    ? rootCtx.participantContexts
    : {};

  const outgoingSigners = new Set();
  for (const inner of tx.innerTransactions) {
    const sPub = inner.signer ? inner.signer.publicKey.toUpperCase() : '';
    if (sPub && sPub !== tradingPub.toUpperCase() && (!vaultPubUpper || sPub !== vaultPubUpper)) {
      outgoingSigners.add(sPub);
    }
  }

  for (const otherTradingPub of outgoingSigners) {
    const ownerPub = String(
      tradingToOwner[otherTradingPub] ||
      tradingToOwner[otherTradingPub.toLowerCase()] ||
      ''
    ).toUpperCase();
    const otherCtx = ownerPub
      ? (pContexts[ownerPub.toLowerCase()] || pContexts[ownerPub] || null)
      : null;
    if (!ownerPub || !otherCtx) {
      if (
        (metadata && metadata.requireAllParticipantsVerified) ||
        Object.keys(tradingToOwner).length > 0
      ) {
        throw new Error(
          `Security rejection on ${nodeName}: missing signed participantContext for outgoing Trading Account ${otherTradingPub.slice(0, 12)}...`
        );
      }
      continue;
    }
    // CRITICAL: Independently verify on the Validator Node that otherTradingPub belongs to ownerPub!
    await verifyTradingAccountOwnershipOnNode(nodeName, otherTradingPub, ownerPub, networkType);
    verifiedUpdates.push(
      ...verifySingleParticipantSettlement(nodeName, tx, ownerPub, otherTradingPub, otherCtx, networkType, settlementId, outflowMap)
    );
  }

  return { outflowMap, verifiedUpdates, settlementId };
}

async function verifyAndCosignOnNode(nodeName, req) {
  return withNodeCosignLock(nodeName, () => _verifyAndCosignOnNodeUnlocked(nodeName, req));
}

async function _verifyAndCosignOnNodeUnlocked(nodeName, req) {
  const sdk = getXpxSdk();
  const {
    Address,
    TransactionMapping,
    TransactionType,
    CosignatureTransaction,
  } = sdk;

  const action = String(req.action || '').trim().toUpperCase();
  const payloadHex = String(req.aggregate_payload_hex || '').trim();
  const generationHash = String(req.generation_hash || '').trim();
  const callerPub = String(req.caller_public_key || '').trim().toUpperCase();
  const tradingPub = String(req.trading_account_public_key || '').trim().toUpperCase();
  const envClusterPub = String(process.env.SIRIUS_VALIDATOR_CLUSTER_PUBKEY || '').trim().toUpperCase();
  const reqClusterPub = String(req.validator_cluster_public_key || '').trim().toUpperCase();
  if (envClusterPub && reqClusterPub && envClusterPub !== reqClusterPub) {
    throw new Error(`Security rejection on ${nodeName}: validator_cluster_public_key mismatch against node configuration`);
  }
  const clusterPub = envClusterPub || reqClusterPub;
  const activeNetType = Number(process.env.SIRIUS_NETWORK_TYPE || (String(process.env.SIRIUS_NETWORK || '').toLowerCase() === 'mainnet' ? 184 : 168));

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
  // Catapult binary wire header: 4B size (0..8) + 64B signature (8..136) + 32B outer signer pubkey (136..200)
  const outerSignerPub = (tx.signer && tx.signer.publicKey)
    ? String(tx.signer.publicKey).toUpperCase()
    : (payloadHex.length >= 200 && /^[0-9a-fA-F]+$/.test(payloadHex.slice(136, 200))
      ? payloadHex.slice(136, 200).toUpperCase()
      : '');

  let pendingSettlementOutflowCommit = null;
  let pendingOwnerBindingCommit = null;

  if (action === 'ACTIVATE_TRADING_ACCOUNT') {
    if (!/^[0-9A-F]{64}$/.test(callerPub) || !/^[0-9A-F]{64}$/.test(tradingPub) || callerPub === tradingPub) {
      throw new Error(`Security rejection on ${nodeName}: invalid or identical caller_public_key / trading_account_public_key`);
    }
    const existingOwner = loadValidatorOwnerRegistry(nodeName).get(tradingPub);
    if (existingOwner && existingOwner !== callerPub) {
      throw new Error(`Security rejection on ${nodeName}: Trading Account ${tradingPub.slice(0, 12)}... is already bound to a different owner`);
    }
    if (tx.innerTransactions.length < 1 || tx.innerTransactions.length > 2) {
      throw new Error(`ACTIVATE_TRADING_ACCOUNT must contain 1 or 2 inner transactions (got ${tx.innerTransactions.length})`);
    }
    const modTxs = tx.innerTransactions.filter((it) => it.type === TransactionType.MODIFY_MULTISIG_ACCOUNT);
    const otherTxs = tx.innerTransactions.filter((it) => it.type !== TransactionType.MODIFY_MULTISIG_ACCOUNT);
    if (modTxs.length !== 1) {
      throw new Error(`ACTIVATE_TRADING_ACCOUNT must contain strictly 1 MODIFY_MULTISIG_ACCOUNT (got ${modTxs.length})`);
    }
    const inner = modTxs[0];
    if (!inner.signer || inner.signer.publicKey.toUpperCase() !== tradingPub) {
      throw new Error('ModifyMultisigAccount signer does not match trading_account_public_key');
    }
    const modPks = (inner.modifications || []).map((m) => {
      if (m.type !== 0) {
        throw new Error('Security rejection: Only Add cosignatory modifications are permitted during activation');
      }
      return m.cosignatoryPublicAccount.publicKey.toUpperCase();
    });

    const isInstantBftMode = inner.minApprovalDelta === 1 && inner.minRemovalDelta === 1 && modPks.length === 1;
    const isTwoOfTwoMode = inner.minApprovalDelta === 2 && inner.minRemovalDelta === 2 && modPks.length === 2;
    if (!isInstantBftMode && !isTwoOfTwoMode) {
      throw new Error(
        `Security rejection: unsupported activation thresholds (${inner.minApprovalDelta}/${inner.minRemovalDelta}, cosigs=${modPks.length})`
      );
    }
    if (isInstantBftMode) {
      if (!clusterPub || !modPks.includes(clusterPub)) {
        throw new Error('Security rejection: Instant BFT Trading Account cosignatory must strictly be [ValidatorClusterPublicKey]');
      }
      if (!outerSignerPub || outerSignerPub !== callerPub) {
        throw new Error('Security rejection: Instant BFT activation outer initiator must be caller_public_key');
      }
      if (otherTxs.length !== 1) {
        throw new Error('Security rejection: Instant BFT activation must include 1 owner authorization anchor transfer');
      }
      const expectedTradingAddr = Address.createFromPublicKey(tradingPub, activeNetType).plain().replace(/[- ]/g, '').toUpperCase();
      const expectedAnchorMemo = `SiriusCLOB:ACTIVATE_BFT:${callerPub}`;
      // Require 0-mosaic Transfer signed by callerPub -> tradingPub with exact ACTIVATE_BFT memo to prove Owner authorization on L1
      for (const anchor of otherTxs) {
        if (anchor.type !== TransactionType.TRANSFER) {
          throw new Error(`Security rejection: unexpected inner tx type ${anchor.type} in Instant BFT activation`);
        }
        if (!anchor.signer || anchor.signer.publicKey.toUpperCase() !== callerPub) {
          throw new Error('Security rejection: Instant BFT activation anchor must be signed by caller_public_key');
        }
        if (Array.isArray(anchor.mosaics) && anchor.mosaics.length > 0) {
          throw new Error('Security rejection: Instant BFT activation anchor transfer must carry 0 mosaics');
        }
        const aRecip = anchor.recipient || anchor.recipientAddress;
        const aRecipAddr = aRecip && typeof aRecip.plain === 'function' ? aRecip.plain().replace(/[- ]/g, '').toUpperCase() : '';
        if (aRecipAddr !== expectedTradingAddr) {
          throw new Error('Security rejection: Instant BFT activation anchor recipient must be trading_account address');
        }
        const aMsgText = String((anchor.message && anchor.message.message) || '');
        const aMsgPayload = String((anchor.message && anchor.message.payload) || '').toUpperCase();
        const expectedAnchorMemoHex = Buffer.from(expectedAnchorMemo, 'utf8').toString('hex').toUpperCase();
        if (aMsgText !== expectedAnchorMemo && aMsgPayload !== expectedAnchorMemoHex) {
          throw new Error('Security rejection: Instant BFT activation anchor memo must strictly be SiriusCLOB:ACTIVATE_BFT:<callerPub>');
        }
      }
    } else {
      if (otherTxs.length > 0) {
        throw new Error('Security rejection: 2-of-2 activation must contain strictly 1 ModifyMultisigAccountTransaction');
      }
      if (!modPks.includes(callerPub) || !clusterPub || !modPks.includes(clusterPub)) {
        throw new Error('Security rejection: Modifications must strictly include [UserMainPublicKey, ValidatorClusterPublicKey]');
      }
    }
    pendingOwnerBindingCommit = { tradingPub, ownerPub: callerPub };
  } else if (action === 'WITHDRAWAL') {
    if (!tradingPub || !callerPub) {
      throw new Error('Missing caller_public_key or trading_account_public_key for WITHDRAWAL');
    }
    const expectedRecipientRaw = String(metadata.recipientAddress || '').replace(/[- ]/g, '').toUpperCase();
    if (!expectedRecipientRaw) {
      throw new Error(`Security rejection on ${nodeName}: missing recipientAddress in WITHDRAWAL metadata`);
    }
    const maxFreeAtomic = metadata.maxWithdrawableAtomic ? BigInt(metadata.maxWithdrawableAtomic) : null;
    const networkType = activeNetType;
    // Security: NEVER trust Gateway-supplied feeCollectorAddress; only accept node-configured FEE_COLLECTOR_ADDRESS
    const feeCollectorAddr = String(process.env.FEE_COLLECTOR_ADDRESS || '').replace(/[- ]/g, '').toUpperCase();
    let totalOutgoingByMosaic = new Map();

    for (const inner of tx.innerTransactions) {
      if (inner.type !== TransactionType.TRANSFER) {
        throw new Error(`Security rejection: WITHDRAWAL aggregate may ONLY contain TRANSFER transactions (got ${inner.type})`);
      }
      const sPub = inner.signer ? inner.signer.publicKey.toUpperCase() : '';
      const innerMosaics = Array.isArray(inner.mosaics) ? inner.mosaics : [];
      // Allow an optional 0-mosaic authorization anchor signed by callerPub (required by Catapult for minApproval=1 outer initiator)
      if (sPub === callerPub && innerMosaics.length === 0) {
        continue;
      }
      if (sPub !== tradingPub) {
        throw new Error('Security rejection: All withdrawal transfers must originate from trading_account_public_key');
      }
      const recipObj = inner.recipient || inner.recipientAddress;
      const recipAddr = recipObj && typeof recipObj.plain === 'function' ? recipObj.plain().replace(/[- ]/g, '').toUpperCase() : '';
      if (!recipAddr || (recipAddr !== expectedRecipientRaw && (!feeCollectorAddr || recipAddr !== feeCollectorAddr))) {
        throw new Error(`Security rejection: Transfer recipient ${recipAddr} does not match approved recipient ${expectedRecipientRaw}`);
      }
      for (const m of innerMosaics) {
        const mHex = m.id.toHex().toUpperCase();
        const amt = BigInt(m.amount.compact ? m.amount.compact() : m.amount);
        if (amt <= 0n) {
          throw new Error(`Security rejection on ${nodeName}: withdrawal mosaic amount must be > 0`);
        }
        totalOutgoingByMosaic.set(mHex, (totalOutgoingByMosaic.get(mHex) || 0n) + amt);
      }
    }

    const checks = Array.isArray(metadata.mosaics) && metadata.mosaics.length > 0
      ? metadata.mosaics
      : (metadata.mosaicHex
        ? [{
            mosaicHex: metadata.mosaicHex,
            maxWithdrawableAtomic: metadata.maxWithdrawableAtomic,
            onChainBalanceAtomic: metadata.onChainBalanceAtomic,
            mosaicIdDecimal: metadata.mosaicIdDecimal,
            requestedAmountAtomic: metadata.requestedAmountAtomic,
          }]
        : []);

    const approvedHexSet = new Set(checks.map((c) => String(c.mosaicHex || '').toUpperCase()).filter(Boolean));
    if (approvedHexSet.size === 0) {
      throw new Error(`Security rejection on ${nodeName}: missing approved mosaic list in WITHDRAWAL metadata`);
    }
    if (!outerSignerPub || outerSignerPub !== callerPub) {
      throw new Error(`Security rejection on ${nodeName}: WITHDRAWAL outer initiator must strictly be caller_public_key`);
    }
    if (totalOutgoingByMosaic.size === 0) {
      throw new Error(`Security rejection on ${nodeName}: WITHDRAWAL must transfer at least one mosaic from trading_account_public_key`);
    }
    // CRITICAL: Independently verify on the Validator Node that tradingPub belongs to callerPub!
    await verifyTradingAccountOwnershipOnNode(nodeName, tradingPub, callerPub, networkType);
    for (const [mKey] of totalOutgoingByMosaic.entries()) {
      if (!approvedHexSet.has(mKey)) {
        throw new Error(`Security rejection on ${nodeName}: unapproved mosaic ${mKey} in withdrawal`);
      }
    }

    const specs = getMosaicSpecForAsset(networkType);
    let l1Mosaics = null;
    try {
      l1Mosaics = await fetchSiriusL1Mosaics(tradingPub, networkType);
    } catch (l1Err) {
      if (process.env.SIRIUS_VALIDATOR_OFFLINE_FALLBACK !== 'true') {
        throw new Error(`Security rejection on ${nodeName}: ${l1Err.message}`);
      }
    }

    const driveAcc = readNodeDriveBalances(nodeName, callerPub);
    for (const [mKey, outAmt] of totalOutgoingByMosaic.entries()) {
      const checkItem = checks.find((c) => String(c.mosaicHex || '').toUpperCase() === mKey);
      if (l1Mosaics) {
        const l1OnChain = l1Mosaics.get(mKey) || 0n;
        const wasmDec = specs.WASM_DEC_BY_HEX[mKey] || (checkItem && checkItem.mosaicIdDecimal ? String(checkItem.mosaicIdDecimal) : '');
        const lockedInDrive = (driveAcc && wasmDec) ? BigInt((driveAcc.locked && driveAcc.locked[wasmDec]) || '0') : 0n;
        const validatorFree = l1OnChain > lockedInDrive ? l1OnChain - lockedInDrive : 0n;
        if (outAmt > validatorFree) {
          throw new Error(
            `L1/Drive balance check rejected on ${nodeName}: requested ${outAmt} (${mKey}) > free ${validatorFree} (L1=${l1OnChain}, locked=${lockedInDrive})`
          );
        }
      }
      if (checkItem) {
        const checkMax = checkItem.maxWithdrawableAtomic != null ? BigInt(checkItem.maxWithdrawableAtomic) : null;
        if (checkMax !== null && outAmt > checkMax) {
          throw new Error(`Security rejection on ${nodeName}: requested withdrawal ${outAmt} (${mKey}) exceeds verified free balance ${checkMax}`);
        }
      }
    }
  } else if (action === 'SETTLEMENT') {
    const allowedSigners = new Set(
      (Array.isArray(metadata.allowedSigners) ? metadata.allowedSigners : []).map((s) => String(s).toUpperCase()).filter(Boolean)
    );
    if (allowedSigners.size === 0) {
      throw new Error(`Security rejection on ${nodeName}: missing allowedSigners in SETTLEMENT metadata`);
    }
    for (const inner of tx.innerTransactions) {
      if (inner.type !== TransactionType.TRANSFER) {
        throw new Error(`Security rejection: SETTLEMENT aggregate may only contain TRANSFER transactions (got ${inner.type})`);
      }
      const signerPk = inner.signer ? inner.signer.publicKey.toUpperCase() : '';
      if (!allowedSigners.has(signerPk)) {
        throw new Error(`Security rejection: Unexpected settlement inner signer ${signerPk}`);
      }
    }
    pendingSettlementOutflowCommit = await verifySettlementAgainstOrderContext(nodeName, tx, callerPub, tradingPub, metadata, activeNetType);
  } else {
    throw new Error(`Unsupported cosign action: ${action}`);
  }

  const validatorAcc = getOrInitNodeValidatorAccount(nodeName);
  const cosig = CosignatureTransaction.signTransactionPayload(validatorAcc, payloadHex, generationHash);

  // Record verified tradingPub -> ownerPub binding ONLY AFTER all activation checks and cosigning succeeded
  if (pendingOwnerBindingCommit) {
    const registry = loadValidatorOwnerRegistry(nodeName);
    registry.set(pendingOwnerBindingCommit.tradingPub, pendingOwnerBindingCommit.ownerPub);
    saveValidatorOwnerRegistry(nodeName, registry);
  }

  // Record verified cumulative order outflows ONLY AFTER all security checks and cosigning succeeded
  if (pendingSettlementOutflowCommit && pendingSettlementOutflowCommit.verifiedUpdates.length > 0) {
    const { outflowMap, verifiedUpdates, settlementId } = pendingSettlementOutflowCommit;
    const nowTs = Date.now();
    for (const u of verifiedUpdates) {
      const cur = outflowMap.get(u.fingerprint) || { outXpx: 0n, outQuote: 0n, settlementIds: new Set(), updatedAt: nowTs };
      if (!settlementId || !cur.settlementIds.has(settlementId)) {
        cur.outXpx += u.outXpx;
        cur.outQuote += u.outQuote;
        if (settlementId) cur.settlementIds.add(settlementId);
        cur.updatedAt = nowTs;
        outflowMap.set(u.fingerprint, cur);
      }
    }
    saveValidatorOrderOutflows(nodeName, outflowMap);
  }

  return {
    approved: true,
    error: '',
    node_name: nodeName,
    signer_public_key: cosig.signer,
    parent_hash: cosig.parentHash,
    signature: cosig.signature,
  };
}

function verifyVmAuthMetadata(callOrStream) {
  const expectedToken = (process.env.SIRIUS_VM_AUTH_TOKEN || '').trim();
  const isMainnet =
    String(process.env.SIRIUS_NETWORK || '').toLowerCase() === 'mainnet' ||
    String(process.env.NETWORK_ENV || '').toLowerCase() === 'mainnet' ||
    String(process.env.SIRIUS_NETWORK_TYPE || '') === '184';
  if (!expectedToken) {
    // Fail-closed on Mainnet: never allow unauthenticated validator RPCs without a token
    return !isMainnet;
  }
  const metaVals = callOrStream && callOrStream.metadata ? callOrStream.metadata.get('x-sirius-vm-token') : [];
  const provided = String((metaVals && metaVals[0]) || '');
  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(expectedToken, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function validateWasmFileToCall(filePath) {
  if (!filePath || typeof filePath !== 'string') {
    throw new Error('Missing file_to_call path');
  }
  const resolved = path.resolve(filePath);
  const clusterRoot = CLUSTER_DIR.endsWith(path.sep) ? CLUSTER_DIR : CLUSTER_DIR + path.sep;
  const contractsRoot = CONTRACTS_DIR.endsWith(path.sep) ? CONTRACTS_DIR : CONTRACTS_DIR + path.sep;
  if (!resolved.startsWith(clusterRoot) && !resolved.startsWith(contractsRoot)) {
    throw new Error(`Security rejection: file_to_call (${filePath}) is outside allowed cluster/contracts directory`);
  }
  if (!resolved.endsWith('.wasm') || !fs.existsSync(resolved)) {
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
  includeDirs: [PROTO_DIR],
});

const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
const supercontractserver = protoDescriptor.supercontractserver;

const SHARED_BUFFER_BYTES = 1024 * 1024; // 1 MB shared IPC buffer per pooled worker
const WASM_WORKER_POOL_SIZE = Math.max(1, Math.min(8, Number(process.env.WASM_WORKER_POOL_SIZE || 2)));

/**
 * Persistent Warm WASM Worker Pool:
 * Eliminates per-order `new Worker()` thread-spawn overhead (60x faster on CPU-throttled cloud
 * containers and ~10x faster locally) while still instantiating a fresh WebAssembly.Instance per call
 * for 100% deterministic memory isolation.
 */
class WarmWasmWorkerPool {
  constructor(nodeName, maxSize = WASM_WORKER_POOL_SIZE) {
    this.nodeName = nodeName;
    this.maxSize = maxSize;
    this.slots = [];
    this.waiters = [];
    this.nextJobId = 1;
  }

  _createSlot() {
    const sharedBuffer = new SharedArrayBuffer(SHARED_BUFFER_BYTES);
    const control = new Int32Array(sharedBuffer, 0, 2);
    const dataBuffer = new Uint8Array(sharedBuffer, 8);
    const worker = new Worker(path.join(__dirname, 'wasm_worker.js'), {
      workerData: { poolMode: true, sharedBuffer },
    });
    const slot = {
      worker,
      sharedBuffer,
      control,
      dataBuffer,
      busy: false,
      disposed: false,
      activeJobId: 0,
      onMessage: null,
      onError: null,
    };

    worker.on('message', (msg) => {
      if (slot.disposed || !slot.onMessage) return;
      if (msg && msg.jobId !== undefined && msg.jobId !== slot.activeJobId) return;
      slot.onMessage(msg);
    });

    worker.on('error', (err) => {
      const cb = slot.onError;
      this.destroy(slot);
      if (cb) cb(err);
    });

    worker.on('exit', (code) => {
      if (!slot.disposed) {
        const cb = slot.onError;
        this.destroy(slot);
        if (cb && code !== 0) cb(new Error(`WASM worker exited unexpectedly with code ${code}`));
      }
    });

    this.slots.push(slot);
    return slot;
  }

  prewarm(count = 1) {
    const target = Math.min(this.maxSize, Math.max(1, count));
    while (this.slots.length < target) {
      this._createSlot();
    }
  }

  acquire() {
    const idle = this.slots.find((s) => !s.busy && !s.disposed);
    if (idle) {
      idle.busy = true;
      idle.activeJobId = this.nextJobId++;
      return Promise.resolve(idle);
    }
    if (this.slots.length < this.maxSize) {
      const fresh = this._createSlot();
      fresh.busy = true;
      fresh.activeJobId = this.nextJobId++;
      return Promise.resolve(fresh);
    }
    return new Promise((resolve) => {
      this.waiters.push(resolve);
    });
  }

  release(slot) {
    if (!slot || slot.disposed) return;
    slot.onMessage = null;
    slot.onError = null;
    slot.activeJobId = 0;
    Atomics.store(slot.control, 1, 0);
    Atomics.store(slot.control, 0, 0);
    if (this.waiters.length > 0) {
      const next = this.waiters.shift();
      slot.busy = true;
      slot.activeJobId = this.nextJobId++;
      next(slot);
    } else {
      slot.busy = false;
    }
  }

  destroy(slot) {
    if (!slot || slot.disposed) return;
    slot.disposed = true;
    slot.busy = false;
    slot.onMessage = null;
    slot.onError = null;
    try {
      Atomics.store(slot.control, 1, 0);
      Atomics.store(slot.control, 0, -1);
      Atomics.notify(slot.control, 0, 1);
    } catch (_) {}
    this.slots = this.slots.filter((s) => s !== slot);
    slot.worker.terminate().catch(() => {});
    if (this.waiters.length > 0 && this.slots.length < this.maxSize) {
      const next = this.waiters.shift();
      const replacement = this._createSlot();
      replacement.busy = true;
      replacement.activeJobId = this.nextJobId++;
      next(replacement);
    }
  }

  shutdown() {
    for (const s of [...this.slots]) {
      this.destroy(s);
    }
  }
}

const compiledWasmCache = new Map();
async function getCompiledWasmModule(wasmPath) {
  if (!compiledWasmCache.has(wasmPath)) {
    const bytes = fs.readFileSync(wasmPath);
    compiledWasmCache.set(wasmPath, WebAssembly.compile(bytes));
  }
  return compiledWasmCache.get(wasmPath);
}

/**
 * Normalizes protobuf Buffer fields to base64 strings before serializing into SharedArrayBuffer.
 */
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

/**
 * Converts base64 fields in worker serverMessage back into Buffers where protobuf expects `bytes`.
 */
function prepareServerMessage(serverMsg) {
  if (serverMsg.write_file_stream && typeof serverMsg.write_file_stream.buffer === 'string') {
    return {
      write_file_stream: {
        identifier: serverMsg.write_file_stream.identifier,
        buffer: Buffer.from(serverMsg.write_file_stream.buffer, 'base64'),
      },
    };
  }
  return serverMsg;
}

function createSupercontractService(nodeName, bindAddress, workerPool = null) {
  const pool = workerPool || new WarmWasmWorkerPool(nodeName);
  return {
    Ping(call, callback) {
      if (!verifyVmAuthMetadata(call)) {
        return callback({
          code: grpc.status.UNAUTHENTICATED,
          message: 'Invalid or missing x-sirius-vm-token metadata',
        });
      }
      const callerName = call.request.name || 'unknown';
      let validatorPublicKey = '';
      try {
        validatorPublicKey = getOrInitNodeValidatorAccount(nodeName).publicKey;
      } catch (_) {}
      callback(null, {
        message: `PONG from ${nodeName} WASM VM (${bindAddress}) to ${callerName}`,
        validator_public_key: validatorPublicKey,
        node_name: nodeName,
      });
    },

    CosignTransaction(call, callback) {
      if (!verifyVmAuthMetadata(call)) {
        return callback({
          code: grpc.status.UNAUTHENTICATED,
          message: 'Invalid or missing x-sirius-vm-token metadata',
        });
      }
      verifyAndCosignOnNode(nodeName, call.request || {})
        .then((reply) => {
          console.log(`[${nodeName} VM] ✍️ BFT Cosigned ${call.request.action} (${reply.signer_public_key.slice(0, 12)}...)`);
          callback(null, reply);
        })
        .catch((err) => {
          console.warn(`[${nodeName} VM] ⛔ CosignTransaction rejected (${call.request && call.request.action}): ${err.message}`);
          callback(null, {
            approved: false,
            error: err.message,
            node_name: nodeName,
            signer_public_key: '',
            parent_hash: '',
            signature: '',
          });
        });
    },

    ExecuteCall(stream) {
      if (!verifyVmAuthMetadata(stream)) {
        console.warn(`[${nodeName} VM] ⛔ Rejected unauthenticated ExecuteCall stream`);
        if (!stream.writableEnded) {
          stream.write({
            returns: {
              success: false,
              execution_gas_consumed: '0',
              download_gas_consumed: '0',
              poex_secret_data: '0',
              return_val: -401,
            },
          });
          stream.end();
        }
        return;
      }
      let slot = null;
      let streamCompleted = false;
      let streamAborted = false;
      let started = false;

      stream.on('data', async (reqMsg) => {
        // 1. Initial ExecuteRequest acquires a warm pooled WASM Worker
        if (reqMsg.request && !started) {
          started = true;
          const execReq = reqMsg.request;
          let validatedWasmPath;
          try {
            validatedWasmPath = validateWasmFileToCall(execReq.file_to_call);
          } catch (secErr) {
            console.error(`[${nodeName} VM] ⛔ ${secErr.message}`);
            if (!stream.writableEnded) {
              stream.write({
                returns: {
                  success: false,
                  execution_gas_consumed: '0',
                  download_gas_consumed: '0',
                  poex_secret_data: '0',
                  return_val: -403,
                },
              });
              stream.end();
            }
            return;
          }

          const paramsHex = Buffer.isBuffer(execReq.parameters)
            ? execReq.parameters.toString('hex')
            : '';

          let wasmModule = null;
          try {
            wasmModule = await getCompiledWasmModule(validatedWasmPath);
          } catch (compErr) {
            console.warn(`[${nodeName} VM] Notice: Precompiled WASM cache fallback:`, compErr.message);
          }

          if (streamAborted) return;
          slot = await pool.acquire();
          if (streamAborted) {
            pool.release(slot);
            slot = null;
            return;
          }

          const jobId = slot.activeJobId;

          slot.onMessage = (msg) => {
            if (streamAborted || streamCompleted) return;
            if (msg.type === 'host_call') {
              const outbound = prepareServerMessage(msg.serverMessage);
              if (!stream.writableEnded) stream.write(outbound);
            } else if (msg.type === 'execution_complete') {
              streamCompleted = true;
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

              const finishedSlot = slot;
              slot = null;
              pool.release(finishedSlot);

              if (!stream.writableEnded) {
                stream.write({ returns: protoReturns });
                stream.end();
              }
            }
          };

          slot.onError = (err) => {
            console.error(`[${nodeName} VM] ❌ Worker error:`, err);
            slot = null;
            streamCompleted = true;
            if (!stream.writableEnded) {
              stream.write({
                returns: {
                  success: false,
                  execution_gas_consumed: '0',
                  download_gas_consumed: '0',
                  poex_secret_data: '0',
                  return_val: -1,
                },
              });
              stream.end();
            }
          };

          slot.worker.postMessage({
            type: 'execute',
            jobId,
            wasmModule,
            fileToCall: validatedWasmPath,
            functionToCall: execReq.function_to_call,
            parametersHex: paramsHex,
            poexSecretDataPrefix: execReq.poex_secret_data_prefix || '0',
            executionGasLimit: execReq.execution_gas_limit || '0',
            downloadGasLimit: execReq.download_gas_limit || '0',
            callMode: execReq.call_mode || 0,
          });

          return;
        }

        // 2. Host call reply from C++ Executor -> wake up blocked WASM worker via Atomics.notify()
        if (slot && !slot.disposed && slot.control) {
          const normalized = normalizeClientMessage(reqMsg);
          const jsonBytes = Buffer.from(JSON.stringify(normalized), 'utf8');
          if (jsonBytes.length > slot.dataBuffer.length) {
            const errBytes = Buffer.from('IPC response exceeded SharedArrayBuffer capacity', 'utf8');
            const copyLen = Math.min(errBytes.length, slot.dataBuffer.length);
            errBytes.copy(slot.dataBuffer, 0, 0, copyLen);
            Atomics.store(slot.control, 1, copyLen);
            Atomics.store(slot.control, 0, -1);
          } else {
            jsonBytes.copy(slot.dataBuffer, 0);
            Atomics.store(slot.control, 1, jsonBytes.length);
            Atomics.store(slot.control, 0, 2); // 2 = response ready
          }
          Atomics.notify(slot.control, 0, 1);
        }
      });

      function abortWorker() {
        if (streamCompleted) return;
        streamAborted = true;
        if (slot) {
          const s = slot;
          slot = null;
          // Stream aborted mid-execution: destroy this worker cleanly so no hung Atomics.wait lingers
          pool.destroy(s);
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

function startVmServer(port, nodeName, bindHost = process.env.SIRIUS_VM_BIND_HOST || '127.0.0.1') {
  return new Promise((resolve, reject) => {
    const bindAddress = `${bindHost}:${port}`;
    const server = new grpc.Server();
    const workerPool = new WarmWasmWorkerPool(nodeName);
    workerPool.prewarm(1);
    // Pre-warm SDK module on boot so the very first CosignTransaction never pays cold require() latency
    try { getXpxSdk(); } catch (_) {}
    server._workerPool = workerPool;
    const origForceShutdown = server.forceShutdown.bind(server);
    server.forceShutdown = () => {
      workerPool.shutdown();
      return origForceShutdown();
    };
    const origTryShutdown = server.tryShutdown.bind(server);
    server.tryShutdown = (cb) => {
      workerPool.shutdown();
      return origTryShutdown(cb);
    };
    server.addService(
      supercontractserver.SupercontractServer.service,
      createSupercontractService(nodeName, bindAddress, workerPool)
    );
    let serverCreds;
    let tlsMode = 'insecure';
    try {
      const built = createGrpcServerCredentials(bindAddress);
      serverCreds = built.credentials;
      tlsMode = built.mode;
    } catch (credErr) {
      return reject(credErr);
    }
    server.bindAsync(bindAddress, serverCreds, (err, boundPort) => {
      if (err) {
        return reject(err);
      }
      console.log(`🚀 [${nodeName}] SuperContract V2 gRPC WASM VM listening on ${bindHost}:${boundPort} (${tlsMode})`);
      resolve(server);
    });
  });
}

if (require.main === module) {
  const port = parseInt(process.argv[2] || process.env.VM_PORT || '5051', 10);
  const nodeName = process.argv[3] || process.env.NODE_NAME || `node-${port}`;
  // Keep Node.js event loop alive indefinitely for daemon mode
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
