'use strict';

/**
 * Sirius Validator Encrypted Keystore (AES-256-GCM + scrypt)
 *
 * Protects validator Ed25519 private keys at rest on normal VPS disks so stolen
 * backups, disk snapshots, or accidental file leaks never expose raw private keys.
 *
 * Format: validator_key.enc (JSON envelope, mode 0600)
 *   - KDF: scrypt (N=131072, r=8, p=1, dkLen=32)
 *   - Cipher: AES-256-GCM with 96-bit random IV & 128-bit authTag
 *   - AAD: binds version, nodeName, networkType, and publicKey to prevent metadata tampering
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEYSTORE_VERSION = 1;
const DEFAULT_SCRYPT_PARAMS = Object.freeze({
  N: 131072, // 2^17 (OWASP recommended, ~128 MB RAM)
  r: 8,
  p: 1,
  dkLen: 32,
});
const MAX_SCRYPT_MEM = 256 * 1024 * 1024; // 256 MB safety ceiling
const MIN_PASSPHRASE_LENGTH = 8;

function buildAad(nodeName, networkType, publicKey) {
  return Buffer.from(
    `sirius-validator-keystore:v${KEYSTORE_VERSION}:${String(nodeName)}:${Number(networkType)}:${String(publicKey).toUpperCase()}`,
    'utf8'
  );
}

function resolveKeystorePassphrase(nodeName) {
  // 1. Explicit passphrase file (ideal for Docker secrets or tmpfs /run/secrets/...)
  const envFile = (process.env.SIRIUS_KEYSTORE_PASSPHRASE_FILE || '').trim();
  if (envFile) {
    if (!fs.existsSync(envFile)) {
      throw new Error(`SIRIUS_KEYSTORE_PASSPHRASE_FILE does not exist: ${envFile}`);
    }
    const content = fs.readFileSync(envFile, 'utf8').replace(/\r?\n$/, '');
    if (content) return content;
  }

  // 2. Native systemd LoadCredential=validator_passphrase:...
  const credDir = (process.env.CREDENTIALS_DIRECTORY || '').trim();
  if (credDir) {
    const credPath = path.join(credDir, 'validator_passphrase');
    if (fs.existsSync(credPath)) {
      const content = fs.readFileSync(credPath, 'utf8').replace(/\r?\n$/, '');
      if (content) return content;
    }
  }

  // 3. Node-specific env var, then generic env var
  const normNode = String(nodeName || '').toUpperCase().replace(/[^A-Z0-9]/g, '_');
  const nodeEnv = process.env[`SIRIUS_KEYSTORE_PASSPHRASE_${normNode}`];
  if (nodeEnv && nodeEnv.length > 0) return nodeEnv;

  const genericEnv = process.env.SIRIUS_KEYSTORE_PASSPHRASE;
  if (genericEnv && genericEnv.length > 0) return genericEnv;

  return '';
}

function deriveKey(passphrase, saltBuf, kdfParams = DEFAULT_SCRYPT_PARAMS) {
  const N = Number(kdfParams.N || DEFAULT_SCRYPT_PARAMS.N);
  const r = Number(kdfParams.r || DEFAULT_SCRYPT_PARAMS.r);
  const p = Number(kdfParams.p || DEFAULT_SCRYPT_PARAMS.p);
  const dkLen = Number(kdfParams.dkLen || DEFAULT_SCRYPT_PARAMS.dkLen);
  // Enforce safe bounds on KDF parameters from untrusted disk envelopes
  if (N < 16384 || N > 1048576 || (N & (N - 1)) !== 0) {
    throw new Error(`Invalid scrypt N parameter: ${N}`);
  }
  if (r < 1 || r > 32 || p < 1 || p > 16 || dkLen !== 32) {
    throw new Error(`Invalid scrypt parameters (r=${r}, p=${p}, dkLen=${dkLen})`);
  }
  return crypto.scryptSync(Buffer.from(passphrase, 'utf8'), saltBuf, dkLen, {
    N,
    r,
    p,
    maxmem: MAX_SCRYPT_MEM,
  });
}

/**
 * Encrypts a validator key record into an AES-256-GCM JSON envelope.
 */
function encryptValidatorKeyRecord(record, passphrase, kdfOverride = null) {
  if (!passphrase || typeof passphrase !== 'string' || passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`Keystore passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
  }
  if (!record || !record.privateKey || !/^[0-9a-fA-F]{64}$/.test(String(record.privateKey))) {
    throw new Error('Invalid validator privateKey: expected 64-character hex');
  }
  if (!record.publicKey || !/^[0-9a-fA-F]{64}$/.test(String(record.publicKey))) {
    throw new Error('Invalid validator publicKey: expected 64-character hex');
  }

  const nodeName = String(record.nodeName || 'node1');
  const networkType = Number(record.networkType || 168);
  const publicKey = String(record.publicKey).toUpperCase();
  const address = String(record.address || '');
  const createdAt = record.createdAt || new Date().toISOString();

  const kdfParams = kdfOverride ? { ...DEFAULT_SCRYPT_PARAMS, ...kdfOverride } : { ...DEFAULT_SCRYPT_PARAMS };
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const aad = buildAad(nodeName, networkType, publicKey);

  const plaintext = Buffer.from(
    JSON.stringify({
      nodeName,
      networkType,
      address,
      publicKey,
      privateKey: String(record.privateKey).toUpperCase(),
      createdAt,
    }),
    'utf8'
  );

  const keyBuf = deriveKey(passphrase, salt, kdfParams);
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuf, iv);
    cipher.setAAD(aad);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      version: KEYSTORE_VERSION,
      cipher: 'aes-256-gcm',
      kdf: 'scrypt',
      kdfParams,
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      ciphertext: encrypted.toString('hex'),
      nodeName,
      networkType,
      publicKey,
      address,
      createdAt,
    };
  } finally {
    keyBuf.fill(0);
    plaintext.fill(0);
  }
}

/**
 * Decrypts an AES-256-GCM validator keystore envelope and verifies integrity + AAD.
 */
function decryptValidatorKeyEnvelope(envelope, passphrase) {
  if (!passphrase || typeof passphrase !== 'string') {
    throw new Error('Missing passphrase to decrypt validator_key.enc');
  }
  if (!envelope || typeof envelope !== 'object' || Number(envelope.version) !== KEYSTORE_VERSION) {
    throw new Error('Unsupported or malformed validator_key.enc envelope');
  }
  if (envelope.cipher !== 'aes-256-gcm' || envelope.kdf !== 'scrypt') {
    throw new Error(`Unsupported keystore cipher/kdf: ${envelope.cipher}/${envelope.kdf}`);
  }
  if (!/^[0-9a-fA-F]{64}$/.test(String(envelope.salt || '')) || !/^[0-9a-fA-F]{24}$/.test(String(envelope.iv || '')) || !/^[0-9a-fA-F]{32}$/.test(String(envelope.authTag || ''))) {
    throw new Error('Corrupted validator_key.enc cryptographic parameters');
  }

  const salt = Buffer.from(envelope.salt, 'hex');
  const iv = Buffer.from(envelope.iv, 'hex');
  const authTag = Buffer.from(envelope.authTag, 'hex');
  const ciphertext = Buffer.from(String(envelope.ciphertext || ''), 'hex');
  const aad = buildAad(envelope.nodeName, envelope.networkType, envelope.publicKey);

  const keyBuf = deriveKey(passphrase, salt, envelope.kdfParams || DEFAULT_SCRYPT_PARAMS);
  let decrypted = null;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuf, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);
    decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const parsed = JSON.parse(decrypted.toString('utf8'));
    if (!parsed || !parsed.privateKey || !/^[0-9a-fA-F]{64}$/.test(String(parsed.privateKey))) {
      throw new Error('Decrypted keystore payload missing valid privateKey');
    }
    if (String(parsed.publicKey || '').toUpperCase() !== String(envelope.publicKey || '').toUpperCase()) {
      throw new Error('Decrypted keystore publicKey mismatch against envelope');
    }
    return parsed;
  } catch (err) {
    if (err && /Unsupported keystore|Corrupted|mismatch|missing valid/.test(err.message)) throw err;
    throw new Error('Failed to decrypt validator_key.enc: invalid passphrase or tampered/corrupted keystore');
  } finally {
    keyBuf.fill(0);
    if (decrypted) decrypted.fill(0);
  }
}

/**
 * Atomically writes an encrypted keystore envelope to disk with mode 0600.
 */
function writeEncryptedKeystoreFile(filePath, envelope) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const tmpPath = `${filePath}.tmp.${process.pid}.${Date.now()}`;
  fs.writeFileSync(tmpPath, JSON.stringify(envelope, null, 2), { mode: 0o600 });
  fs.renameSync(tmpPath, filePath);
  try { fs.chmodSync(filePath, 0o600); } catch (_) {}
}

/**
 * Reads and decrypts validator_key.enc from disk.
 */
function readEncryptedKeystoreFile(filePath, passphrase) {
  const envelope = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  return decryptValidatorKeyEnvelope(envelope, passphrase);
}

/**
 * Overwrites a plaintext key file with random/zero bytes before unlinking.
 */
function secureShredFile(filePath) {
  try {
    if (!fs.existsSync(filePath)) return;
    const stat = fs.statSync(filePath);
    const len = Math.max(stat.size, 512);
    const fd = fs.openSync(filePath, 'r+');
    try {
      fs.writeSync(fd, crypto.randomBytes(len), 0, len, 0);
      fs.fsyncSync(fd);
      fs.writeSync(fd, Buffer.alloc(len, 0), 0, len, 0);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.unlinkSync(filePath);
  } catch (_) {
    try { fs.unlinkSync(filePath); } catch (__) {}
  }
}

module.exports = {
  KEYSTORE_VERSION,
  DEFAULT_SCRYPT_PARAMS,
  MIN_PASSPHRASE_LENGTH,
  resolveKeystorePassphrase,
  encryptValidatorKeyRecord,
  decryptValidatorKeyEnvelope,
  writeEncryptedKeystoreFile,
  readEncryptedKeystoreFile,
  secureShredFile,
};
