#!/usr/bin/env node
'use strict';

/**
 * Sirius Validator Encrypted Keystore CLI (AES-256-GCM + scrypt)
 *
 * Commands:
 *   node scripts/keystore.js init --node node1     Generate a new random key directly into validator_key.enc
 *   node scripts/keystore.js encrypt --node node1  Encrypt existing validator_key.json -> validator_key.enc and shred plaintext
 *   node scripts/keystore.js inspect --node node1  Display public metadata (publicKey, address, cipher) without passphrase
 *   node scripts/keystore.js verify --node node1   Verify passphrase unlocks validator_key.enc (never prints private key)
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const sdk = require('tsjs-xpx-chain-sdk');
const {
  MIN_PASSPHRASE_LENGTH,
  resolveKeystorePassphrase,
  encryptValidatorKeyRecord,
  writeEncryptedKeystoreFile,
  readEncryptedKeystoreFile,
  secureShredFile,
} = require('../executor/validator_keystore');

const ROOT_DIR = path.resolve(__dirname, '..');
const CLUSTER_DIR = process.env.SIRIUS_CLUSTER_DIR
  ? path.resolve(process.env.SIRIUS_CLUSTER_DIR)
  : path.join(ROOT_DIR, 'cluster');

function parseArgs(argv) {
  const cmd = argv[2] || 'help';
  let nodeName = process.env.NODE_NAME || 'node1';
  let networkType = Number(process.env.SIRIUS_NETWORK_TYPE || (String(process.env.SIRIUS_NETWORK || '').toLowerCase() === 'mainnet' ? 184 : 168));
  let keepPlaintext = false;
  for (let i = 3; i < argv.length; i++) {
    if (argv[i] === '--node' && argv[i + 1]) nodeName = argv[++i];
    else if (argv[i] === '--network-type' && argv[i + 1]) networkType = Number(argv[++i]);
    else if (argv[i] === '--keep-plaintext') keepPlaintext = true;
  }
  return { cmd, nodeName, networkType, keepPlaintext };
}

function promptHidden(promptText) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const origWrite = rl._writeToOutput;
    rl._writeToOutput = function (str) {
      if (str.includes(promptText)) origWrite.call(rl, str);
      else if (str === '\r\n' || str === '\n' || str === '\r') origWrite.call(rl, '\n');
    };
    rl.question(promptText, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

async function getPassphraseInteractive(nodeName, confirm = false) {
  const fromEnv = resolveKeystorePassphrase(nodeName);
  if (fromEnv) return fromEnv;
  if (!process.stdin.isTTY) {
    throw new Error('No TTY and no SIRIUS_KEYSTORE_PASSPHRASE / SIRIUS_KEYSTORE_PASSPHRASE_FILE provided');
  }
  const p1 = await promptHidden(`Enter keystore passphrase (min ${MIN_PASSPHRASE_LENGTH} chars): `);
  if (p1.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
  }
  if (confirm) {
    const p2 = await promptHidden('Confirm keystore passphrase: ');
    if (p1 !== p2) throw new Error('Passphrases do not match');
  }
  return p1;
}

async function main() {
  const { cmd, nodeName, networkType, keepPlaintext } = parseArgs(process.argv);
  const encPath = path.join(CLUSTER_DIR, nodeName, 'validator_key.enc');
  const jsonPath = path.join(CLUSTER_DIR, nodeName, 'validator_key.json');

  if (cmd === 'init') {
    if (fs.existsSync(encPath)) {
      throw new Error(`Refusing to overwrite existing encrypted keystore: ${encPath}`);
    }
    const passphrase = await getPassphraseInteractive(nodeName, true);
    const acc = sdk.Account.generateNewAccount(networkType);
    const record = {
      nodeName,
      networkType,
      address: acc.address.plain(),
      publicKey: acc.publicKey,
      privateKey: acc.privateKey,
      createdAt: new Date().toISOString(),
    };
    const envelope = encryptValidatorKeyRecord(record, passphrase);
    writeEncryptedKeystoreFile(encPath, envelope);
    readEncryptedKeystoreFile(encPath, passphrase); // verify round-trip
    console.log(`\n🔐 Created encrypted validator keystore: ${encPath}`);
    console.log(`   Node Name:   ${nodeName}`);
    console.log(`   NetworkType: ${networkType}`);
    console.log(`   Public Key:  ${acc.publicKey}`);
    console.log(`   Address:     ${acc.address.plain()}`);
    console.log(`   Cipher:      aes-256-gcm (scrypt N=${envelope.kdfParams.N})\n`);
    return;
  }

  if (cmd === 'encrypt') {
    if (!fs.existsSync(jsonPath)) {
      throw new Error(`Plaintext key not found at ${jsonPath}`);
    }
    if (fs.existsSync(encPath)) {
      throw new Error(`Encrypted keystore already exists at ${encPath}. Remove it first if re-encrypting.`);
    }
    const raw = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
    if (!raw || !raw.privateKey || !/^[0-9a-fA-F]{64}$/.test(raw.privateKey)) {
      throw new Error(`Invalid privateKey in ${jsonPath}`);
    }
    const acc = sdk.Account.createFromPrivateKey(raw.privateKey, Number(raw.networkType || networkType), 1);
    const passphrase = await getPassphraseInteractive(nodeName, true);
    const envelope = encryptValidatorKeyRecord(
      {
        nodeName,
        networkType: Number(raw.networkType || networkType),
        address: acc.address.plain(),
        publicKey: acc.publicKey,
        privateKey: acc.privateKey,
        createdAt: raw.createdAt || new Date().toISOString(),
      },
      passphrase
    );
    writeEncryptedKeystoreFile(encPath, envelope);
    const check = readEncryptedKeystoreFile(encPath, passphrase);
    if (check.privateKey.toUpperCase() !== acc.privateKey.toUpperCase()) {
      throw new Error('Verification round-trip mismatch! Keeping original plaintext file.');
    }
    if (!keepPlaintext) {
      secureShredFile(jsonPath);
    }
    console.log(`\n🔐 Encrypted ${jsonPath} -> ${encPath}`);
    console.log(`   Public Key: ${acc.publicKey}`);
    console.log(`   Address:    ${acc.address.plain()}`);
    console.log(`   Plaintext:  ${keepPlaintext ? 'kept (--keep-plaintext)' : 'securely shredded & removed'}\n`);
    return;
  }

  if (cmd === 'inspect') {
    if (!fs.existsSync(encPath)) {
      throw new Error(`Encrypted keystore not found at ${encPath}`);
    }
    const env = JSON.parse(fs.readFileSync(encPath, 'utf8'));
    console.log(JSON.stringify({
      file: encPath,
      version: env.version,
      cipher: env.cipher,
      kdf: env.kdf,
      kdfParams: env.kdfParams,
      nodeName: env.nodeName,
      networkType: env.networkType,
      publicKey: env.publicKey,
      address: env.address,
      createdAt: env.createdAt,
    }, null, 2));
    return;
  }

  if (cmd === 'verify') {
    if (!fs.existsSync(encPath)) {
      throw new Error(`Encrypted keystore not found at ${encPath}`);
    }
    const passphrase = await getPassphraseInteractive(nodeName, false);
    const dec = readEncryptedKeystoreFile(encPath, passphrase);
    console.log(`✅ Keystore unlocked & verified cleanly for ${dec.nodeName} (PublicKey: ${dec.publicKey})`);
    return;
  }

  console.log(`
Sirius Validator Encrypted Keystore CLI (AES-256-GCM + scrypt)

Usage:
  node scripts/keystore.js init    --node <name> [--network-type 168|184]
  node scripts/keystore.js encrypt --node <name> [--keep-plaintext]
  node scripts/keystore.js inspect --node <name>
  node scripts/keystore.js verify  --node <name>
`);
}

main().catch((err) => {
  console.error('❌ Keystore error:', err.message);
  process.exit(1);
});
