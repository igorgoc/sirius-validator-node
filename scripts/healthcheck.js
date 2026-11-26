/**
 * Sirius Validator Node — Automated Healthcheck
 * Pings the local gRPC SuperContract VM service and checks contract existence.
 */

const fs = require('fs');
const path = require('path');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const { createGrpcClientCredentials } = require('../executor/grpc_tls');

const PROTO_PATH = path.join(__dirname, '../executor/proto/supercontract_server.proto');
const PORT = parseInt(process.argv[2] || process.env.VM_PORT || '5051', 10);
const HOST = process.env.HEALTHCHECK_HOST || '127.0.0.1';

const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});

const proto = grpc.loadPackageDefinition(packageDefinition);
const targetAddr = `${HOST}:${PORT}`;
const { credentials, channelOptions } = createGrpcClientCredentials(targetAddr);
const client = new proto.supercontractserver.SupercontractServer(
  targetAddr,
  credentials,
  channelOptions
);

const metadata = new grpc.Metadata();
if (process.env.SIRIUS_VM_AUTH_TOKEN) {
  metadata.set('x-sirius-vm-token', process.env.SIRIUS_VM_AUTH_TOKEN);
}

const deadline = new Date(Date.now() + 3000);

client.Ping({ name: 'healthcheck' }, metadata, { deadline }, (err, response) => {
  if (err) {
    console.error(`❌ Healthcheck FAILED on ${HOST}:${PORT}:`, err.message);
    process.exit(1);
  }
  if (!response || !response.message) {
    console.error(`❌ Healthcheck FAILED: Invalid response payload`);
    process.exit(1);
  }

  // Also check contract binary
  const contractsDir = process.env.CONTRACTS_DIR || path.join(__dirname, '../contracts');
  const wasmPath = path.join(contractsDir, 'sirius_clob.wasm');
  if (!fs.existsSync(wasmPath)) {
    console.warn(`⚠️ Warning: sirius_clob.wasm not found at ${wasmPath}`);
  }

  const keyNote = response.validator_public_key ? ` [Cosigner: ${response.validator_public_key.slice(0, 12)}...]` : '';
  console.log(`✅ Healthcheck PASSED: ${response.message}${keyNote}`);
  process.exit(0);
});
