/**
 * Shared gRPC TLS / mTLS Credential Builder for SiriusCLOB Gateway <-> Validator Nodes
 *
 * Supports both file paths and inline PEM strings (including escaped \n) via env vars:
 *   - SIRIUS_VM_TLS_CA                  (Root CA PEM or file path)
 *   - SIRIUS_VM_TLS_CERT                (Server or Client certificate PEM or file path)
 *   - SIRIUS_VM_TLS_KEY                 (Server or Client private key PEM or file path)
 *   - SIRIUS_VM_TLS_REQUIRE_CLIENT_CERT (Server mTLS enforcement; defaults to true when CA is provided)
 *   - SIRIUS_VM_TLS_SERVER_NAME         (Optional client SNI/hostname override for IP-based endpoints)
 *   - SIRIUS_VM_ALLOW_INSECURE_REMOTE   (Set 'true' ONLY when running inside a private WireGuard/Tailscale mesh)
 *   - SIRIUS_VM_REQUIRE_TLS             (Server fail-closed toggle when binding non-loopback without TLS)
 */

const fs = require('fs');
const grpc = require('@grpc/grpc-js');

function loadPemInput(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  if (trimmed.includes('-----BEGIN ')) {
    return Buffer.from(trimmed.replace(/\\n/g, '\n'), 'utf8');
  }
  if (fs.existsSync(trimmed)) {
    return fs.readFileSync(trimmed);
  }
  throw new Error(`TLS credential file not found: ${trimmed}`);
}

function isLoopbackTarget(endpoint) {
  const clean = String(endpoint || '').trim().toLowerCase();
  if (!clean) return true;
  if (
    clean.startsWith('127.0.0.1:') ||
    clean === '127.0.0.1' ||
    clean.startsWith('localhost:') ||
    clean === 'localhost' ||
    clean.startsWith('[::1]:') ||
    clean === '::1'
  ) {
    return true;
  }
  return false;
}

function createGrpcClientCredentials(targetEndpoint) {
  const caBuf = loadPemInput(process.env.SIRIUS_VM_TLS_CA);
  const certBuf = loadPemInput(process.env.SIRIUS_VM_TLS_CERT);
  const keyBuf = loadPemInput(process.env.SIRIUS_VM_TLS_KEY);
  const tlsEnabled = Boolean(caBuf || certBuf || keyBuf);

  if (tlsEnabled) {
    if ((certBuf && !keyBuf) || (!certBuf && keyBuf)) {
      throw new Error('gRPC mTLS misconfiguration: both SIRIUS_VM_TLS_CERT and SIRIUS_VM_TLS_KEY must be provided together');
    }
    const creds = grpc.credentials.createSsl(caBuf || null, keyBuf || null, certBuf || null);
    const channelOptions = {};
    if (process.env.SIRIUS_VM_TLS_SERVER_NAME) {
      channelOptions['grpc.ssl_target_name_override'] = process.env.SIRIUS_VM_TLS_SERVER_NAME.trim();
    }
    return { credentials: creds, channelOptions, mode: certBuf ? 'mTLS' : 'TLS' };
  }

  // Fail-closed: refuse plaintext gRPC to remote validator hosts unless explicitly inside a private mesh
  if (!isLoopbackTarget(targetEndpoint) && process.env.SIRIUS_VM_ALLOW_INSECURE_REMOTE !== 'true') {
    throw new Error(
      `Security rejection: Refusing plaintext gRPC connection to remote validator ${targetEndpoint}. ` +
      `Configure SIRIUS_VM_TLS_CA/CERT/KEY for mTLS (or set SIRIUS_VM_ALLOW_INSECURE_REMOTE=true ONLY inside a private WireGuard/Tailscale mesh).`
    );
  }

  return {
    credentials: grpc.credentials.createInsecure(),
    channelOptions: {},
    mode: 'insecure-loopback',
  };
}

function createGrpcServerCredentials(bindAddress) {
  const caBuf = loadPemInput(process.env.SIRIUS_VM_TLS_CA);
  const certBuf = loadPemInput(process.env.SIRIUS_VM_TLS_CERT);
  const keyBuf = loadPemInput(process.env.SIRIUS_VM_TLS_KEY);
  const tlsEnabled = Boolean(certBuf || keyBuf);

  if (tlsEnabled) {
    if (!certBuf || !keyBuf) {
      throw new Error('gRPC server TLS misconfiguration: both SIRIUS_VM_TLS_CERT and SIRIUS_VM_TLS_KEY are required');
    }
    const checkClientCert = Boolean(caBuf) && process.env.SIRIUS_VM_TLS_REQUIRE_CLIENT_CERT !== 'false';
    const creds = grpc.ServerCredentials.createSsl(
      caBuf || null,
      [{ private_key: keyBuf, cert_chain: certBuf }],
      checkClientCert
    );
    return { credentials: creds, mode: checkClientCert ? 'mTLS' : 'TLS' };
  }

  const isMainnet =
    String(process.env.SIRIUS_NETWORK || '').toLowerCase() === 'mainnet' ||
    String(process.env.NETWORK_ENV || '').toLowerCase() === 'mainnet' ||
    String(process.env.SIRIUS_NETWORK_TYPE || '') === '184';
  const requireTlsOnNonLoopback =
    process.env.SIRIUS_VM_REQUIRE_TLS === 'true' ||
    (isMainnet && process.env.SIRIUS_VM_ALLOW_INSECURE_REMOTE !== 'true');

  if (!isLoopbackTarget(bindAddress) && requireTlsOnNonLoopback) {
    throw new Error(
      `Security rejection: Refusing to bind non-loopback validator ${bindAddress} without TLS` +
      `${isMainnet ? ' on Mainnet' : ' (SIRIUS_VM_REQUIRE_TLS=true)'}. ` +
      `Provide SIRIUS_VM_TLS_CERT, SIRIUS_VM_TLS_KEY, and SIRIUS_VM_TLS_CA (or set SIRIUS_VM_ALLOW_INSECURE_REMOTE=true ONLY inside a private WireGuard/Tailscale mesh).`
    );
  }

  return {
    credentials: grpc.ServerCredentials.createInsecure(),
    mode: 'insecure',
  };
}

module.exports = {
  loadPemInput,
  isLoopbackTarget,
  createGrpcClientCredentials,
  createGrpcServerCredentials,
};
