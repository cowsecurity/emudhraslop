'use strict';
const fs = require('node:fs');
const tls = require('node:tls');
const https = require('node:https');
const crypto = require('node:crypto');
const net = require('node:net');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const result = {version: `Node ${process.versions.node}`, accepted: false,
  leaf_sha256: '', error_class: '', sources: []};
let finished = false;
function finish(error, socket) {
  if (finished) return;
  finished = true;
  if (error) {
    const code = String(error.code || '');
    result.error_class = /CERT|ISSUER|SIGNATURE|SELF_SIGNED|VERIFY/.test(code) ?
      'certificate_rejected' : code === 'TIMEOUT' ? 'timeout' : 'network_error';
  } else if (socket && socket.authorized) {
    const peer = socket.getPeerCertificate();
    if (peer && peer.raw) {
      result.accepted = true;
      result.leaf_sha256 = hash(peer.raw);
    } else result.error_class = 'peer_certificate_unavailable';
  }
  if (socket) socket.destroy();
  process.stdout.write(JSON.stringify(result));
}
function readCA(path) {
  const descriptor = fs.openSync(path, 'r');
  try {
    if (!fs.fstatSync(descriptor).isFile()) throw new Error('not a CA file');
    const buffer = Buffer.alloc(16777217);
    let size = 0;
    while (size < buffer.length) {
      const count = fs.readSync(descriptor, buffer, size, buffer.length - size, null);
      if (!count) break;
      size += count;
    }
    if (size > 16777216) throw new Error('CA size limit');
    const data = buffer.subarray(0, size);
    result.sources.push({path, sha256: hash(data), complete: true});
    return data;
  } finally { fs.closeSync(descriptor); }
}
try {
  const config = JSON.parse(fs.readFileSync(0, 'utf8'));
  const options = {host: config.host, port: config.port,
    rejectUnauthorized: true};
  if (!net.isIP(config.host)) options.servername = config.host;
  if (config.ca_bundle) options.ca = readCA(config.ca_bundle);
  else {
    // This identifies the effective native CA list when the runtime exposes it;
    // bundled roots alone cannot represent OS/additional CA settings.
    const available = typeof tls.getCACertificates === 'function';
    const certificates = available ? tls.getCACertificates('default') : tls.rootCertificates;
    result.sources.push({path: available ? 'node:default-ca-list' : 'node:bundled-ca-list',
      sha256: hash(certificates.join('\n')), complete: available});
    if (process.env.NODE_EXTRA_CA_CERTS) readCA(process.env.NODE_EXTRA_CA_CERTS);
  }
  if (!config.host) finish();
  else if (config.client === 'tls') {
    const socket = tls.connect(options);
    socket.setTimeout(config.timeout * 1000, () => {
      finish({code: 'TIMEOUT'}, socket);
    });
    socket.once('secureConnect', () => finish(null, socket));
    socket.once('error', error => finish(error, socket));
  } else if (config.client === 'https') {
    const request = https.request({...options, method: 'HEAD', path: '/', agent: false}, response => {
      response.destroy();
    });
    request.once('socket', socket => {
      socket.once('secureConnect', () => { finish(null, socket); request.destroy(); });
    });
    request.setTimeout(config.timeout * 1000, () => {
      finish({code: 'TIMEOUT'}); request.destroy();
    });
    request.once('error', error => finish(error));
    request.end();
  } else { result.error_class = 'unsupported_client'; finish(); }
} catch (_) { result.error_class = 'trust_source_unreadable'; finish(); }
