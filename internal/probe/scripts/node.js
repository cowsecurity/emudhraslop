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
let exitAfterOutput = false;
let cleanup = () => {};
function finish(error, socket) {
  if (finished) return;
  finished = true;
  if (error) {
    const code = String(error.code || '');
    result.error_class = /CERT|ISSUER|SIGNATURE|SELF_SIGNED|VERIFY/.test(code) ?
      'certificate_rejected' : code === 'TIMEOUT' ? 'timeout' : 'network_error';
  } else if (socket && socket.authorized) {
    try {
      const peer = socket.getPeerCertificate();
      if (peer && peer.raw) {
        result.leaf_sha256 = hash(peer.raw);
        result.accepted = true;
      } else result.error_class = 'peer_certificate_unavailable';
    } catch (_) { result.error_class = 'peer_certificate_unavailable'; }
  }
  cleanup();
  if (socket) socket.destroy();
  process.stdout.write(JSON.stringify(result), () => {
    // A pending built-in fetch connection can outlive AbortController (there is
    // no public built-in dispatcher close API). This one-shot helper exits only
    // after its JSON is flushed, closing any remaining native handles.
    if (exitAfterOutput) process.exit(0);
  });
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
// Built-in fetch exposes its own request/socket association through Undici.
// An unrelated connection (including another request to the same origin) must
// never become proof for this request. No external Undici package is imported.
function probeFetch(config) {
  exitAfterOutput = true;
  if (typeof globalThis.fetch !== 'function' || typeof AbortController !== 'function') {
    result.error_class = 'unsupported_client'; finish(); return;
  }
  if (config.ca_bundle || config.ca_dir || process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
    result.error_class = 'unsupported_configuration'; finish(); return;
  }
  const diagnostics = require('node:diagnostics_channel');
  const {AsyncLocalStorage} = require('node:async_hooks');
  const scope = new AsyncLocalStorage();
  const token = {};
  const controller = new AbortController();
  const host = net.isIP(config.host) === 6 ? `[${config.host}]` : config.host;
  const url = new URL(`https://${host}:${config.port}/`);
  let targetRequest;
  let peerSocket;
  let timer;
  const create = diagnostics.channel('undici:request:create');
  const send = diagnostics.channel('undici:client:sendHeaders');
  function onCreate({request}) {
    if (scope.getStore() !== token || targetRequest) return;
    if (String(request.origin) === url.origin && request.method === 'HEAD' && request.path === '/') {
      targetRequest = request;
    }
  }
  function onSend({request, socket}) {
    if (!targetRequest || request !== targetRequest || finished) return;
    // Callback exceptions escape through diagnostics_channel; keep failures local.
    try {
      if (!socket || !socket.encrypted || !socket.authorized ||
          typeof socket.getPeerCertificate !== 'function') {
        result.error_class = 'peer_certificate_unavailable';
        queueMicrotask(() => finish());
        return;
      }
      peerSocket = socket;
      // Leave Undici's synchronous write intact before aborting our HEAD request.
      queueMicrotask(() => finish(null, socket));
    } catch (_) {
      result.error_class = 'peer_certificate_unavailable';
      queueMicrotask(() => finish());
    }
  }
  cleanup = () => {
    clearTimeout(timer);
    create.unsubscribe(onCreate);
    send.unsubscribe(onSend);
    controller.abort();
    if (peerSocket) peerSocket.destroy();
    scope.disable();
  };
  create.subscribe(onCreate);
  send.subscribe(onSend);
  timer = setTimeout(() => finish({code: 'TIMEOUT'}), config.timeout * 1000);
  scope.run(token, () => globalThis.fetch(url, {
    method: 'HEAD', redirect: 'manual', credentials: 'omit', signal: controller.signal
  })).then(response => {
    if (response.body) response.body.cancel().catch(() => {});
    if (!finished) { result.error_class = 'peer_certificate_unavailable'; finish(); }
  }).catch(error => {
    if (!finished) finish(error.cause || error);
  });
}
try {
  const config = JSON.parse(fs.readFileSync(0, 'utf8'));
  const options = {host: config.host, port: config.port,
    rejectUnauthorized: true};
  if (!net.isIP(config.host)) options.servername = config.host;
  if (config.client === 'fetch' && (config.ca_bundle || config.ca_dir)) {
    result.error_class = 'unsupported_configuration'; finish();
  } else if (config.ca_bundle) options.ca = readCA(config.ca_bundle);
  else {
    // This identifies the effective native CA list when the runtime exposes it;
    // bundled roots alone cannot represent OS/additional CA settings.
    const available = typeof tls.getCACertificates === 'function';
    const certificates = available ? tls.getCACertificates('default') : tls.rootCertificates;
    result.sources.push({path: available ? 'node:default-ca-list' : 'node:bundled-ca-list',
      sha256: hash(certificates.join('\n')), complete: available});
    if (process.env.NODE_EXTRA_CA_CERTS) readCA(process.env.NODE_EXTRA_CA_CERTS);
  }
  if (finished) { /* Unsupported configuration already reported. */ }
  else if (!config.host) {
    if (config.client === 'fetch' && typeof globalThis.fetch !== 'function') result.error_class = 'unsupported_client';
    finish();
  }
  else if (config.client === 'fetch') probeFetch(config);
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
