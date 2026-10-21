import hashlib
import json
import os
import socket
import ssl
import sys


def source(path):
    result = {"path": path, "complete": False}
    if path and os.path.isfile(path):
        with open(path, "rb") as handle:
            data = handle.read(16777217)
        if len(data) <= 16777216:
            result.update(sha256=hashlib.sha256(data).hexdigest(), complete=True)
    return result


def classify(error):
    # Exception messages may contain proxy credentials and must never be emitted.
    pending = [error]
    seen = set()
    while pending and len(seen) < 16:
        item = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, (ssl.SSLCertVerificationError, ssl.CertificateError)):
            return "certificate_rejected"
        if isinstance(item, (TimeoutError, socket.timeout)):
            return "timeout"
        for value in (getattr(item, "__cause__", None), getattr(item, "__context__", None)):
            if isinstance(value, BaseException):
                pending.append(value)
    return "network_error"


def probe(config, result):
    client = config["client"]
    bundle, directory = config["ca_bundle"], config["ca_dir"]
    verify = bundle or directory or True
    context = None
    if client == "stdlib" or (client == "httpx" and (bundle or directory)):
        context = ssl.create_default_context(cafile=bundle or None, capath=directory or None)
    if bundle or directory:
        result["sources"] = [source(value) for value in (bundle, directory) if value]
    elif client == "stdlib":
        defaults = ssl.get_default_verify_paths()
        result["sources"] = [source(value) for value in (defaults.cafile, defaults.capath) if value]
    if client == "requests":
        import requests
        result["version"] += "; requests " + requests.__version__
        if not bundle and not directory:
            path = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("CURL_CA_BUNDLE") or requests.certs.where()
            result["sources"] = [source(path)]
    elif client == "httpx":
        import httpx
        result["version"] += "; httpx " + httpx.__version__
        if not bundle and not directory:
            import certifi
            path = os.environ.get("SSL_CERT_FILE") or os.environ.get("SSL_CERT_DIR") or certifi.where()
            result["sources"] = [source(path)]
    elif client == "botocore":
        import botocore
        result["version"] += "; botocore " + botocore.__version__
        from botocore.awsrequest import AWSPreparedRequest
        from botocore.httpsession import URLLib3Session, get_cert_path
        if directory:
            result["error_class"] = "unsupported_configuration"
            return
        verify = bundle or os.environ.get("AWS_CA_BUNDLE") or True
        result["sources"] = [source(get_cert_path(verify))]
    elif client != "stdlib":
        result["error_class"] = "unsupported_client"
        return
    if not config["host"]:
        return
    host, port, timeout = config["host"], config["port"], config["timeout"]
    address = "https://" + host + (":" + str(port) if port != 443 else "") + "/"
    peer = None
    if client == "stdlib":
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secure:
                peer = secure.getpeercert(True)
    elif client == "requests":
        # Fresh Session, isolated HOME, no supplied auth/cookies, no redirects.
        with requests.Session() as session:
            with session.get(address, timeout=timeout, verify=verify, stream=True, allow_redirects=False) as response:
                connection = getattr(response.raw, "connection", None)
                secure = getattr(connection, "sock", None)
                if secure is not None:
                    peer = secure.getpeercert(True)
    elif client == "httpx":
        with httpx.Client(verify=context or verify, timeout=timeout, follow_redirects=False) as session:
            with session.stream("GET", address) as response:
                stream = response.extensions.get("network_stream")
                secure = stream.get_extra_info("ssl_object") if stream else None
                if secure is not None:
                    peer = secure.getpeercert(True)
    elif client == "botocore":
        session = URLLib3Session(verify=verify, timeout=timeout)
        try:
            request = AWSPreparedRequest(method="GET", url=address, headers={}, body=None, stream_output=True)
            response = session.send(request)
            try:
                secure = getattr(getattr(response.raw, "_connection", None), "sock", None)
                if secure is not None:
                    peer = secure.getpeercert(True)
            finally:
                response.raw.close()
        finally:
            session.close()
    if peer:
        result.update(accepted=True, leaf_sha256=hashlib.sha256(peer).hexdigest())
    else:
        result["error_class"] = "peer_certificate_unavailable"


result = {"version": "Python " + sys.version.split()[0], "accepted": False,
          "leaf_sha256": "", "error_class": "", "sources": []}
try:
    config = json.load(sys.stdin)
    probe(config, result)
except ImportError:
    result["error_class"] = "package_unavailable"
except Exception as error:
    result["error_class"] = classify(error)
print(json.dumps(result, separators=(",", ":")))
