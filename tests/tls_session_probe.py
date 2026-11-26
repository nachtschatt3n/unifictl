#!/usr/bin/env python3
"""Loopback-only CLI TLS regression. Requires Python 3 and openssl on PATH.

Run after cargo build: python3 tests/tls_session_probe.py target/debug/unifictl
All certificates, configuration and synthetic credentials live in a temporary directory.
"""
import http.server
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading


def main():
    binary = Path(sys.argv[1]).resolve(strict=True)
    openssl = shutil.which("openssl")
    if not openssl:
        raise SystemExit("openssl is required for this TLS regression")
    with tempfile.TemporaryDirectory(prefix="unifictl-tls-probe-") as name:
        work = Path(name)
        conf = work / "openssl.cnf"
        conf.write_text("[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage=serverAuth\n")
        cert, key = work / "cert.pem", work / "key.pem"
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config", str(conf), "-out", str(cert), "-keyout", str(key)], check=True, capture_output=True)
        calls = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                assert body["password"] == "synthetic-password"
                calls.append(("POST", self.path))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-CSRF-Token", "synthetic-token")
                self.end_headers()
                self.wfile.write(b'{"ok":true}')

            def do_GET(self):
                assert self.headers["X-CSRF-Token"] == "synthetic-token"
                calls.append(("GET", self.path))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"data":[]}')

            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            cases = [("untrusted-default", "localhost", None, None, False), ("custom-ca", "localhost", True, cert, True), ("wrong-hostname", "127.0.0.1", True, cert, False), ("explicit-insecure", "localhost", False, None, True)]
            for label, host, verify, ca, success in cases:
                cfgdir = work / label
                cfgdir.mkdir()
                local = {"url": f"https://{host}:{server.server_port}", "username": "synthetic-user", "password": "synthetic-password", "site": "default"}
                if verify is not None:
                    local["verify_tls"] = verify
                if ca is not None:
                    local["ca_file"] = str(ca)
                (cfgdir / "config.yaml").write_text(json.dumps({"local": local}))
                env = {k: v for k, v in os.environ.items() if k.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
                env.update(UNIFICTL_CONFIG_DIR=str(cfgdir), UNIFICTL_NO_SESSION_CACHE="1")
                before = len(calls)
                result = subprocess.run([str(binary), "--no-project-config", "local", "site", "list", "-o", "json"], cwd=work, env=env, capture_output=True, text=True, timeout=20)
                assert (result.returncode == 0) == success, (label, result.returncode, result.stderr)
                assert len(calls) - before == (2 if success else 0), (label, calls[before:])
                assert "synthetic-password" not in result.stdout + result.stderr
                print(f"PASS {label}: {len(calls) - before} authenticated HTTP requests")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    main()
