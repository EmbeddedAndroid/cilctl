#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""A stand-in CIL API for tests/test_cilctl.py. Lease 7 is ready with a
sentinel private key, lease 8 has failed; DELETE answers released for 7
and failed for 8. DELETE of lease 2 is a 504 page every other call (a
slow teardown; the lease stays ready), of 3 always (stays ready), and of
4 always but the lease is released anyway. Leases 5, 6, 10 and 11 are
ready with a bad connection (an ssh option as the user, no user, port
70000, a space in the host).
Anything under /html/ is an HTML 502 page. Under /multi/ the CIL has two
pools, under /images/ one pool with two images, under /fail/ a new lease
is lease 8. With $STUB_TLS (a
directory) it serves https for localhost and writes its CA certificate
to $STUB_TLS/ca.pem first. Prints its port on stdout."""
import json, os, ssl
from http.server import BaseHTTPRequestHandler, HTTPServer

# split so the repo never holds a key header
KEY = "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nSENTINEL-KEY-MATERIAL\n-----END " + "OPENSSH PRIVATE KEY-----\n"
# a test CA and its certificate for localhost (a DNS name only, no IP
# address), for tests only
TLS_CA = """\
-----BEGIN CERTIFICATE-----
MIIBlzCCAT2gAwIBAgIUEJOuSI5+QgGOlsXdGKIW3vkptFUwCgYIKoZIzj0EAwIw
GTEXMBUGA1UEAwwOY2lsY3RsIHRlc3QgQ0EwHhcNMjYxMTIxMTgxMTE2WhcNNDYx
MTE2MTgxMTE2WjAZMRcwFQYDVQQDDA5jaWxjdGwgdGVzdCBDQTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABJJM3cKW0/13Jy0sNfkIXeK8A/nOoJYna4IUeYQg1Ipk
eJti04IZWLv9tt07bgiIfxH/Id5iFxh71d8uD16Hy+ajYzBhMB0GA1UdDgQWBBRG
gqERxyYg4SGjbeXkUGQAw2LXOzAfBgNVHSMEGDAWgBRGgqERxyYg4SGjbeXkUGQA
w2LXOzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQD
AgNIADBFAiA1s/wJd3PFNkozW5mIfxc9slW87BRfnrDxONW8rtM93wIhAIJThMNc
WlwXFPs4i5rFH7IjOU4AcY8TvGeUezHml7Bw
-----END CERTIFICATE-----
"""
TLS_CERT = """\
-----BEGIN CERTIFICATE-----
MIIBvTCCAWKgAwIBAgIUHSXKEj17X2/YS4Axz4l3g2pwquQwCgYIKoZIzj0EAwIw
GTEXMBUGA1UEAwwOY2lsY3RsIHRlc3QgQ0EwHhcNMjYxMTIxMTgxMTE2WhcNNDYx
MTE1MTgxMTE2WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAATk0p0SdFSGyhuccO3C/M5+PLlXggeaOTOC/obxw2sH7zR8wzfZ
e/hTZyq7oeBxEw42tc+HFRefK2ivnaXDgZ+To4GMMIGJMBQGA1UdEQQNMAuCCWxv
Y2FsaG9zdDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAK
BggrBgEFBQcDATAdBgNVHQ4EFgQUeIcesrF+qdzPiMCC5DW4Kx3j0FIwHwYDVR0j
BBgwFoAURoKhEccmIOEho23l5FBkAMNi1zswCgYIKoZIzj0EAwIDSQAwRgIhAMYJ
v73dy6iJHGaoA6ZDaGMXE2PsElS4B6/JaykagR3NAiEAnTgO4hoxx0XfNZZBiQcM
p21h/z5EUVeri74KS65udLw=
-----END CERTIFICATE-----
"""
TLS_KEY = "-----BEGIN " + "PRIVATE KEY-----\n" + """\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgak+qkFtjTaRceOmX
1K8p20gi4nSdh3mz45/I0/BteEmhRANCAATk0p0SdFSGyhuccO3C/M5+PLlXggea
OTOC/obxw2sH7zR8wzfZe/hTZyq7oeBxEw42tc+HFRefK2ivnaXDgZ+T
""" + "-----END " + "PRIVATE KEY-----\n"
CONN = {"user": "ubuntu", "host": "192.0.2.9", "port": 22, "fwd_host": "127.0.0.1", "fwd_port": 1,
        "private_key_pem": KEY}
POOL = {"id": 1, "name": "arm64", "max_concurrent": 12, "max_cpu": 12, "max_ram_mb": 20480, "max_disk_gb": 200,
        "allowed_images": ["ubuntu-24.04-arm64"], "env_keys": ["http_proxy", "https_proxy", "no_proxy"]}
POOLS = {"": [POOL], "/multi": [POOL, dict(POOL, id=2, name="x86", allowed_images=["ubuntu-24.04"])],
         "/images": [dict(POOL, allowed_images=["ubuntu-24.04-arm64", "debian-13-arm64"])], "/fail": [POOL]}


BAD = {5: dict(CONN, user="-oProxyCommand=touch${IFS}/tmp/cilctl-pwned"),
       6: {k: v for k, v in CONN.items() if k != "user"}, 10: dict(CONN, fwd_port=70000),
       11: dict(CONN, fwd_host="a b")}


def lease(i, st):
    return {"id": i, "status": st, "host_id": 1, "requester": "t", "image": "ubuntu-24.04-arm64",
            "cpu": 2, "ram_mb": 2048, "disk_gb": 20, "expires_at": "2026-11-13T20:00:00",
            "last_error": "boot timeout" if st == "failed" else None, "connection": BAD.get(i, CONN)}


DELETES = {2: 0}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def page(self, code):
        b = b"<html>gateway error</html>"
        self.send_response(code)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def split(self):
        for pre in ("/multi", "/images", "/fail"):
            if self.path.startswith(pre + "/"):
                return pre, self.path[len(pre):]
        return "", self.path

    def do_GET(self):
        pre, p = self.split()
        if p.startswith("/html/"):
            return self.page(502)
        if p == "/api/health":
            return self.reply({"status": "ok", "service": "cil", "version": "0.11.0"})
        if p == "/api/v1/pools":
            return self.reply(POOLS[pre])
        if p == "/api/v1/hosts":
            return self.reply([{"id": 1, "name": "host-1", "state": "ready", "max_concurrent": 3,
                                "cpu_budget": 16, "ram_mb_budget": 23552, "state_detail": "xen 4.20"}])
        if p == "/api/v1/images":
            return self.reply([{"name": "ubuntu-24.04-arm64", "enabled": True, "default_user": "ubuntu",
                                "arch": "aarch64"}])
        if p == "/api/v1/leases":
            return self.reply([lease(7, "ready"), lease(8, "failed")])
        if p == "/api/v1/leases/7":
            return self.reply(lease(7, "ready"))
        if p == "/api/v1/leases/8":
            return self.reply(lease(8, "failed"))
        if p in ("/api/v1/leases/2", "/api/v1/leases/3", "/api/v1/leases/5", "/api/v1/leases/6",
                 "/api/v1/leases/10", "/api/v1/leases/11"):
            return self.reply(lease(int(p.rsplit("/", 1)[1]), "ready"))
        if p == "/api/v1/leases/4":
            return self.reply(lease(4, "released"))
        if p == "/api/v1/leases/7/events":
            return self.reply([{"ts": "2026-11-13T19:00:00", "kind": "ready", "detail": "up"}])
        self.reply({"detail": "not found"}, 404)

    def do_POST(self):
        pre, p = self.split()
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        if p == "/api/v1/leases":
            with open(os.environ["STUB_POSTS"], "a") as f:
                f.write(json.dumps(body, sort_keys=True) + "\n")
            if set(body) - {"pool", "requester", "image", "cpu", "ram_mb", "disk_gb", "ttl_min", "npus"}:
                return self.reply({"detail": "unexpected field"}, 422)
            if "npus" in body and (type(body["npus"]) is not int or not 1 <= body["npus"] <= 4):
                return self.reply({"detail": "npus: 1 to 4 when given"}, 422)
            return self.reply(dict(lease(8 if pre == "/fail" else 7, "queued"), status="queued",
                                   npus=body.get("npus", 0)), 201)
        if p == "/api/v1/leases/7/extend":
            return self.reply(lease(7, "ready"))
        self.reply({"detail": "not found"}, 404)

    def do_DELETE(self):
        pre, p = self.split()
        if p == "/api/v1/leases/7":
            return self.reply(lease(7, "released"))
        if p == "/api/v1/leases/8":
            return self.reply(lease(8, "failed"))
        if p == "/api/v1/leases/2":
            DELETES[2] += 1
            if DELETES[2] % 2:
                return self.page(504)
            return self.reply(lease(2, "released"))
        if p in ("/api/v1/leases/3", "/api/v1/leases/4"):
            return self.page(504)
        self.reply({"detail": "not found"}, 404)


s = HTTPServer(("127.0.0.1", 0), H)
if os.environ.get("STUB_TLS"):
    c, k = (os.path.join(os.environ["STUB_TLS"], n) for n in ("cert.pem", "key.pem"))
    for n, t in ((c, TLS_CERT), (k, TLS_KEY), (os.path.join(os.environ["STUB_TLS"], "ca.pem"), TLS_CA)):
        with open(n, "w") as f:
            f.write(t)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(c, k)
    s.socket = ctx.wrap_socket(s.socket, server_side=True)
print(s.server_address[1], flush=True)
s.serve_forever()
