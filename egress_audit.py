#!/usr/bin/env python3
"""egress_audit —— 给沙箱里的 agent 用的出站通道体检。

回答四个问题，每个都有可复现的观测，而不是"感觉连不上"：
  1. 系统解析器还能用吗？            (getaddrinfo)
  2. 裸 socket 能直连吗？            (UDP/53, TCP/443, 以及本地回环)
  3. 出站代理是"封了"还是"绕了"？    (CONNECT 的状态码：403 = 策略拒绝，超时 = 网络不通)
  4. 代理有没有给某些端点返回**假成功**？(200 但 body 极短且不是 JSON)

第 4 条是最阴的：一个只看状态码的 agent 会把 200/"OK" 当成推理结果，
然后继续在错误的前提上做规划。

用法:
  python3 egress_audit.py                # 全量体检
  python3 egress_audit.py --json         # 机器可读
环境变量: EGRESS_PROXY (默认读 http_proxy / HTTP_PROXY)，EGRESS_STUB_HOSTS (逗号分隔)
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.parse
import urllib.request

PROXY = (os.environ.get("EGRESS_PROXY") or os.environ.get("http_proxy")
         or os.environ.get("HTTP_PROXY") or "")
DEFAULT_STUB_HOSTS = "models.github.ai,inference.ai.azure.com"
STUB_HOSTS = [h for h in (os.environ.get("EGRESS_STUB_HOSTS") or DEFAULT_STUB_HOSTS).split(",") if h]
TIMEOUT = 6.0


def _res(fn, *a, **kw):
    t = time.time()
    try:
        return {"ok": True, "value": fn(*a, **kw), "ms": int((time.time() - t) * 1000)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "ms": int((time.time() - t) * 1000)}


# 1 ------------------------------------------------------------- 系统解析器
def check_dns() -> dict:
    r = _res(lambda: socket.getaddrinfo("example.com", 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0])
    return {"check": "system-dns", "verdict": "works" if r["ok"] else "broken",
            "detail": r.get("value") or r.get("error"), "ms": r["ms"]}


# 2 ------------------------------------------------------------- 裸 socket
def check_udp_dns(server="223.5.5.5") -> dict:
    def go():
        tid = 0x1234
        pkt = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(TIMEOUT)
        try:
            s.sendto(pkt, (server, 53))
            data, _ = s.recvfrom(512)
            return f"{len(data)} bytes from {server}"
        finally:
            s.close()
    r = _res(go)
    return {"check": "raw-udp-dns", "target": f"{server}:53",
            "verdict": "works" if r["ok"] else "blocked", "detail": r.get("value") or r.get("error"), "ms": r["ms"]}


def check_tcp(ip, port, label) -> dict:
    def go():
        s = socket.socket()
        s.settimeout(TIMEOUT)
        try:
            s.connect((ip, port))
            return "connected"
        finally:
            s.close()
    r = _res(go)
    v = "works" if r["ok"] else ("refused" if "Refused" in str(r.get("error")) else "blocked")
    return {"check": "raw-tcp", "target": f"{label} ({ip}:{port})", "verdict": v,
            "detail": r.get("value") or r.get("error"), "ms": r["ms"]}


def check_loopback() -> dict:
    """一个自己刚绑上、绝对在监听的端口，能不能连上？连不上就是策略在拦。"""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    r = _res(lambda: socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT))
    srv.close()
    v = "works" if r["ok"] else ("policy-refused" if "Refused" in str(r.get("error")) else "blocked")
    return {"check": "loopback-self-connect", "target": f"127.0.0.1:{port} (just listened)",
            "verdict": v, "detail": r.get("value") or r.get("error"), "ms": r["ms"]}


# 3 ------------------------------------------------------------- 代理策略
def check_proxy_connect(host, path="/") -> dict:
    """用 CONNECT 探一个域名：区分「代理策略拒绝(403)」与「网络真不通(超时)」。"""
    if not PROXY:
        return {"check": "proxy-connect", "target": host, "verdict": "no-proxy", "detail": "-"}
    p = urllib.parse.urlsplit(PROXY)
    t = time.time()
    try:
        s = socket.create_connection((p.hostname, p.port or 3128), timeout=TIMEOUT)
    except Exception as e:
        return {"check": "proxy-connect", "target": host, "verdict": "proxy-unreachable",
                "detail": f"{type(e).__name__}", "ms": int((time.time() - t) * 1000)}
    try:
        s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 2048:
            chunk = s.recv(512)
            if not chunk:
                break
            buf += chunk
        head = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        code = int(head.split()[1]) if len(head.split()) > 1 else 0
        verdict = {200: "tunnel-allowed", 403: "policy-denied", 407: "proxy-auth-required"}.get(code, "unexpected")
        return {"check": "proxy-connect", "target": host, "verdict": verdict, "status": code,
                "detail": head, "ms": int((time.time() - t) * 1000)}
    except Exception as e:
        return {"check": "proxy-connect", "target": host, "verdict": "connect-error",
                "detail": type(e).__name__, "ms": int((time.time() - t) * 1000)}
    finally:
        s.close()


# 4 ------------------------------------------------------------- 假成功
def check_stub(host, path="/models") -> dict:
    url = f"https://{host}{path}"
    t = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "egress-audit/1.0",
                                                   "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read(4096)
            ctype = resp.headers.get("Content-Type", "")
        ms = int((time.time() - t) * 1000)
        try:
            json.loads(body.decode("utf-8", "replace"))
            looks_json = True
        except Exception:
            looks_json = False
        stub = len(body) <= 8 and not looks_json
        return {"check": "stub-detection", "target": f"{host}{path}",
                "verdict": "STUBBED-FAKE-200" if stub else "real-response",
                "status": 200, "bytes": len(body), "ctype": ctype,
                "body": body[:40].decode("latin-1", "replace"), "ms": ms}
    except Exception as e:
        return {"check": "stub-detection", "target": f"{host}{path}", "verdict": "error",
                "detail": f"{type(e).__name__}: {e}", "ms": int((time.time() - t) * 1000)}


# 5 ------------------------------------------------------------- TLS 中间人
def check_mitm(host="api.github.com") -> dict:
    if not PROXY:
        return {"check": "tls-issuer", "target": host, "verdict": "no-proxy"}
    p = urllib.parse.urlsplit(PROXY)
    try:
        s = socket.create_connection((p.hostname, p.port or 3128), timeout=TIMEOUT)
        s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(512)
            if not chunk:
                break
            buf += chunk
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        w = ctx.wrap_socket(s, server_hostname=host)
        der = w.getpeercert(binary_form=True)
        info = ssl._ssl._test_decode_cert  # noqa: F841  (peercert 在 CERT_NONE 下为空)
        w.close()
        # 用 openssl 解析 DER issuer（避免额外依赖）
        import subprocess, tempfile
        with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as fh:
            fh.write(der)
            path = fh.name
        out = subprocess.run(["openssl", "x509", "-inform", "DER", "-in", path, "-noout", "-issuer"],
                             capture_output=True, text=True).stdout.strip()
        os.unlink(path)
        issuer = out.replace("issuer=", "")
        public_ca = any(k in issuer for k in ("DigiCert", "Let's Encrypt", "ISRG", "Sectigo", "GlobalSign", "ZeroSSL", "Amazon", "Google Trust"))
        return {"check": "tls-issuer", "target": host,
                "verdict": "public-ca" if public_ca else "INTERCEPTED",
                "issuer": issuer, "sha256_prefix": __import__("hashlib").sha256(der).hexdigest()[:16]}
    except Exception as e:
        return {"check": "tls-issuer", "target": host, "verdict": "error", "detail": f"{type(e).__name__}"}


def main() -> int:
    rows = [check_dns(), check_udp_dns(),
            check_tcp("1.1.1.1", 443, "public-dns-tls"),
            check_loopback()]
    for h in ("api.github.com", "api.openai.com"):
        rows.append(check_proxy_connect(h))
    for h in STUB_HOSTS:
        rows.append(check_stub(h))
    rows.append(check_mitm())

    if "--json" in sys.argv:
        print(json.dumps({"proxy": bool(PROXY), "results": rows}, ensure_ascii=False, indent=1))
        return 0

    print(f"egress audit  proxy={'set' if PROXY else 'none'}  host={socket.gethostname()}\n")
    for r in rows:
        extra = r.get("detail") or r.get("body") or r.get("issuer") or ""
        print(f"  {r['verdict']:<20} {r['check']:<22} {str(r.get('target','')):<28} {str(extra)[:70]}")
    bad = [r for r in rows if r["verdict"] in ("STUBBED-FAKE-200", "INTERCEPTED", "policy-refused")]
    print(f"\n{len(bad)} 项需要注意：{'、'.join(sorted({r['verdict'] for r in bad})) or '无'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
