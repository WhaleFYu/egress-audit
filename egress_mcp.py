#!/usr/bin/env python3
"""egress_mcp —— 把一个"为什么连不上"的诊断器暴露成 MCP 工具（stdio，零依赖）。

MCP 客户端（Claude Desktop / Cursor / 任意 agent 框架）只需要一行配置：

    {"mcpServers": {"egress-audit": {"command": "python3", "args": ["/abs/path/egress_mcp.py"]}}}

然后 agent 就能调用：

  diagnose_url(url="https://api.deepseek.com/models", proxy="http://127.0.0.1:8080")
  -> {"verdict": "PROXY-POLICY-DENY", "observations": {...}, "remediation": "..."}

存在理由：agent 说"网络不可用"时，四种原因（策略拒绝 / 隧道挂死 / 限额伪装成上游 429 /
200 但内容被截断）的处置互相矛盾。只看状态码的 agent 会选错方向，然后把算力烧在不存在的问题上。

判据全部保留：返回里有每一步的原始观测，agent 可以自己复核，而不是相信一句结论。

只写 stdout 的 JSON-RPC；日志一律 stderr（否则会污染协议流）。
"""
from __future__ import annotations

import json
import socket
import ssl
import sys
import time
import urllib.parse

SERVER_INFO = {"name": "egress-audit", "version": "1.0.0"}
PROTOCOL = "2025-06-18"
MAX_BODY = 8192

REMEDIATION = {
    "PROXY-POLICY-DENY": "代理在 CONNECT 上直接拒绝（不是超时）。换域名/重试都无用；需要改白名单或换出口。",
    "PROXY-AUTH-REQUIRED": "代理要认证（407）。给 --proxy 带上凭据，或改用已认证的出口。",
    "PROXY-UNREACHABLE": "连代理本身失败——先确认代理地址/端口，别去查上游。",
    "HANG-IN-TUNNEL": "CONNECT 成功但读不到响应：失败发生在隧道内部（策略放行后掐断，或该主机本就不提供该协议/端口）。别把它当成上游限流。",
    "EMPTY-REPLY": "403/404 且 body 恰好 0 字节。正常端点通常不会在自己的路径上回空 body，更像中间层合成的拒绝；换一条出口复测再下结论。",
    "STUB-FAKE-OK": "200 但 body 极短且不是正常 JSON。这是假成功——只看状态码会把它当成有效响应。",
    "RELAY-5XX": "502/503/504 且 body 是出口自己写的话术（如 Upstream fetch failed）：失败在「出口 → 源站」这一段，既不是源站回错，也不是策略拒绝。别去改请求参数。",
    "UPSTREAM-ERROR": "上游正常返回了错误（4xx/5xx）。这是端点侧问题，不是网络问题。",
    "OK": "拿到了正常的 HTTP 响应；注意这只证明「这一次、从这条出口、拿到内容」，不证明长期可用。",
    "TLS-MITM": "TLS 证书的 issuer 不是公共 CA（疑似本地中间人）。响应内容不能当作端点证据。",
    "DNS-FAIL": "本地解析器查不到这个域名。先换解析（或走代理让代理侧解析）；在这一步失败时不要下「端点不可达」的结论。",
    "TIMEOUT": "在超时内没有任何响应。先判断是 DNS、TCP 还是读阶段挂住，见 observations。",
}


def _jsonable(o):
    if isinstance(o, dict):
        return {k: _jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_jsonable(v) for v in o]
    if isinstance(o, (str, int, float, bool)) or o is None:
        return o
    return repr(o)


def _ms(t0: float) -> int:
    return int((time.time() - t0) * 1000)


def diagnose(url: str, proxy: str | None = None, timeout: float = 8.0) -> dict:
    """分层体检一个 URL，返回判决 + 每一步的原始观测。"""
    obs: dict = {"url": url, "proxy": proxy, "timeout": timeout}
    u = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme != "http" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    obs["target"] = f"{host}:{port}"

    t0 = time.time()
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        obs["dns"] = {"ok": True, "ip": infos[0][4][0], "ms": _ms(t0)}
    except Exception as e:
        obs["dns"] = {"ok": False, "error": f"{type(e).__name__}: {e}", "ms": _ms(t0)}
        # 有代理时本地 DNS 失败是正常的（解析在代理侧做），继续走代理路径
        if not proxy:
            return _finish("DNS-FAIL", obs)

    sock = None
    t0 = time.time()
    try:
        if proxy:
            p = urllib.parse.urlsplit(proxy if "://" in proxy else "http://" + proxy)
            try:
                sock = socket.create_connection((p.hostname, p.port or 8080), timeout=timeout)
            except Exception as e:
                obs["connect"] = {"ok": False, "error": f"{type(e).__name__}: {e}", "ms": _ms(t0)}
                return _finish("PROXY-UNREACHABLE", obs)
            sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 2048:
                chunk = sock.recv(512)
                if not chunk:
                    break
                head += chunk
            line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            code = int(line.split()[1]) if len(line.split()) > 1 else 0
            obs["connect"] = {"via": "proxy", "status_line": line, "code": code, "ms": _ms(t0)}
            if code == 403:
                return _finish("PROXY-POLICY-DENY", obs)
            if code == 407:
                return _finish("PROXY-AUTH-REQUIRED", obs)
            if code != 200:
                return _finish("PROXY-UNREACHABLE", obs)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)
            obs["connect"] = {"via": "direct", "ok": True, "ms": _ms(t0)}
    except Exception as e:
        obs.setdefault("connect", {})
        obs["connect"].update({"ok": False, "error": f"{type(e).__name__}: {e}", "ms": _ms(t0)})
        return _finish("HANG-IN-TUNNEL", obs)

    t0 = time.time()
    try:
        ctx = ssl.create_default_context()
        verified = True
        try:
            ssock = ctx.wrap_socket(sock, server_hostname=host)
        except ssl.SSLCertVerificationError as e:
            # 不静默降级：先如实记下校验失败，再重建一条不校验的连接去看 issuer 到底是谁
            verified = False
            obs.setdefault("notes", []).append(f"cert verification failed: {e.verify_message}")
            sock2 = (socket.create_connection((urllib.parse.urlsplit(proxy).hostname, urllib.parse.urlsplit(proxy).port), timeout=timeout)
                     if proxy else socket.create_connection((host, port), timeout=timeout))
            if proxy:
                sock2.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
                h = b""
                while b"\r\n\r\n" not in h and len(h) < 2048:
                    c = sock2.recv(512)
                    if not c:
                        break
                    h += c
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            ssock = ctx2.wrap_socket(sock2, server_hostname=host)
        cert = ssock.getpeercert() or {}
        issuer = dict(x[0] for x in cert.get("issuer", ())) if cert else {}
        obs["tls"] = {"verified": verified, "issuer_cn": issuer.get("commonName"),
                      "issuer_org": issuer.get("organizationName"), "not_after": cert.get("notAfter"), "ms": _ms(t0)}
        sock = ssock
    except Exception as e:
        obs["tls"] = {"ok": False, "error": f"{type(e).__name__}: {e}", "ms": _ms(t0)}
        try:
            sock.close()
        except Exception:
            pass
        return _finish("TIMEOUT", obs)

    t0 = time.time()
    try:
        sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: egress-audit-mcp/1.0\r\n"
                      f"Accept: */*\r\nConnection: close\r\n\r\n").encode())
        raw = b""
        while len(raw) < MAX_BODY:
            chunk = sock.recv(2048)
            if not chunk:
                break
            raw += chunk
            if b"\r\n\r\n" in raw:
                h, _, body = raw.partition(b"\r\n\r\n")
                if len(body) >= 64:
                    break
        head_b, _, body = raw.partition(b"\r\n\r\n")
        status = int(head_b.split(b"\r\n", 1)[0].split()[1]) if head_b else 0
        ctype = ""
        for line in head_b.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-type:"):
                ctype = line.split(b":", 1)[1].strip().decode("latin-1", "replace")
        obs["http"] = {"status": status, "ctype": ctype, "bytes": len(body),
                       "preview": body[:120].decode("utf-8", "replace"), "ms": _ms(t0)}
    except Exception as e:
        obs["http"] = {"ok": False, "error": f"{type(e).__name__}: {e}", "ms": _ms(t0)}
        return _finish("HANG-IN-TUNNEL", obs)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    status, n, preview = obs["http"]["status"], obs["http"]["bytes"], obs["http"]["preview"].strip()
    if status == 200 and n <= 8 and preview.upper() in ("OK", ""):
        return _finish("STUB-FAKE-OK", obs)
    if status in (403, 404) and n == 0:
        return _finish("EMPTY-REPLY", obs)
    if status in (502, 503, 504) and any(k in preview.lower() for k in
                                        ("upstream fetch failed", "cannot connect to", "bad gateway", "proxy error")):
        return _finish("RELAY-5XX", obs)
    if status >= 400:
        return _finish("UPSTREAM-ERROR", obs)
    return _finish("OK", obs)


def _finish(verdict: str, obs: dict) -> dict:
    cn = (obs.get("tls") or {}).get("issuer_org") or ""
    if "Local" in cn or "local" in cn:
        obs["notes"] = ["TLS issuer 看起来是本地中间人；响应内容不能当作端点证据。"]
    return {"verdict": verdict, "remediation": REMEDIATION.get(verdict, ""), "observations": _jsonable(obs)}


TOOLS = [
    {
        "name": "diagnose_url",
        "description": ("Layer-by-layer diagnosis of 'why can't I reach this URL': proxy CONNECT policy vs tunnel hang vs "
                        "MITM vs empty reply vs fake 200. Returns a verdict plus every raw observation it was based on, "
                        "so the caller can re-check instead of trusting a one-line conclusion."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL or host to check, e.g. https://api.deepseek.com/models"},
                "proxy": {"type": "string", "description": "Optional HTTP proxy, e.g. http://127.0.0.1:8080 (CONNECT is used for https)"},
                "timeout": {"type": "number", "description": "Seconds per phase (default 8)"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "diagnose_hosts",
        "description": "Run diagnose_url over several hosts at once (comma separated or array); returns one verdict per host.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hosts": {"type": "string", "description": "Comma separated hosts/URLs"},
                "proxy": {"type": "string", "description": "Optional HTTP proxy"},
                "timeout": {"type": "number", "description": "Seconds per phase (default 6)"},
            },
            "required": ["hosts"],
        },
    },
]


def call_tool(name: str, args: dict) -> dict:
    if name == "diagnose_url":
        return diagnose(str(args.get("url") or ""), args.get("proxy"), float(args.get("timeout") or 8))
    if name == "diagnose_hosts":
        raw = args.get("hosts") or ""
        hosts = raw if isinstance(raw, list) else [x.strip() for x in str(raw).split(",") if x.strip()]
        return {"results": [diagnose(h, args.get("proxy"), float(args.get("timeout") or 6)) for h in hosts]}
    raise KeyError(name)


def handle(msg: dict) -> dict | None:
    mid = msg.get("id")
    method = msg.get("method")
    if mid is None:  # notification
        return None
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": PROTOCOL, "capabilities": {"tools": {}}, "serverInfo": SERVER_INFO}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/call":
        params = msg.get("params") or {}
        try:
            out = call_tool(str(params.get("name")), params.get("arguments") or {})
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False, indent=2)}],
                "isError": False}}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}], "isError": True}}
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}


def serve() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception as e:
            print(f"bad json: {e}", file=sys.stderr)
            continue
        out = handle(msg)
        if out is not None:
            sys.stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        print(json.dumps(diagnose("https://api.github.com/", None, 6), ensure_ascii=False)[:600])
    else:
        serve()
