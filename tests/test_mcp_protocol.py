"""MCP 协议层回归测试——全部离线，不碰网络。

为什么这些断言值得写：MCP 客户端是**逐条 JSON-RPC** 的，任何一条回错就不再往下走；
而 stdout 里混进一行日志，整个会话就会静默失效（客户端只会说 "server failed to start"）。
所以这里既测分发逻辑，也测"子进程里 stdout 只有协议"。
"""
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import egress_mcp as M  # noqa: E402


class DispatchTest(unittest.TestCase):
    def test_initialize_reports_tools_capability(self):
        out = M.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(out["id"], 1)
        self.assertIn("tools", out["result"]["capabilities"])
        self.assertEqual(out["result"]["serverInfo"]["name"], "egress-audit")

    def test_notification_gets_no_response(self):
        self.assertIsNone(M.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_tools_list_shape(self):
        out = M.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = [t["name"] for t in out["result"]["tools"]]
        self.assertEqual(names, ["diagnose_url", "diagnose_hosts"])
        for t in out["result"]["tools"]:
            self.assertEqual(t["inputSchema"]["type"], "object")
            self.assertIn("description", t)

    def test_unknown_method_is_jsonrpc_error(self):
        out = M.handle({"jsonrpc": "2.0", "id": 3, "method": "nope"})
        self.assertEqual(out["error"]["code"], -32601)

    def test_bad_tool_comes_back_as_tool_error_not_crash(self):
        out = M.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                        "params": {"name": "no_such_tool", "arguments": {}}})
        self.assertTrue(out["result"]["isError"])
        self.assertIn("no_such_tool", out["result"]["content"][0]["text"])

    def test_every_verdict_has_remediation(self):
        # agent 拿到的如果不只是结论，还要有"下一步该改哪里"，否则它只会重试。
        for v in ("PROXY-POLICY-DENY", "HANG-IN-TUNNEL", "EMPTY-REPLY", "STUB-FAKE-OK", "RELAY-5XX", "DNS-FAIL", "OK"):
            self.assertTrue(M.REMEDIATION.get(v), v)


class StdioTest(unittest.TestCase):
    def test_stdout_carries_only_protocol_lines(self):
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ]
        inp = "\n".join(json.dumps(m) for m in msgs) + "\n"
        p = subprocess.run([sys.executable, os.path.join(HERE, "..", "egress_mcp.py")],
                           input=inp, capture_output=True, text=True, timeout=60)
        lines = [ln for ln in p.stdout.splitlines() if ln.strip()]
        self.assertEqual(len(lines), 2, f"stdout 只应有 2 条响应，实际: {p.stdout!r}")
        for ln in lines:
            self.assertEqual(json.loads(ln)["jsonrpc"], "2.0")


if __name__ == "__main__":
    unittest.main()
