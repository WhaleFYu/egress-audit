"""最小的回归测试：体检结果必须永远能 JSON 序列化。

来由：这个脚本在 GitHub runner 上第一次真正跑起来就崩了——
`loopback-self-connect` 成功时把 socket 对象放进了 detail，
`json.dumps` 抛 `TypeError: Object of type socket is not JSON serializable`。
本地环境里回环被策略拦（永远走失败分支），所以这个分支从没被走到过。
教训写进测试：**别人的环境会走到你没走过的那条分支。**
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import egress_audit as E  # noqa: E402


class FakeSock:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class JsonableTest(unittest.TestCase):
    def test_jsonable_handles_objects(self):
        rows = [{"check": "x", "detail": FakeSock()}, {"detail": b"\x00\x01"}, {"detail": None}]
        out = json.dumps(E._jsonable(rows))
        self.assertIn("FakeSock", out)

    def test_loopback_ok_path_is_serializable(self):
        """模拟本机策略放行回环：连上了也不能把 socket 塞进结果。"""
        fake = FakeSock()
        real = E.socket.create_connection
        E.socket.create_connection = lambda *a, **kw: fake
        try:
            row = E.check_loopback()
        finally:
            E.socket.create_connection = real
        self.assertEqual(row["verdict"], "works")
        self.assertIsInstance(row["detail"], str)
        self.assertTrue(fake.closed, "连上的 socket 必须被关掉，别泄漏 fd")
        json.dumps(E._jsonable(row))     # 不抛异常即通过

    def test_all_checks_serializable(self):
        """不加网络断言，只断言形状：任何 check 的输出都得能进 JSON。"""
        rows = [E._res(lambda: 1)]
        json.dumps(E._jsonable(rows))


if __name__ == "__main__":
    unittest.main(verbosity=2)
