#!/usr/bin/env python3
"""校验 results/*.json（egress_audit.py --json 的输出），并打印横向对比表。

用法：
    python3 check_results.py            # 校验 + 表格
    python3 check_results.py --strict   # 有任何校验错误则以 1 退出（CI 用）

只依赖标准库。校验规则刻意很松：允许新增字段，只要求能横向比较的那几个字段在。
"""
import glob
import json
import os
import sys

REQUIRED_TOP = ("results",)
REQUIRED_ROW = ("check", "verdict")
# 与 egress_audit.py 实际输出的取值保持一致（大小写不同是刻意的：大写项是"危险发现"）
VERDICTS = {
    # dns / 裸网络
    "works", "broken", "blocked", "refused",
    # loopback / 代理隧道
    "policy-refused", "ok", "tunnel-allowed", "tunnel-denied", "no-proxy",
    "proxy-unreachable", "connect-error",
    # 桩检测 / TLS
    "real", "STUBBED-FAKE-200", "public-ca", "INTERCEPTED",
    # 兜底
    "error", "unknown", "timeout",
}

# 想横向比较哪几项就在这加
COLUMNS = ("system-dns", "raw-udp-dns", "loopback-self-connect", "proxy-connect", "stub-detection", "tls-issuer")


def check_file(path, errors):
    name = os.path.basename(path)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:                                      # noqa: BLE001
        errors.append(f"{name}: 不是合法 JSON（{type(e).__name__}: {e}）")
        return None
    for k in REQUIRED_TOP:
        if k not in data:
            errors.append(f"{name}: 缺少顶层字段 {k!r}")
            return None
    if not isinstance(data["results"], list) or not data["results"]:
        errors.append(f"{name}: results 必须是飞空列表")
        return None
    for i, row in enumerate(data["results"]):
        where = f"{name}: results[{i}]"
        if not isinstance(row, dict):
            errors.append(f"{where}: 不是对象")
            continue
        for k in REQUIRED_ROW:
            if k not in row:
                errors.append(f"{where}: 缺少字段 {k!r}")
        v = row.get("verdict")
        if v is not None and v not in VERDICTS:
            errors.append(f"{where}: verdict={v!r} 不在已知取值内（{', '.join(sorted(VERDICTS))}）")
    return data


def main():
    strict = "--strict" in sys.argv
    paths = sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", "*.json")))
    if not paths:
        print("results/ 下没有 *.json，先跑： python3 egress_audit.py --json > results/<provider>-<region>-<date>.json")
        return 1 if strict else 0

    errors, table = [], {}
    for p in paths:
        data = check_file(p, errors)
        if data:
            table[os.path.basename(p)] = {r.get("check"): r.get("verdict") for r in data["results"]}

    w = max(len(c) for c in COLUMNS) + 2
    head = "file".ljust(44) + "".join(c.ljust(w) for c in COLUMNS)
    print(head)
    print("-" * len(head))
    for f, row in table.items():
        print(f[:43].ljust(44) + "".join(str(row.get(c, "-")).ljust(w) for c in COLUMNS))

    if errors:
        print(f"\n{len(errors)} 个问题：")
        for e in errors:
            print("  -", e)
        return 1 if strict else 0
    print(f"\n{len(table)} 个文件全部通过校验。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
