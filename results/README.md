# results/ —— 各家沙箱的实测结果合集

这个目录存 `egress_audit.py --json` 的原始输出。一个文件 = 一台机器 / 一个沙箱在某天的一次体检。

存在它的理由很简单：**"agent 连不上"是个含糊的说法，而这四种"连不上"的处置方式完全不同**——
重试、换代理、换域名、少花钱、还是立刻停下通知人。只看错误信息分不清，只能实测。

## 文件名

```
<provider>-<region>-<YYYY-MM-DD>.json
huawei-cloud-ecs-beijing-2026-11-25.json
modal-us-east-1-2026-12-01.json
github-actions-runner-2026-12-01.json
```

同一台机器换一天就再存一个文件，别覆盖——时间序列本身有用。

## 怎么产生

```bash
pip install nothing   # 零依赖，只用标准库
EGRESS_PROXY=http://127.0.0.1:18081 \
EGRESS_STUB_HOSTS=example.com \
  python3 egress_audit.py --json > results/<provider>-<region>-<date>.json
```

`EGRESS_STUB_HOSTS` 可选：填一个"应该有真实响应"的主机，用来检测**假成功**——返回 `200` 但 body 是几个字节的
`OK`。不填则该项记 `error`。

## 字段

| 字段 | 含义 |
|---|---|
| `check` | 检查项名：`system-dns` / `raw-udp-dns` / `raw-tcp` / `loopback-self-connect` / `proxy-connect` / `stub-detection` / `tls-issuer` |
| `verdict` | 结论，取值见 `check_results.py` 里的 `VERDICTS` |
| `target` | 打的目标（域名 / IP:端口） |
| `detail` | 原始异常或响应行，不做美化——保留现场 |
| `ms` | 耗时；`policy-refused` 常常是 **< 5ms**，这就是它和"超时"最直观的区别 |

## 提交前请自查（重要）

- **不要把凭据写进 detail**。如果把 URL 里的 `?key=...` 或 `Authorization` 头带进来了，先删掉再提交。
- **不要把内网主机名/私网 IP 原样提交**（`10.x` / `192.168.x` 之类），换成 `internal-host`。
- 允许新增字段（比如你自己加的 `provider_version`），`check_results.py` 只校验几个必需字段。
- 一个文件对应一次真实运行。不要手写、不要补全没跑过的检查项——这个目录的价值全在"没被修饰过"。

## 校验

```bash
python3 check_results.py            # 本地
python3 check_results.py --strict   # CI 里用，有问题就退出 1
```
