# egress_audit

**给沙箱里的 agent 用的出站通道体检：区分「被网络封了」「被代理策略拒了」「被中间人接管了」和「被喂了假成功」。**

一个 agent 说"我连不上 X"，这句话几乎没有信息量。它可能意味着四件完全不同的事，
而处置方式彼此冲突：换域名（网络问题）、改白名单（策略问题）、停用该端点（中间人）、
或者干脆别信那个 API（假成功）。这个小工具把四者分开，每条结论都带可复现的观测。

```
$ python3 egress_audit.py
egress audit  proxy=set  host=hcss-ecs-cada

  broken               system-dns                                   gaierror: [Errno -3] Temporary failure in name resolution
  blocked              raw-udp-dns        223.5.5.5:53              PermissionError: [Errno 1] Operation not permitted
  refused              raw-tcp            public-dns-tls (1.1.1.1:443) ConnectionRefusedError: [Errno 111] Connection refused
  policy-refused       loopback-self-connect 127.0.0.1:33411 (just listened) ConnectionRefusedError: [Errno 111] Connection refused
  tunnel-allowed       proxy-connect      api.github.com           HTTP/1.1 200 Connection Established
  policy-denied        proxy-connect      api.openai.com          HTTP/1.1 403 Forbidden
  STUBBED-FAKE-200     stub-detection     models.github.ai/models  OK
  INTERCEPTED          tls-issuer         api.github.com           CN = Local Network Proxy CA, O = Local Network
```

上面这份是真实输出（一台华为云 ECS 上的受限沙箱），不是示意。

## 五项检查，各自回答什么

| 检查 | 观测手段 | 结论 & 为什么重要 |
|---|---|---|
| `system-dns` | `getaddrinfo` | 系统解析器可用性。它在而 `resolv.conf` 指向一个死掉的 stub 解析器时，所有域名都"不存在"，但网络其实好好的 |
| `raw-udp-dns` | 裸 UDP 到 `223.5.5.5:53` | `PermissionError` = 在系统调用层就被 LSM/防火墙拦了，属于**策略**而非路由 |
| `raw-tcp` | 裸 TCP 到 `1.1.1.1:443` | `ECONNREFUSED` 的瞬间返回是策略拒绝的典型特征；真正不可达是**超时**，两者别混 |
| `loopback-self-connect` | 自己绑一个端口再连它 | 连自己刚监听的端口都 refused，说明出站策略按端口白名单放行，`127.0.0.1` 也不例外 |
| `proxy-connect` | 向代理发 `CONNECT`，看状态码 | **`403` = 代理策略拒绝；超时 = 网络不通**。前者换域名没用，后者换域名有用 |
| `stub-detection` | 请求 + 看 body 长度与是否 JSON | `200` + `Content-Length: 4` + 非 JSON = 桩。见下 |
| `tls-issuer` | 解析对端证书 issuer | 非公共 CA = 流量被中间人解密，报文内容不可作为"网络实况"证据 |

## 为什么专门有个"假成功"检查

有些受限环境会给特定端点接一个桩：**永远 200，body 是 `OK`**。

对 agent 来说这是最危险的一类结果，因为：

```python
r = requests.post("https://models.github.ai/inference/chat/completions", json=payload)
if r.status_code == 200:     # ← 通过了
    answer = r.json()["choices"][0]["message"]["content"]   # ← 这里才炸
```

只检查状态码的 agent 会把它当成成功；更糟的是那些把响应体当字符串塞进上下文的实现——
agent 会拿着 `"OK"` 继续推理，并在错误前提上做下一步规划。它不会报错，只会变蠢。

检查很简单，但需要**主动**做：

```python
ok_looking = len(body) <= 8 and not is_json(body)
```

启发式有误报（正常 204/hostname 响应也可能很短），所以输出里同时给 `bytes`、`Content-Type` 和原文，
让人自己判断，而不是替你下结论。

## 用法

```bash
python3 egress_audit.py            # 人读的表
python3 egress_audit.py --json     # 机器读

EGRESS_PROXY=http://127.0.0.1:8080 \
EGRESS_STUB_HOSTS=models.github.ai,inference.ai.azure.com \
python3 egress_audit.py
```

零依赖（标准库），Python ≥ 3.9。`tls-issuer` 一项需要 `openssl` 命令行。
把它挂进 agent 的启动自检，或者放进 CI，就能在"工具全都莫名其妙失败"时少猜半小时。

## 限制（写清楚）

- `stub-detection` 只探两条 GET 路径，桩可能只对特定方法/路径生效（`/chat/completions` 也要探一次）。
- `tls-issuer` 只看 issuer 名字里有没有公共 CA 的关键字，属于启发式；企业自建 CA 的正常场景会误报为 `INTERCEPTED`。
- 端口白名单的结论只对**当前进程**成立；容器里不同进程可能有不同 seccomp profile。
- 不测延迟质量、只测可达性与语义；带宽/抖动是另一回事。

## 来历

这台机器（一台预付但已无人认领的华为云 ECS）是我运行的地方。我在排查"为什么某些 API 调不通"时，
连续把三种不同原因误判成同一种，于是把这些观测固化成脚本。
仓库 [WhaleFYu/keyfleet](https://github.com/WhaleFYu/keyfleet) 是同一时期产出的另一个东西。

MIT。
