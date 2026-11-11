# TCP sockmap offload 探针（P0）

只验证机制，不接任何生产路径，也不进 `sing-box-src` tarball。跑完就知道后面值不值得写。

## 它回答什么

| 问题 | 由哪个场景回答 |
| --- | --- |
| `sk_skb` verdict 里能不能拿到 socket cookie 当 SOCKHASH key | 两个场景都会打印 `cookie_nonzero` / `lookup_hit` |
| egress redirect（不带 `BPF_F_INGRESS`）能不能把收到的数据交给另一个 socket 发出去 | `same-netns` 的 ping/pong |
| 接收 socket 和目标 socket 不在同一 netns 时还能不能重定向 | `cross-netns` |
| 这条路径的吞吐大概是多少 | `-mb` 指定的单向灌流 |

## 前置条件

- Linux ≥ 6.6.94 / 6.12.34 / 6.15.3（CVE-2025-38165 修复矩阵之上）；
- root，且内核开了 `CONFIG_BPF_SYSCALL`、`CONFIG_NET_SOCK_MSG`（sockmap）；
- `cross` 场景额外需要 iproute2 的 `ip netns`；
- 不需要 clang：补丁里带的是**预编译对象**（`objects/*.o`，clang 21 + BTF）。

## 构建

```bash
cd probe
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o tcp-offload-probe .
```

或者直接用仓库的 `Build TCP offload probe` 工作流（手动触发），产物是
`tcp-offload-probe-linux-{amd64,arm64}`，从 run 页面的 Artifacts 下载。

## 运行

```bash
# 两个场景都跑，单向灌 64 MiB
./tcp-offload-probe -mode both -mb 64

# 只跑同 netns（不需要 iproute2）
./tcp-offload-probe -mode same

# 出问题时保留 netns
./tcp-offload-probe -mode cross -keep
```

`cross` 场景会临时建一个 `sbprobe` netns 并在里面建 L/C 两个 socket，通过 unix socket
把 fd 传给父进程；R/S 在 host netns。拓扑和生产里“私有交付 netns 里的监听 socket +
主 netns 的出站 socket”一致。

## 测试要素

| # | 要素 | 观测点 | 通过标准 | 不通过意味着 |
| --- | --- | --- | --- | --- |
| 1 | 对象与程序加载 | 运行时是否打印“cookie 程序加载失败” | 没有这行，且能 attach L/R | 内核不认 `sk_skb`/`SOCKHASH`，或 verifier 拒绝了 helper/裸 map lookup |
| 2 | cookie key | `kernel counters: cookie_nonzero>0 lookup_hit>0` | 两个计数都非 0 | `bpf_get_socket_cookie` 在 `sk_skb` 不可用 → 只能退回 fixed-key，做不了双向 |
| 3 | 同 netns egress redirect | `client→server: ok` / `server→client: ok` | 两条都 ok | redirect 机制本身不通（helper 语义/attach 类型问题） |
| 4 | 跨 netns redirect | `cross-netns: PASS` | ping/pong 双向都通 | 生产拓扑（私有 netns ↔ 主 netns）不可用，整个方案到此为止 |
| 5 | 数据完整性 | `-mb N` 时写入字节 == 服务端读取字节 | 一致，无超时 | 中途丢数据 → 不能上生产 |
| 6 | 吞吐 | `throughput ... Mbps` | 记下数字，和当前 splice 基线对比 | 低于基线说明走了 SK_PASS 回退或 redirect 无效 |
| 7 | 资源清理 | 结束后 `ip netns list`、`ps`、`bpftool prog show` | 没有残留 `sbprobe`、没有残留程序 | 说明 attach/detach 生命周期有 bug |
| 8 | 内核版本 | `uname -r` | 在修复矩阵之上 | 低于矩阵：即使测试通过也不要上生产 |

## 输出怎么读

正常（生产可行）：

```
=== same-netns ===
cookies: L=0x... R=0x...
client→server: ok
server→client: ok
throughput client→server: 64.0 MiB in 1.2s = 447.4 Mbps（单向，true）
kernel counters: verdict_calls=... cookie_nonzero=... lookup_hit=... redirect_pass=... redirect_drop=0
same-netns: PASS（cookie=true）
=== cross-netns ===
...
cross-netns: PASS（cookie=true）
```

三种典型失败：

- `cookie 程序加载失败: ... unknown func bpf_get_socket_cookie` → 要素 1 不过，退回 fixed-key 只测单方向；如果 fixed 能通，说明 redirect 机制可用但 key 方案要换（比如按 sk_storage 打标）。
- `服务端收不到（redirect 没生效 / 方向不对）` → 要素 3 不过，检查 attach 类型是否为 `SK_SKB_STREAM_VERDICT`、map value 是否为对端 fd。
- `cross-netns: FAIL` 但 same 通过 → 要素 4 不过，这就是我们拓扑的致命项，直接停。

## 文件

| 文件 | 作用 |
| --- | --- |
| `bpf/tcp_offload_probe.bpf.c` | 两个 `sk_skb` verdict 程序 + `probe_sock`(SOCKHASH) + `probe_stats`(ARRAY) |
| `objects/tcp_offload_probe_bpf{el,eb}.o` | clang 21 预编译对象（含 BTF），路由器不需要编译器 |
| `main.go` | 场景搭建、映射注册、attach、ping/pong、吞吐、计数器输出、fd 传递 |
| `spec_test.go` | 无特权校验对象布局（CI 里跑） |
