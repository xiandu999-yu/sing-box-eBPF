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

# 先跑一遍用户态 splice 转发（不装 BPF）作为 A/B 基线
./tcp-offload-probe -mode same -mb 64 -baseline

# 出问题时保留 netns
./tcp-offload-probe -mode cross -keep
```

## 实测（2026-11-11，OpenWrt R6S）

```
=== same-netns ===
cookies: L=0x4241a3 R=0x4241a2
client→server: ok
server→client: ok
throughput client→server: 64.0 MiB in 479ms = 1121.6 Mbps（单向，true）
kernel counters: verdict_calls=1090 cookie_nonzero=1090 redirect_ok=1090 redirect_miss=0
same-netns: PASS（cookie=true）
=== cross-netns ===
cookies: L=0x420ae1 R=0x420ae0
client→server: ok
server→client: ok
throughput client→server: 64.0 MiB in 32ms = 16572.0 Mbps（单向，true）
kernel counters: verdict_calls=1090 cookie_nonzero=1090 redirect_ok=1090 redirect_miss=0
cross-netns: PASS（cookie=true）
```

结论：

- **核心未知全部消除**：`sk_skb` verdict 里 `bpf_get_socket_cookie` 可用；`bpf_sk_redirect_hash`
  的 egress 语义成立（`redirect_ok=1090`、`redirect_miss=0`）；**跨 netns 也成立**——这正是
  生产拓扑（私有交付 netns 的监听 socket ↔ 主 netns 的出站 socket）。
- 两次的 `verdict_calls=1090` 对应 64 MiB，说明 psock 是批量交付（≈61 KB/次），不是逐包。
- 吞吐数字**不能当结论**：两个场景都是 loopback，且同一份数据在同一台机器上跑两次
  差 14 倍（1121 vs 16572 Mbps），说明这组数字被调度/窗口/缓存噪声主导。要判断
  “省了多少”，必须跑 `-baseline` 在同一台机器上做 A/B。

还没证明的（都要 P1 才有答案）：真实网卡路径、用户态前缀冲刷、半关闭语义、
积压保险丝、以及每连接两个 goroutine 的调度开销。

## 测试要素

| # | 要素 | 观测点 | 通过标准 | 不通过意味着 |
| --- | --- | --- | --- | --- |
| 1 | 对象与程序加载 | 运行时是否打印 `cookie 程序加载失败`；两者都失败时会再试 `probe_verdict_noop` | noop 能装载（说明装载路径正常），cookie/fixed 装载成功 | noop 也失败 = 装载路径/程序类型本身有问题；只有 cookie 失败 = `bpf_get_socket_cookie` 不被 sk_skb 允许 |
| 2 | cookie key | `kernel counters: cookie_nonzero>0 redirect_ok>0` | 两个计数都非 0 | `bpf_get_socket_cookie` 在 `sk_skb` 不可用 → 只能退回 fixed-key，做不了双向 |
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

失败时会打印内核 verifier 日志（`LogLevelBranch|LogLevelStats` + `VerifierError.Log` 全文），
`unsatisfied map reference` 这类是用户态装载方式的问题，不是内核拒绝。

> 2026-11-11 修过四次：
> 1. 最早直接 `ebpf.NewProgram(progSpec)` 单程序装载，程序里的 map 重定位没有被替换成
>    map fd，内核侧报 `instruction N: unsatisfied map reference`。现在改成“每个程序各自
>    一个只含单个程序的 collection”，map 由 collection 统一创建并解析引用。
> 2. `sk_skb` 程序必须带 `expected_attach_type`，否则 `bpf_prog_load` 可能直接返回 `EINVAL`。
>    现在对象里 section 改成 `sk_skb/stream_verdict`，Go 侧也显式设置
>    `AttachType = AttachSkSKBStreamVerdict`。
> 3. **R6S 实机日志确认：`bpf_map_lookup_elem` 查 SOCKHASH 返回的是 socket 引用**
>    （`R0=sock(ref_obj_id=4)`），不在 exit 前 `bpf_sk_release()` 就会被 verifier 判
>    `Unreleased reference` / `reference leak`。现在程序不再预查表，命中/未命中直接看
>    `bpf_sk_redirect_hash()` 的返回值（`SK_PASS`=命中并已重定向，`SK_DROP`=未命中），
>    两条路径都返回 `SK_PASS`，未命中时数据按普通路径投递，不会静默丢包。
> 4. **attach 的目标是 SOCKHASH map 的 fd，不是 socket fd**：内核走
>    `bpf_prog_attach -> sock_map_get_from_fd`，把程序存进 map 的
>    `progs.verdict`；传 socket fd 会得到 `EINVAL`。顺序也必须是
>    **先 attach 到 map、再插入 socket**，这样 socket 插入时创建的 psock 才带上程序。

## 文件

| 文件 | 作用 |
| --- | --- |
| `bpf/tcp_offload_probe.bpf.c` | 两个 `sk_skb` verdict 程序 + `probe_sock`(SOCKHASH) + `probe_stats`(ARRAY) |
| `objects/tcp_offload_probe_bpf{el,eb}.o` | clang 21 预编译对象（含 BTF），路由器不需要编译器 |
| `main.go` | 场景搭建、映射注册、attach、ping/pong、吞吐、计数器输出、fd 传递 |
| `spec_test.go` | 无特权校验对象布局（CI 里跑） |
