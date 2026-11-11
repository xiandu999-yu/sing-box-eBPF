# sing-ebpf：delivery / netkit / bypass_process 记录

> 2026-11-02，OpenWrt R6S。收尾时状态：**local 用 cgroup，shared 用 socket_assign(TCX head)**。local 的 socket_assign 拦截未打通，暂停。
>
> 2026-11-06 之后基准换成上游 `ed2bdc8`，见第 9 节。

## 1. 最终配置形态

```json
{
  "experimental": {
    "ebpf": { "delivery": "netkit-l3" }
  },
  "inbounds": [
    {
      "type": "ebpf",
      "tag": "ebpf-local",
      "local": {
        "enabled": true,
        "data_plane": "cgroup",
        "dns_mode": "off",
        "bypass_private_address": true,
        "bypass_rule_set": ["geoip-cn1", "..."],
        "bypass_process": ["mihomo", "dae", "docker", "..."],
        "bypass_port": [123]
      }
    },
    {
      "type": "ebpf",
      "tag": "ebpf-shared",
      "shared": {
        "enabled": true,
        "data_plane": "socket_assign",
        "tcx_position": "head",
        "interface": ["eth1", "eth2"],
        "bypass_private_address": true
      }
    }
  ],
  "route": { "find_process": true }
}
```

- `delivery` 是**根级** `experimental.ebpf`，不是 inbound 里。
- `route.find_process: true` 是面板显示进程名的前提。

## 2. L3 的结论（已闭环）

netkit L3 **不是裸 IP 帧**：

- `netkit_setup()` 两种模式都调 `ether_setup()`，`hard_header_len = ETH_HLEN`；
- L3 只做三件事：禁止设 MAC、`IFF_NOARP`、不做 `eth_hw_addr_random`（MAC 全零）；
- `netkit_xmit()` 里 `pskb_may_pull(skb, ETH_HLEN)` + `eth_skb_pull_mac()` 无条件 pull 14 字节。

**所以**：当年按“L3 = 无以太头”去 `skb_adjust_room(-14)`，等于让 netkit 把 IP 头前 14 字节当 MAC 吃掉 —— 静默损坏、校验和全错、单向重传风暴（`in=377 / eth2_out=34347`），全程不报错。

改成「保留以太头 + 两端 MAC 全零 + 不开 ARP」后，实测网页正常打开。**结论：L3 能通，但收益为 0**（省的是 ARP/邻居表，我们本来不用；每包仍要写 6 字节 MAC）。

规则记死：**过了 netkit 的帧，以太头只能由 netkit 自己剪。**

## 3. bypass_process（应用名旁路）

### 原理

`cgroup/connect4|6`、`cgroup/sendmsg4|6` 运行在**发起系统调用的线程上下文**里，`bpf_get_current_comm()` 直接是进程名（`task->comm`，15 字节截断）。

- cgroup 数据面：命中直接 `return 1`；
- socket_assign 数据面：命中写 `SELF_BYPASS` 位到共享表，TC 侧读到就放过。

### 实现（精简版，与完整版分离）

| | 完整版 | 精简版 |
|---|---|---|
| 入口 | `PrepareCgroup` / `CgroupBackend` | `PrepareProcessMarker` / `ProcessMarkerBackend` |
| 文件 | `internal/core/cgroup_*.go` | `internal/core/marker.go` |
| 挂载 | 7 钩子 + 全套重定向表 + 控制块 + UDP 清理 | 4 钩子 + 2 张表 |
| LPM 表 | — | `cgroup_process_bypass`（内核名 `cgroup_process_`，15 字符截断） |

### 验证记录

- LPM 内容正确：`daed`=0x20、`dae`=0x18、`dockerd`=0x38、`docker`=0x30……无 0 长度条目；
- 名单里有 mihomo → 它被放过；换成 `["zzzznomatch"]` → mihomo 立刻被代理。**判定链路工作正常**。

### 坑

- 名字必须写**截断后**的 15 字节形式（`transmission-da` 而不是 `transmission-daemon`）；
- comm 是线程名，Java/Chromium 这类改线程名的程序会判不到；
- 只看连接建立时刻，不回溯已有连接；
- marker 的替换映射必须和真实 self-bypass 表**容量/类型一致**，否则 cilium 报 `map spec is incompatible`（`MaxEntries` + `LRUHash` 两个都要改）。

## 4. 面板进程名兼容

zashboard 读 `metadata.process || metadata.processPath?.basename`；metacubexd 读 `processPath`。

mihomo 的三件套是分开的，我们原来只发 `processPath` 且拼了 `(user)` 后缀，导致 zashboard 列里显示 `curl (root)`。已改为：

```go
"process":     basename(processPath),
"processPath": processPath,   // 不带 (user)
"uid":         processUID,
```

## 5. 已验证（2026-11-02 收尾）

- `route.find_process: true` 生效，**面板进程名正常显示**（zashboard / metacubexd 都读 `metadata.process`，metacubexd 另有 `processPath`）；
- 交付设备命名已修：`netkit-l3` 建出 `sb-netkit-*`，日志 `delivery_used: netkit-l3`，`delivery_interface: sb-netkit-33fab`；
- `bypass_process` 两种数据面都可用，实测：名单里有 mihomo → 它被放过；换成 `["zzzznomatch"]` → 它立刻被代理；
- LPM 内容核对无误（`daed`=0x20、`dae`=0x18、`dockerd`=0x38、`docker`=0x30、`honk-core`=0x48），无 0 长度条目。

### 最终决定：local 固定用 cgroup

```json
"local":  { "data_plane": "cgroup" }
"shared": { "data_plane": "socket_assign", "tcx_position": "head" }
```

`experimental.ebpf.delivery` 保留 `netkit-l3`（shared 需要），`tcx_position` 对 local 不再有意义。

### 未解：local 的 socket_assign 拦截

事实：

- `sb_tc_local_l2` 已挂 eth0 egress（TCX），`sb_tc_ctl` 的 `flags=1`、`delivery_ifindex=0x4f=79` 均正确；
- `sb_tc_stats` **全零**，Clash API 里**没有**源地址为 `192.168.99.3` 的连接 → 包原样出去，压根没产生连接；
- L2/L3 表现一致；挂 `tail` 实测**可用**，挂 `head` 不行；
- `local_egress_mark` **不看源地址**（源码确认）：只有 `safety_bypass(destination)`（dst 为 0/127/≥224 直接 PASS）、`host_destination`、`bypass_destination`、端口、uid、socket 元数据；
- 因此若有前置 nft/tproxy 把 dst 改成了 `127.0.0.1:6942`，我们在 TC 看到的就是 127 → 第一行 PASS 且不计数。但这对 head/tail 一样，解释不了差异。

未确认的假设：head 时 TCX 锚点落空（程序没进判定），或 landscape 的 egress 程序改写了包状态。

**下一步（如果重启这条线）**：在 `native/tc.bpf.c` 的 `local_egress_mark` 每个 `return` 前加一个计数器：

```
SKIP_ENABLED / SKIP_INGRESS / SKIP_PARSE / SKIP_SELECT / SKIP_SELFBYPASS / REDIRECTED
```

复用 `sb_tc_stats`，不新增 map，一次 `bpftool map dump name sb_tc_stats` 即可定位。**需要 `make generate`。**


## 6. 与 landscape / einat 的共存

- **einat**：传统 clsact，只处理它绑定的那张接口。TCX 恒先于 clsact，所以我们的程序总在它之前，它看不到被劫持的包。
- **landscape（TCX fork）**：默认 `Order::Last`（追加到链尾），我们 `head`，天然在其之前。
- ⚠️ 但 local 的 TCX 实测 `head` 不生效、`tail` 可用（见第 5 节），结论尚未查清——**动 local 的 `tcx_position` 前先读第 5 节**。
- 被劫持的包在我们这里 `bpf_redirect` 就终止了本 hook，后面的 NAT 不会执行，**不存在“要不要放过”的问题**。
- mark 给谁看？没人看：einat 只把 `skb->mark` 当 fib lookup 输入；landscape 的 32 位 mark 已全部占满（layout/trace/action/reuse/flow id）。**结论：不要用 mark 做旁路**。
- 两个 ebpf inbound 各自有独立私有 netns（`link-netnsid 4` / `5`），所以两条交付链路是**必需**的，不是冗余。

## 7. 交付相关文件

| 文件 | 作用 |
|---|---|
| `patches/sing-box/0001-delivery-option.patch` | sing-box 侧全部改动（含 clashapi 进程名） |
| `patches/modules/sing-ebpf/0001-sing-ebpf-changes.patch` | 模块侧全部改动（含预编译 `.o` 二进制段） |
| `ci/pins.env` | 两个仓库的 commit 固定点 |
| 模块 `native/cgroup.bpf.c` | pname 判定 + 4 个 marker section（自身早退用上游的 `self_bypass_tgid`） |
| 模块 `internal/core/marker.go` | 精简版加载器（只挑 4 程序 + 2 表） |
| 模块 `internal/core/process_bypass.go` | 名字校验 + LPM 写入 |
| 模块 `runtime/tc_delivery.go` | 交付设备命名（`netkit-l3` → `sb-netkit-`） |

## 8. 流程备忘

- Go 改动 → 只 Build；`native/*.bpf.c`、`abi.h` 改动 → 对象必须重生成；
- 对象**不在补丁里**：`assemble-source` 工作流用 NDK r29 的 Clang 21 现场 `make generate`
  （模块 Makefile 有版本硬校验）。上游模块仓库那个 `generate-objects` 工作流与本仓库无关；
- 模块和 sing-box 补丁是一对：改模块的公开签名/类型名，补丁必须同批更新；
- 判断 generate 是否跑对：`internal/bpfgen/manifest.txt` 里 `native/cgroup.bpf.c` 的 sha256 应与实际文件一致（当前 `dfb9d129…6149`）。
- **`probe/` 是独立的诊断程序**（TCP sockmap 可行性探针），有自己的 `go.mod` 和
  `Build TCP offload probe` 工作流，不进 `sing-box-src` tarball；`probe/objects/*.o`
  是本机 clang 21 预编译并随仓库提交的，`.gitattributes` 里按 `binary` 处理。

## 9. 2026-11-06：基准前移到 `ed2bdc8`

`SING_BOX_COMMIT` 由 `2f42c08` 换成 `ed2bdc8`（上游 `fix(ebpf): register packet listeners after bind`）。
那一版把 eBPF inbound 拆成 `inboundResources` / `inboundWorkers` / `inboundDiagnostics` 三个内嵌
结构体，数据面启动也拆成了 `startCgroupDataPlane` / `startTCDataPlane` /
`startSharedRewriteDataPlane` / `startTCListenersIfNeeded`，所以补丁是重做而不是 rebase：

- `processMarkers` 挪进 `inboundResources`；`localBypassProcess`、`tcxPriority`、`tcxPosition`、
  `delivery` 留在 `Inbound` 本体；
- `delivery` / `tcx_*` 改在 `startTCDataPlane` 里写进 `TCConfig`；
- marker-only 钩子（socket_assign 下的 `bypass_process`）仍挂在 cgroup 数据面之后的分支上；
- 启动日志的 `delivery` / `delivery_used` / `bypass_process` 跟到新的
  `logStartupSummaryLocked`（现在由 `lifecycleAccess` 保护）。

同一版上游还改了包监听器的注册顺序：`net.ListenConfig.Control` 在 bind 之前跑，注册失败时
cookie 撤不掉，所以新增 `dialer.RegisterEBPFSelfBypassPacketConn`，在 `ListenPacket` 成功之后
才注册（`common/dialer/default.go`、`protocol/tailscale/system_binding.go`）。这是上游自己的修复，
我们不用跟。

模块固定点仍是 `ee36c75`；它已经导出了这套代码要的全部 API（含按次统计的 UDP
admission 计数的枚举），所以诊断字段一个不少。整套组合（上游 `ed2bdc8` + 两份补丁 +
`go mod replace ../module`）已实测编译通过。

`assemble-source` 多了 **Verify patch anchors**：补丁是行级 diff，上游再挪函数时可能"应用成功"
但落在死代码上，所以每个关键改动都断言一遍（含缝在 `repairTCInfrastructure` 里的 `tc_repair` 探针）。

## 10. 2026-11-07：跟随上游两跳（`d3217e2` + 模块 `1af55b7a`）

- sing-box `SING_BOX_COMMIT` → `d3217e29`（`deps(ebpf): adopt userspace release cleanup contract`）。
  相对 `ed2bdc8` **只改了 `go.mod` / `go.sum`**，把模块固定点提到 `1af55b7a`；eBPF 代码一行没动，
  所以 sing-box 补丁原样套用（重放后逐字节相同，只有 `index` 行变了）。
- 模块 `MODULE_COMMIT` → `1af55b7a`（`fix(self-bypass): clean up userspace release registrations`）。
  两处语义变化：`SelfBypassUserspaceRelease` 的 `CleanupMode()` 从 `socket_release` 改成
  `userspace_unregister`（内核 release 钩子只是兜底，注册者负责在 close 前删条目）；
  `UnregisterSocket` 在没有内核钩子时也会删，且 `ErrKeyNotExist` / `ENOENT` 视为成功，
  双清理路径幂等。

对配置没有影响：用户态注册路径（`selfBypassUsesUserspaceRegistration()`）判断的是
`SelfBypass.Mode()`，不是 `CleanupMode()`；sing-box 侧的 `UnregisterSocket` 调用点在
`protocol/ebpf/inbound_connection.go` 的 close/回滚分支，原本就在。

模块补丁重放到 `1af55b7a` 零冲突（25 个文件），顺手 `gofmt` 了补丁自己新增的几处结构体对齐。
整套组合已实测编译通过，`sing-box check` 用带 `bypass_process` / `netkit-l3` / `socket_assign`
的配置跑通。

## 11. 2026-11-09：self-bypass 大改（`91bc15bf` + 模块 `e4ac4ff8`）

这一跳上游推了 17 个 commit，主要是把 self-bypass 重做了一遍：先「prefer socket-mark」，
再整体回退成「remove socket-mark self-bypass path」，最后清理相关诊断。模块侧同时修了
cgroup storage / shared 回程、生成物行尾可移植性。

对我们的影响只有一处需要手工合并：`internal/core/cgroup_abi.go` 的 `CgroupConfig`——
上游新增 `selfBypass *SelfBypass`（cgroup 后端自己持有 self-bypass 句柄），正好和我们加的
`BypassProcess` / `MarkerOnly` 落在同一个字段块里，两边都保留即可。其余 24 个模块文件、
以及 sing-box 侧 17 个文件全部零冲突。

自检结果：

- 两个 zip 与对应 commit 的树逐字节一致；
- 两份补丁在 pristine clone 上 `git apply --check` 通过，重放后树与开发树一致；
- 从 pristine 开始按 CI 顺序完整构建（`go mod replace ../module` + `make generate` 之外的全部步骤）通过；
- `sing-box check` 用 cgroup + socket_assign + `bypass_process` + `netkit-l3` 的配置通过，非法 `delivery` 仍被拒。

`bypass_process` 的判定路径没有变化：cgroup 数据面仍在 `handle_v4/6` 里查
`cgroup_process_bypass`，socket_assign 仍走 marker-only 钩子；上游这轮动的 socket-mark
是另一条（已删除的）尝试，和我们写 `cgroup_socket_bypass` 的 TC 标记不是一回事。

## 12. 2026-11-09 晚：self-bypass 收尾（`949d0cea` + 模块 `bec0ab94`）

两个仓库各 3 个 commit，都还在 self-bypass 上：

- sing-box：`fix self-bypass dial lifecycle`、`restore cgroup address self-bypass`、
  `update sing-ebpf fallback diagnostics`。`selfBypassUsesUserspaceRegistration()` 现在把
  `SelfBypassCgroupSocketAddr` 也算作"需要用户态注册"，这是上游自己的判断，我们不用跟。
- 模块：`reclaim closed self-bypass sockets`、`restore cookie-cleaned cgroup address bypass`、
  `report self-bypass fallback failures`；`api.go` 新增 `SelfBypassCgroupSocketAddr` 常量与
  `FallbackReason()`，`self_bypass.go` +112。

**两份补丁这一跳零冲突**（25 + 17 个文件），模块补丁不需要再手工合并 `CgroupConfig`。
自检同前：zip 与 commit 树逐字节一致、pristine 上 `git apply --check` 通过、
按 CI 顺序完整构建通过、`sing-box check` 通过、非法配置仍被拒。

版本仍是上游的 `1.15.0-alpha.13`（`docs/changelog.md` 顶部没动，也没有新 tag）。

## 13. 2026-11-11：上游把「自身早退」自己做了（`6dc5542f` + 模块 `d2983dce`）

模块侧 9 个 commit、58 个文件，主要是 socket-local 自旁路存储（新增 `tc_storage` 对象）
和 **direct TGID 自旁路**。后者和我们早期加的东西是同一个机制：

| | 我们的老实现 | 上游新实现 |
| --- | --- | --- |
| 控制块字段 | `owner_tgid` | `self_bypass_tgid`（同一 ABI 槽位，36 字节） |
| Go 侧 | `CgroupConfig.ownerTGID` / backend `ownerTGID` | `CgroupConfig.selfBypassTGID` / `runtimeState.direct_tgid` |
| C 侧判定 | `is_owner_process(config)` | `is_direct_self_bypassed(config)`（`SB_EBPF_DIRECT_TGID` 变体） |

所以这轮把我们的整套删了，改用上游的；`bypass_process` 的 pname 判定接在
`is_direct_self_bypassed(config)` 之后，marker 钩子不变。模块补丁从 1852 行降到 1783 行，
25 → 24 个文件（`cgroup_maps_test.go` 和上游一致了，不再出现在补丁里）。

另外 6 处冲突都是「两边各加字段」：`CgroupConfig`、`TCBackend`、`cgroup.bpf.c` 的
`get_current_comm` 声明与 pname 判定、`native/abi.h`；sing-box 侧 3 处是
`EBPFRuntimeDiagnostics` / `EBPFDiagnostics` / `diagnosticsForAPI` 的字段重排。

自检同前：zip 与 commit 树逐字节一致、pristine 上 `git apply --check` 通过、
按 CI 顺序完整构建通过、`sing-box check` 通过、非法配置仍被拒。
版本仍是上游的 `1.15.0-alpha.13`。

> 这一轮第一次跑 assemble-source 时在 `make generate` 挂了：手工合并
> `native/cgroup.bpf.c` 时 `is_direct_self_bypassed()` 少了收尾的 `}`，
> `process_bypassed()` 被当成嵌套函数定义。已修复，并且现在本机就用
> clang 21（`BPF_SYSROOT=/ BPF_UAPI_ARCH_INCLUDE=/usr/include/x86_64-linux-gnu`
> 覆盖 Makefile 变量）把 9 个变体全部编译过一遍，再 `go build` + `check`，
> 避免再把这类错误留给 CI。

## 14. 2026-11-11：TCP sockmap 卸载——机制可用，**实测无收益，不实施**

背景：dae/kdae 那篇 `tcp-sockmap-offload.md` 的结论是「重新启用 sk_skb egress redirect」。
为了不在 Router 上赌，先写了独立探针 `probe/`（不进 tarball），在 R6S 上做 P0 验证。

机制层面全部通过（kernel 6.18.60 arm64）：

- `sk_skb` verdict 里 `bpf_get_socket_cookie` 可用，cookie 直接当 SOCKHASH key；
- `bpf_sk_redirect_hash` 不带 `BPF_F_INGRESS` = egress，`redirect_ok>0`、`redirect_miss=0`；
- **跨 netns 成立**：私有交付 netns 的监听 socket 可以 redirect 到主 netns 的出站 socket。

但 A/B 是否定的（256 MiB，同一台机器）：

| 路径 | 墙钟 | 进程 user+sys |
| --- | --- | --- |
| 用户态 splice 转发（= 生产现状） | 113 ms / 18940 Mbps | 170 ms（1510 MiB/cpu-s） |
| sockmap egress redirect | 289 ms / 7429 Mbps | 174 ms（1472 MiB/cpu-s） |

**CPU 成本一样，墙钟反而慢 2.5 倍。** loopback 上 splice 已经接近 memcpy，sockmap 多的
psock ingress 队列 / EAGAIN 重试 / delayed work 在这个规模是净负担；真实流量（小连接、
短消息）只会更差（LWN 1033063）。A/B 只替换了转发那一步，NIC 路径两边相同，所以结论对
真实网卡同样成立。

三个实现约束（将来谁再想做，直接看 `probe/README.md`）：

1. verdict 程序**不能预查 SOCKHASH**——`bpf_map_lookup_elem` 返回 socket 引用，
   不 `bpf_sk_release` 就 reference leak；命中/未命中看 `redirect_hash` 返回值；
2. attach 的目标是 **SOCKHASH map 的 fd**（`bpf_prog_attach → sock_map_get_from_fd`），
   不是 socket fd；
3. 顺序必须是**先 attach 到 map、再插 socket**，psock 才会带上程序。

结论：不做 P1。以后要重新评估，先跑
`probe/tcp-offload-probe -mode same -mb 256 -baseline` 和同命令去掉 `-baseline`
比 `MiB/cpu-s`，差距 <25% 就不用往下走。






