# 补丁说明

本目录里的补丁会在 CI 拉取完源码之后、编译之前自动套用：

| 补丁 / 固定点 | 目标 | 基准 |
| --- | --- | --- |
| `sing-box/0001-delivery-option.patch` | `reF1nd/sing-box` | `sing-box.commit` 里的 commit |
| `modules/sing-ebpf/pin.env` | `xiandu999-yu/sing-ebpf` | `MODULE_REF` 里的 commit |

套用逻辑见 `.github/scripts/apply-patches.sh`：sing-box 本体用 `git apply --3way`；模块**不打补丁**，按 `pin.env` 解析出伪版本后 `go mod edit -replace`，所以升级模块只要改 `MODULE_REF`，不需要改这个仓库里的其它东西。

---

## 1. sing-box：`delivery` 与 TCX 顺序

### 新增配置

`delivery` 放在**根级** `experimental.ebpf` 下：整个进程只有一条 socket_assign 交付链路，它不属于任何一个 inbound；`tcx_*` 仍在 `local` / `shared` 里，各管各的挂载点：

| 字段 | 位置 | 取值 | 默认 | 说明 |
| --- | --- | --- | --- | --- |
| `delivery` | `experimental.ebpf` | `veth` / `netkit` / `netkit-l3`（实验）/ `auto` | `auto` | socket_assign 的交付链路类型；**纯选择器**，没有 socket_assign 时写了也不报错、不生效。设备名跟随实际建成的类型 |
| `tcx_position` | local / shared | `head` / `tail` | `head` | TCX 挂链首还是链尾 |
| `tcx_priority` | local / shared | 1–65535 | 未设 | 显式数字，设置后覆盖 `tcx_position` |

`netkit-l3` 是**实验值**：只去掉 MAC/ARP，帧格式与 L2 完全一样，没有性能收益（见第 3 节）。默认不用它，写它也不会报错。

```json
{
  "experimental": {
    "ebpf": { "delivery": "auto" }
  },
  "inbounds": [
    {
      "type": "ebpf",
      "local": {
        "enabled": true,
        "data_plane": "socket_assign",
        "tcx_position": "head"
      },
      "shared": {
        "enabled": true,
        "data_plane": "socket_assign",
        "interface": ["eth1", "eth2"],
        "tcx_position": "head"
      }
    }
  ]
}
```

### 取值与生效

- `delivery` 只是选择器：不写 → `auto`；写了但没有任何 scope 用 `socket_assign` → 不建链路、不报错。
- `auto`：先按 netkit（L2，Linux 6.7+）建，失败退回 veth，并在启动日志里警告 `netkit is unavailable on this kernel`。要强制某一种就写 `netkit` / `veth`。
- 设备名跟随**实际建成**的类型（`sb-netkit-*` / `sb-veth-*`）。

### 校验规则

- `delivery` 只校验取值（`veth|netkit|netkit-l3|auto`），**不再校验** scope 的 `enabled` / `data_plane`，也不再要求两边一致——位置改到顶层后这两类错误在结构上就不存在了。
- `tcx_position` 非法取值报错；两边显式设置且不一致同样报错。
- `tcx_position: head` 使用显式链首锚点（挂在现有第一个程序之前），**包括没有 priority 标记的程序**；`tail` 挂到链尾；显式 `tcx_priority` 时仍按优先级排序。
- 都没设时是 `auto` + `head` + 由位置决定锚点（priority 保持 0）。
- `inbound_start` 的结构化日志带 `delivery`（配置值）和 `delivery_used`（实际值），可直接看出最后用的是 netkit 还是 veth。

### 改动文件

| 文件 | 改动 |
| --- | --- |
| `option/ebpf.go` | `EBPFInboundOptions` 增加 `Delivery`（顶层）；`EBPFLocalOptions` / `EBPFSharedOptions` 增加 `TCXPriority`、`TCXPosition` |
| `protocol/ebpf/inbound.go` | 新增 `delivery` / `tcxPriority` / `tcxPosition` 字段；`normalizeDelivery`（空值 → `auto`）、`resolveTCXOrder` |
| `protocol/ebpf/inbound_lifecycle.go` | 把三个值传给 `commonEBPF.TCConfig` |

---

## 2. sing-ebpf：netkit L2 交付链路 + TCX 顺序

### netkit 交付链路（L2）

`socket_assign` 需要在私有 netns 里交付报文，原来只能建 veth 对；模块增加 netkit 对（**L2 模式**）。

- 设备名跟随**实际建成的类型**：`sb-netkit-<5位hex>` / `sb-veth-<6位hex>`。`auto` 先按 netkit 建，失败才用 veth 重试，所以名字永远对得上真正挂上去的那一对（不再有中性的 `sb-dlv-`）；Linux 接口名上限 15 字符，`sing-box-veth-…` 放不下；
- 设备创建走原始 `RTM_NEWLINK`：`sagernet/netlink` 的 `LinkAdd` 是封闭的类型 switch，不认识 netkit；
- netkit L2 保留以太头，因此**选择/交付/回程 BPF 程序与已提交对象完全不用改**，MAC、静态邻居、`route_localnet` 等逻辑原样复用；
- 创建失败会带明确原因（内核 ≥ 6.7、`CONFIG_NETKIT`、`CAP_NET_ADMIN`），不静默退回 veth。
- 控制块里的 `delivery_mode` **恒为 0**：bit0（L3，跳过以太头）随 `netkit-l3` 一起删除，bit1（`bpf_redirect_peer`）实测会让 netkit 的 TX 卡死（发出 4 个包后不再前进），不再开启。交付/回程全部走“改写目的 MAC + `bpf_redirect` 到宿主端设备”这条已验证的 L2 路径。
- `netkit-l3` 在模块侧也直接报错，不会再去建一个没有以太头的 netkit 设备：

  ```
  TC eBPF delivery netkit-l3 has been removed, use netkit (L2) instead
  ```

### TCX 顺序

`tcx_priority` / `tcx_position` 随 `TCConfig` 下发，存到 backend 上，挂载时读取：

```go
func tcxPriorityOf(backend *commonEBPF.TCBackend, fallback uint16) uint16 {
	if backend != nil {
		if value := backend.TCXPriority(); value != 0 {
			return value
		}
		switch backend.TCXPosition() {
		case "tail":
			return ^uint16(0) // 65535
		case "head":
			return DefaultTCPriority
		}
	}
	return fallback
}
```

作用于全部 4 个 TCX 挂载点：首次挂载（主程序 + icmp）、健康检查修复（主程序 + icmp）。

### 改动文件

| 文件 | 改动 |
| --- | --- |
| `api.go` | `TCConfig` 增加 `Delivery` / `TCXPriority` / `TCXPosition` 并透传 |
| `internal/core/tc.go` | 配置字段 + backend 保存上述状态 |
| `internal/core/access.go` | 新增 `DeliveryKind()` / `TCXPriority()` / `TCXPosition()` |
| `runtime/tc_netkit.go`（新） | `createTCDeliveryPair` 分派、`addNetkitPair` 原始 netlink 建链 |
| `runtime/tc_isolated_delivery.go` | 交付链路按 kind 创建 veth 或 netkit；两个 hook 改为 TCX 优先 + clsact 回退 |
| `runtime/tc_delivery.go` | 新设备命名；新增 `attachTCDeliveryHook` / `deliveryHookAttached` / `closeTCDeliveryHook` / `repairTCDeliveryHook` |
| `internal/core/tc.go` | 新增 `DeliveryIngressProgram()` / `IsolatedReturnProgram()` 供 TCX 使用 |
| `runtime/tc_dataplane.go` | `deliveryKind` 字段、`tcxPriorityOf`、4 处 TCX 挂载点改用新优先级；删除不再使用的 `tcVethSequence` |
| `runtime/tc_delivery_link_netns_test.go` | 残留设备检测前缀同步为新命名 |

---

## 3. 为什么锁死在 L2（`netkit-l3` 已移除）

L3（netkit 用 mode 1、去以太头直投 + 回程补头）实现过，链路能建、程序能挂、控制块也对，但**客户端流量就是不通**：计数表现为 `in=377 / eth1_out=76 / eth2_out=34347`，回程被重复放大上百倍，浏览器全超时。

最后一轮抓包（30 秒 / 8006 包）反过来证明了客户端的 TCP 是好的：

| 观测 | 结果 |
| --- | --- |
| `4847 → 64.226.122.113:443`（openwrt.org） | SYN → ClientHello → ServerHello → Certificate，服务端连发到 Seq≈392527（≈390 KB），客户端 ACK 全部跟上 |
| `13998 → 185.199.108.153:443`（openwrt.github.io） | TLS 1.3 握手完整 |
| `13999 → 4.145.79.81:443` | TLS 1.2 带证书完整 |
| TCP DNS（两条）/ UDP DNS | 全部有应答 |
| `[TCP Retransmission]` | **0 个** |

抓包里那 10 个 RST 全是同一形状：客户端在 `Seq=1 Ack=1` 的老连接上发 1 字节保活/首包，对端立刻 RST。最干净的对照是同一台主机的两条连接——`#5806` 老连接发 Application Data 被 RST，同一时刻 `#5932` 新建连接握手、证书、数据全通。这是切配置后旧连接池失效的残留，不是路径丢包，更不是客户端拒收。

所以"客户端不要"的推断可以推翻：客户端从来没拒过，是回程在某个位置被丢了。要继续追 L3，需要的不是更多猜测，而是失败瞬间的定向证据：

```
tcp.analysis.flags || tcp.flags.reset == 1
```

- **SYN 反复重传、没有 SYN-ACK** → 丢在 `isolated_delivery`；
- **握手完成、Application Data 不再回来** → 丢在 `isolated_return`（推头失败或整帧超 MTU，小包过 1460 全丢，正好是"握手成功但页面转圈"）。

`netkit-l3` 现在作为**实验开关**放回来了：它能建、能跑（帧格式和 L2 一样，只是两端 MAC 全零、不开 ARP），但收益是 0 —— 我们本来就不用 ARP。默认仍然走 `auto` → netkit L2。

实测（零 MAC 版）：`delivery: netkit-l3` 下网页正常打开，与 L2 无差别；`ip -d link` 里 `mode l3`、`link/ether 00:00:00:00:00:00`。**结论：能通，但没有理由用。**

### 「L3 = 裸 IP」是错的

翻驱动源码后可以确认，netkit 的 L3 **不是“裸 IP 帧”**：

- `netkit_setup()` 对两种模式都调 `ether_setup()`，设备始终是以太设备（`hard_header_len = ETH_HLEN`）；
- L3 只做三件事：不允许设 MAC、`IFF_NOARP` 保持、不做 `eth_hw_addr_random`（MAC 全零）；
- `netkit_xmit()` 里 `pskb_may_pull(skb, ETH_HLEN)` + `eth_skb_pkt_type()` + `eth_skb_pull_mac()`（后者无条件 `skb_pull_inline(skb, ETH_HLEN)`）——**两种模式线上都是完整以太帧**，剥头发生在对端 rx 侧。

所以：**删掉以太头的 L3 不可能通；保留以太头的 L3 能通，但没有收益。** 我们当时按“L3 = 无以太头”去 `skb_adjust_room(-14)`，等于让 `netkit_xmit` 把 IP 头前 14 字节当 MAC 头吃掉：对端收到从 IP 头中间开始的垃圾、校验和全错、服务端无限重传（正是 `in=377 / eth2_out=34347` 那个形态，而且不会报任何错）。

L3 省下来的只有 MAC/ARP/邻居表；而交付路径里 MAC 是 eBPF 写进去的静态值、ARP 从来不用。所以 L2 是终局，不是妥协——`netkit-l3` 留着只为了以后不用再翻一遍源码。

另外，收口时发现工作区里 `delivery_mode` 对 `netkit` **也**开着 bit1（`bpf_redirect_peer`）——而这个开关当初测过会把 netkit 的 TX 卡死。也就是说“两端都换回 L2 程序也不行”很可能不是 L2 程序的问题，而是这个开关在普通 netkit 上同样生效。本次一并改成恒 0。

因此这一版模块的两处改动是：

| 文件 | 改动 |
| --- | --- |
| `internal/core/tc.go` | `delivery_mode` 恒为 0；删掉空的 `netkit-l3` 分支；clsact 回退固定用 `classifier/isolated_delivery_legacy` |
| `runtime/tc_netkit.go` | `DeliveryNetkitL3` 恢复为「模式 1 + 不设 MAC」（零 MAC 帧），不再删头；新增 `createTCDeliveryPairWithNames` / `createTCDeliveryPairAuto`；`ProbeDelivery` 走同一条路径，`--probe-delivery auto` 会报出实际建成的那种 |
| `runtime/tc_delivery.go` | 命名只认具体类型：删掉 `sb-dlv-`，`auto` 在取名前就被解析成 netkit/veth |
| `runtime/tc_isolated_delivery.go` | 建链时先解析 `auto` 再取名字，`deliveryKind` 记录实际类型 |

`native/tc_isolation.h` 不动，`internal/bpfgen/*.o` 不动 —— 所以**不需要 `make generate`**。

模块里 `isolated_delivery_l3` / `isolated_return_l3` 等 L3 程序段仍留在 `native/tc_isolation.h` 和已提交对象里，只是没有任何代码去挂载它们。

---

## 4. local：按进程名旁路（`bypass_process`）

只在 `local.data_plane: cgroup` 下有效。`cgroup/connect4|6`、`cgroup/sendmsg4|6` 运行在**发起系统调用的那个线程的上下文**里，所以 `bpf_get_current_comm()` 返回的就是发起连接的进程名（内核 `task->comm`，可执行文件 basename，截断 15 字节），不需要扫 `/proc`，也没有 pid→名字映射表的竞态。

判定插在 `handle_v4/6` 里 `is_cookie_bypassed()` 之后、**所有选择器之前**（包括 DNS 劫持），命中即 `return 1`，不改写目标地址：

```json
{
  "local": {
    "enabled": true,
    "data_plane": "cgroup",
    "bypass_process": ["aria2c", "transmission-da"]
  }
}
```

- **前缀匹配**（LPM trie，按 bit 前缀）：`transmission-da` 能命中 `transmission-daemon` 被截断后的名字。
- 名字超过 15 字节在启动时直接报错，不会静默不匹配；非 ASCII 同样报错。
- 与 `bypass_port` / `bypass_private_address` / `exclude_uid` 独立，命中任何一条旁路即可。
- 在 `socket_assign` 下配置它会**启动失败**：TC 上下文里 `bpf_get_current_comm()` 拿到的是软中断，判不了进程。

实现：新增 LPM 表 `cgroup_process_bypass`（内核名 `sb_cg_pname`，256 条），`handle_v4/6` 多一次 comm 拷贝 + 一次查表；控制位 `SB_EBPF_CGROUP_FLAG_PROCESS_BYPASS (1U << 19U)` 未置位时这段完全不执行，零开销。

**这一节改动了 C 与 map，必须重新生成 `internal/bpfgen/*.o`（`make generate`）。**

---

## 已知限制

1. **默认只做 L2**。`netkit-l3` 是实验开关：帧格式与 L2 相同、只是 MAC 全零且不开 ARP，**没有性能收益**，别拿它当优化（见第 3 节）。
2. **交付链路为 TCX 优先、clsact 回退**。`sb_tc_return` / `sb_tc_deliver` 在支持 TCX 的内核上以 TCX link 挂载，`tcx_priority` / `tcx_position` 对它们同样生效；只有内核不支持 TCX，或无法读取/记录 TCX 顺序（缺权限）时才回退 clsact。
3. **netkit 需要内核 ≥ 6.7** 并启用 netkit 支持；OpenWrt 24.10（6.6）不支持 netkit，默认的 `auto` 会自动退回 veth（启动日志有 `netkit is unavailable on this kernel` 警告）。
4. 一个 sing-box 实例仍只能有一个 `local` 接管。
