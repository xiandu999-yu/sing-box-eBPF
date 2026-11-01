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

`local` 和 `shared` 各有一份，都是可选字段：

| 字段 | 取值 | 默认 | 说明 |
| --- | --- | --- | --- |
| `delivery` | `veth` / `netkit` / `auto` | `auto` | socket_assign 的交付链路类型；只在 socket_assign 实际启用时生效。设备名跟随实际建成的类型 |
| `tcx_position` | `head` / `tail` | `head` | TCX 挂链首还是链尾 |
| `tcx_priority` | 1–65535 | 未设 | 显式数字，设置后覆盖 `tcx_position` |

`netkit-l3` 已从取值里删除，写它会直接启动失败（见下）。

```json
{
  "type": "ebpf",
  "local": {
    "enabled": true,
    "data_plane": "socket_assign",
    "delivery": "auto",
    "tcx_position": "head"
  },
  "shared": {
    "enabled": true,
    "data_plane": "socket_assign",
    "delivery": "auto",
    "interface": ["eth1", "eth2"],
    "tcx_position": "head"
  }
}
```

### 默认值的推导顺序

1. `local.delivery` 显式设置 → 用它；
2. 否则 `shared.delivery` 显式设置 → 用它；
3. 都没设，且 local 或 shared 里有 `enabled: true` + `data_plane: socket_assign` → **`auto`**（优先 netkit，建不出来退回 veth）；
4. 其余情况（没有 socket_assign、或两个 scope 都关）→ `veth`，此时不会建交付链路。

也就是说默认是 `auto`：内核支持 netkit（≥ 6.7）就用 netkit L2，不支持就退回 veth 并在启动日志里警告，不用改配置。要强制某一种就显式写 `netkit` 或 `veth`。

### 校验规则

- `delivery: netkit` / `auto` 要求**该 scope 自己** `enabled` 且 `data_plane: socket_assign`，否则启动失败：

  ```
  local.delivery=netkit requires local.enabled and local.data_plane=socket_assign
  ```

- 只写 `delivery: veth` 不受此限制，关掉 netkit 不需要额外条件。

- local 与 shared 共用同一条交付链路，两边**都显式设置且不一致**时报错：

  ```
  local.delivery (netkit) and shared.delivery (veth) differ,
  but both scopes share one delivery link
  ```

- `netkit-l3` 已移除，写它报：

  ```
  delivery: netkit-l3 has been removed, use delivery: netkit (L2) or delivery: auto instead
  ```

- `tcx_position` 非法取值报错；两边显式设置且不一致同样报错。
- `tcx_position: head` 使用显式链首锚点（挂在现有第一个程序之前），**包括没有 priority 标记的程序**；`tail` 挂到链尾；显式 `tcx_priority` 时仍按优先级排序。
- 只设一边时以设置的为准；都没设时是 `netkit` + `head` + 由位置决定锚点（priority 保持 0）。
- `inbound_start` 的结构化日志新增 `delivery`（配置值）和 `delivery_used`（实际值）字段，可直接看出最后用的是 netkit 还是 veth。

### 改动文件

| 文件 | 改动 |
| --- | --- |
| `option/ebpf.go` | `EBPFLocalOptions` / `EBPFSharedOptions` 增加 `Delivery`、`TCXPriority`、`TCXPosition`，`delivery` 枚举为 `veth,netkit,auto` |
| `protocol/ebpf/inbound.go` | 新增 `delivery` / `tcxPriority` / `tcxPosition` 字段；`normalizeDelivery` 保留空值语义、`resolveTCXOrder`；上述校验与默认值推导 |
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

这条线索留给以后，当前版本**不提供 L3**：枚举里没有 `netkit-l3`，配置里写它直接报错。

另外，收口时发现工作区里 `delivery_mode` 对 `netkit` **也**开着 bit1（`bpf_redirect_peer`）——而这个开关当初测过会把 netkit 的 TX 卡死。也就是说“两端都换回 L2 程序也不行”很可能不是 L2 程序的问题，而是这个开关在普通 netkit 上同样生效。本次一并改成恒 0。

因此这一版模块的两处改动是：

| 文件 | 改动 |
| --- | --- |
| `internal/core/tc.go` | `delivery_mode` 恒为 0；删掉空的 `netkit-l3` 分支；clsact 回退固定用 `classifier/isolated_delivery_legacy` |
| `runtime/tc_netkit.go` | `DeliveryNetkitL3` 分支直接报错；新增 `createTCDeliveryPairWithNames` / `createTCDeliveryPairAuto`；`ProbeDelivery` 走同一条路径，`--probe-delivery auto` 会报出实际建成的那种 |
| `runtime/tc_delivery.go` | 命名只认具体类型：删掉 `sb-dlv-`，`auto` 在取名前就被解析成 netkit/veth |
| `runtime/tc_isolated_delivery.go` | 建链时先解析 `auto` 再取名字，`deliveryKind` 记录实际类型 |

`native/tc_isolation.h` 不动，`internal/bpfgen/*.o` 不动 —— 所以**不需要 `make generate`**。

模块里 `isolated_delivery_l3` / `isolated_return_l3` 等 L3 程序段仍留在 `native/tc_isolation.h` 和已提交对象里，只是没有任何代码去挂载它们。

---

## 已知限制

1. **只做 L2**。L3 需要 raw-IP 的交付/回程程序变体，并且回程要自己补以太头；已验证在 netkit L3 上不通，不再提供（见第 3 节）。
2. **交付链路为 TCX 优先、clsact 回退**。`sb_tc_return` / `sb_tc_deliver` 在支持 TCX 的内核上以 TCX link 挂载，`tcx_priority` / `tcx_position` 对它们同样生效；只有内核不支持 TCX，或无法读取/记录 TCX 顺序（缺权限）时才回退 clsact。
3. **netkit 需要内核 ≥ 6.7** 并启用 netkit 支持；OpenWrt 24.10（6.6）不支持 netkit，默认的 `auto` 会自动退回 veth（启动日志有 `netkit is unavailable on this kernel` 警告）。
4. 一个 sing-box 实例仍只能有一个 `local` 接管。
