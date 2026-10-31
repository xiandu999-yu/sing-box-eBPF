# 补丁说明

本目录里的补丁会在 CI 拉取完源码之后、编译之前自动套用：

| 补丁 | 目标 | 基准 |
| --- | --- | --- |
| `sing-box/0001-delivery-option.patch` | `reF1nd/sing-box`（由 `sing-box.commit` 固定） | 该 pin 的 commit |
| `modules/sing-ebpf/0001-netkit-l2-delivery.patch` | `CHIZI-0618/sing-ebpf` | `modules/sing-ebpf/pin.env` 里的 commit |

套用逻辑见 `.github/scripts/apply-patches.sh`：sing-box 本体用 `git apply --3way`，模块则是“克隆仓库 → 打补丁 → `go mod edit -replace`”。

---

## 1. sing-box：`delivery` 与 TCX 顺序

### 新增配置

`local` 和 `shared` 各有一份，都是可选字段：

| 字段 | 取值 | 默认 | 说明 |
| --- | --- | --- | --- |
| `delivery` | `veth` / `netkit` | `veth` | socket_assign 的交付链路类型 |
| `tcx_position` | `head` / `tail` | `head` | TCX 挂链首还是链尾 |
| `tcx_priority` | 1–65535 | 未设 | 显式数字，设置后覆盖 `tcx_position` |

```json
{
  "type": "ebpf",
  "local": {
    "enabled": true,
    "data_plane": "socket_assign",
    "delivery": "netkit",
    "tcx_position": "head"
  },
  "shared": {
    "enabled": true,
    "data_plane": "socket_assign",
    "delivery": "netkit",
    "interface": ["eth1", "eth2"],
    "tcx_position": "head"
  }
}
```

### 校验规则

- `delivery: netkit` 要求该 scope 自己 `enabled` 且 `data_plane: socket_assign`，否则启动失败：

  ```
  local.delivery=netkit requires local.enabled and local.data_plane=socket_assign
  ```

- local 与 shared 共用同一条交付链路，两边**都显式设置且不一致**时报错：

  ```
  local.delivery (netkit) and shared.delivery (veth) differ,
  but both scopes share one delivery link
  ```

- `tcx_position` 非法取值报错；两边显式设置且不一致同样报错。
- `tcx_position: head` 使用显式链首锚点（挂在现有第一个程序之前），**包括没有 priority 标记的程序**；`tail` 挂到链尾；显式 `tcx_priority` 时仍按优先级排序。
- 只设一边时以设置的为准；都没设时是 `veth` + `head` + priority 1。
- `inbound_start` 的结构化日志新增 `delivery` 字段，可直接看出实际用的是 veth 还是 netkit。

### 改动文件

| 文件 | 改动 |
| --- | --- |
| `option/ebpf.go` | `EBPFLocalOptions` / `EBPFSharedOptions` 增加 `Delivery`、`TCXPriority`、`TCXPosition` |
| `protocol/ebpf/inbound.go` | 新增 `delivery` / `tcxPriority` / `tcxPosition` 字段；`normalizeDelivery`、`resolveTCXOrder`；上述校验 |
| `protocol/ebpf/inbound_lifecycle.go` | 把三个值传给 `commonEBPF.TCConfig` |

---

## 2. sing-ebpf：netkit L2 交付链路 + TCX 顺序

### netkit 交付链路（L2）

`socket_assign` 需要在私有 netns 里交付报文，原来只能建 veth 对；补丁增加 netkit 对（**L2 模式**）。

- 设备名：`sb-veth-<6位hex>` / `sb-netkit-<5位hex>`（Linux 接口名上限 15 字符，`sing-box-veth-…` 放不下）；
- 设备创建走原始 `RTM_NEWLINK`：`sagernet/netlink` 的 `LinkAdd` 是封闭的类型 switch，不认识 netkit；
- netkit L2 保留以太头，因此**现有的选择/交付/回程 BPF 程序与对象完全不用改**，MAC、静态邻居、`route_localnet` 等逻辑原样复用；
- 创建失败会带明确原因（内核 ≥ 6.7、`CONFIG_NETKIT`、`CAP_NET_ADMIN`），不静默退回 veth。

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
| `runtime/tc_isolated_delivery.go` | 交付链路按 kind 创建 veth 或 netkit |
| `runtime/tc_delivery.go` | 新设备命名（crypto/rand），`nextTCVethNames` 保留为兼容包装 |
| `runtime/tc_dataplane.go` | `deliveryKind` 字段、`tcxPriorityOf`、4 处 TCX 挂载点改用新优先级；删除不再使用的 `tcVethSequence` |
| `runtime/tc_delivery_link_netns_test.go` | 残留设备检测前缀同步为新命名 |

---

## 已知限制

1. **netkit 只有 L2**。L3（去以太头直投）需要新增 delivery 的 raw-IP 程序变体并重新生成 `bpfel/bpfeb` 对象，尚未实现；内核在 L3 下也禁止设置 MAC。
2. **交付链路仍是传统 clsact**。`sb_tc_return` / `sb_tc_deliver` 仍以 `*netlink.BpfFilter` 形式挂在 clsact 上，因此：
   - `tcx_priority` / `tcx_position` 目前只影响接口选择程序（eth0 egress、eth1/eth2 ingress）；
   - netkit 的 noqueue 优势在交付设备上会被 clsact 抵消一部分。
3. **netkit 需要内核 ≥ 6.7** 并启用 netkit 支持；OpenWrt 24.10（6.6）不可用，运行时会明确报错。
4. 一个 sing-box 实例仍只能有一个 `local` 接管。
