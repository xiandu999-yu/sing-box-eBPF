# sing-ebpf：delivery / netkit / bypass_process 记录

> 2026-11-02，OpenWrt R6S。收尾时状态：**local 用 cgroup，shared 用 socket_assign(TCX head)**。local 的 socket_assign 拦截未打通，暂停。

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

## 5. 未完成：local 的 socket_assign 拦截

现象与已查事实：

- `sb_tc_local_l2` 已挂 eth0 egress（TCX），`sb_tc_ctl` 里 `flags=1`、`delivery_ifindex=0x4f=79` 均正确；
- `sb_tc_stats` **全零** → `local_egress_mark` 在第一个统计点之前返回；
- 境外地址 `curl` 卡在 `SYN-SENT`，sing-box **没有任何连接日志**（即根本没产生连接）；
- L2 与 L3 表现一致 → 与交付链路类型/命名无关；
- `ss` 显示的是 socket 对端真实地址，**不能**用来判断包有没有被改写（我一度据此误判）。

锁定到两行：

```c
if (control == 0 || control->enabled == 0U || control->delivery_ifindex == 0U) return TC_ACT_UNSPEC;
if (skb->ingress_ifindex != 0U) return TC_ACT_UNSPEC;
```

控制块已排除，所以嫌疑集中在 `skb->ingress_ifindex != 0`（包可能被 landscape 重投过一次）。

**下一步（如果重启这个线）**：在 `native/tc.bpf.c` 的 `local_egress_mark` 里加六个计数器到已有 `sb_tc_stats`：

```
SKIP_ENABLED / SKIP_INGRESS / SKIP_PARSE / SKIP_SELECT / SKIP_SELFBYPASS / REDIRECTED
```

一次 `bpftool map dump name sb_tc_stats` 即可定位。**需要 `make generate`。**

## 6. 与 landscape / einat 的共存

- **einat**：传统 clsact，只处理它绑定的那张接口。TCX 恒先于 clsact，所以我们的程序总在它之前，它看不到被劫持的包。
- **landscape（TCX fork）**：默认 `Order::Last`（追加到链尾），我们 `head`，天然在其之前。
- 被劫持的包在我们这里 `bpf_redirect` 就终止了本 hook，后面的 NAT 不会执行，**不存在“要不要放过”的问题**。
- mark 给谁看？没人看：einat 只把 `skb->mark` 当 fib lookup 输入；landscape 的 32 位 mark 已全部占满（layout/trace/action/reuse/flow id）。**结论：不要用 mark 做旁路**。
- 两个 ebpf inbound 各自有独立私有 netns（`link-netnsid 4` / `5`），所以两条交付链路是**必需**的，不是冗余。

## 7. 交付相关文件

| 文件 | 作用 |
|---|---|
| `patches/sing-box/0001-delivery-option.patch` | sing-box 侧全部改动（含 clashapi 进程名） |
| `patches/modules/sing-ebpf/pin.env` | `MODULE_REF` 指向模块提交 |
| 模块 `native/cgroup.bpf.c` | pname 判定 + owner 早退 + 4 个 marker section |
| 模块 `internal/core/marker.go` | 精简版加载器（只挑 4 程序 + 2 表） |
| 模块 `internal/core/process_bypass.go` | 名字校验 + LPM 写入 |
| 模块 `runtime/tc_delivery.go` | 交付设备命名（`netkit-l3` → `sb-netkit-`） |

## 8. 流程备忘

- Go 改动 → 只 Build；`native/*.bpf.c`、`abi.h` 改动 → 必须 `make generate`；
- `generate-objects` **不会自动提交**，产物在 run 页面的 Artifacts 里，要手动下载覆盖 `internal/bpfgen/` 再提交；
- 模块和 sing-box 补丁是一对：改模块的公开签名/类型名，补丁必须同批更新；
- 判断 generate 是否跑对：`internal/bpfgen/manifest.txt` 里 `native/cgroup.bpf.c` 的 sha256 应与实际文件一致（当前 `dfb9d129…6149`）。
