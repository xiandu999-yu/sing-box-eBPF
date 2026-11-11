// SPDX-License-Identifier: GPL-2.0
//
// TCP sockmap offload probe —— 只验证机制，不接入任何生产路径。
//
// 三个问题：
//   1. sk_skb stream verdict 里能不能拿到 socket cookie 当 SOCKHASH 的 key；
//   2. egress redirect（bpf_sk_redirect_hash，不带 BPF_F_INGRESS）能不能把
//      收到的数据交给另一个 socket 发出去；
//   3. 对端 socket 与接收 socket 不在同一个 netns 时还能不能重定向。
//
// 两个程序各自独立，用户态分别加载：
//   probe_verdict_cookie  用 bpf_get_socket_cookie() 做 key（生产方案）
//   probe_verdict_fixed   固定 key=0，只测 redirect 本身（cookie 不可用时的退路）
//
// 编译（本机 clang 21，产物随补丁提交；路由器上没有编译器）：
//   clang -target bpf -O2 -g -I/usr/include -I/usr/include/x86_64-linux-gnu \
//     -c tcp_offload_probe.bpf.c -o objects/tcp_offload_probe_bpfel.o

#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

// SK_PASS / SK_DROP：verdict 的返回值
#define PROBE_PASS 1
#define PROBE_DROP 0

struct probe_key {
    __u64 cookie;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 4096);
    __type(key, struct probe_key);
    __type(value, __u32);
} probe_sock SEC(".maps");

// [0] verdict 次数
// [1] cookie 非零次数
// [2] 查表命中次数
// [3] redirect 返回 SK_PASS 次数
// [4] redirect 返回 SK_DROP 次数
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} probe_stats SEC(".maps");

static void *(*map_lookup)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static __u64 (*get_socket_cookie)(struct __sk_buff *skb) = (void *)BPF_FUNC_get_socket_cookie;
static long (*redirect_hash)(struct __sk_buff *skb, void *map, void *key, __u64 flags) =
    (void *)BPF_FUNC_sk_redirect_hash;

static __always_inline void bump(__u32 index) {
    __u64 *value = map_lookup(&probe_stats, &index);
    if (value != 0) __sync_fetch_and_add(value, 1);
}

static __always_inline int redirect(struct __sk_buff *skb, struct probe_key *key) {
    bump(0);
    if (map_lookup(&probe_sock, key) == 0) return PROBE_PASS;  // miss 必须放过，否则静默丢包
    bump(2);
    long result = redirect_hash(skb, &probe_sock, key, 0);  // 不带 BPF_F_INGRESS = egress
    if (result == PROBE_PASS) {
        bump(3);
    } else {
        bump(4);
        return PROBE_PASS;
    }
    return result;
}

SEC("sk_skb")
int probe_verdict_cookie(struct __sk_buff *skb) {
    struct probe_key key = {};
    key.cookie = get_socket_cookie(skb);
    if (key.cookie == 0) {
        bump(0);
        return PROBE_PASS;
    }
    bump(1);
    return redirect(skb, &key);
}

SEC("sk_skb")
int probe_verdict_fixed(struct __sk_buff *skb) {
    struct probe_key key = {};
    key.cookie = 0;
    return redirect(skb, &key);
}

char _license[] SEC("license") = "GPL";
