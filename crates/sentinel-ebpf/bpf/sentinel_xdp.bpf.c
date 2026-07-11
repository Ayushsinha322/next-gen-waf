/* Sentinel WAF — XDP source-IP blocklist.
 *
 * Drops packets from blocked IPs at the earliest point in the kernel (the NIC
 * driver / XDP hook), before they ever reach the userspace proxy socket.
 *
 * Maps (populated from userspace by the aya loader in sentinel-ebpf):
 *   - blocked_v4 : LPM trie of blocked IPv4 CIDRs (a /32 = a single IP)
 *   - blocked_v6 : LPM trie of blocked IPv6 CIDRs (a /128 = a single IP)
 *   - counters   : per-CPU [pass, drop] packet counters, polled by userspace
 *
 * Compiled to BPF bytecode with:
 *   clang -O2 -g -target bpf -c sentinel_xdp.bpf.c -o ../src/bpf/sentinel_xdp.o
 * The resulting ELF is committed and embedded via include_bytes! so the
 * runtime image builds on stable Rust with no BPF toolchain.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include "bpf_helpers_min.h"

#define COUNTER_PASS 0
#define COUNTER_DROP 1

/* LPM-trie keys: kernel requires the leading u32 prefix length, then the
 * address bytes in network byte order (matched MSB-first). */
struct lpm_v4_key {
    __u32 prefixlen;
    __u32 addr; /* network byte order */
};

struct lpm_v6_key {
    __u32 prefixlen;
    __u8 addr[16]; /* network byte order */
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_v4_key);
    __type(value, __u32);
} blocked_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_v6_key);
    __type(value, __u32);
} blocked_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

static __always_inline void bump(__u32 idx) {
    __u64 *c = bpf_map_lookup_elem(&counters, &idx);
    if (c)
        *c += 1;
}

static __always_inline int pass(void) {
    bump(COUNTER_PASS);
    return XDP_PASS;
}

static __always_inline int drop(void) {
    bump(COUNTER_DROP);
    return XDP_DROP;
}

SEC("xdp")
int sentinel_xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return pass();

    __u16 proto = eth->h_proto;

    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return pass();
        struct lpm_v4_key key = {
            .prefixlen = 32,
            .addr = ip->saddr, /* already network byte order */
        };
        if (bpf_map_lookup_elem(&blocked_v4, &key))
            return drop();
    } else if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return pass();
        struct lpm_v6_key key = {.prefixlen = 128};
        __builtin_memcpy(key.addr, &ip6->saddr, 16);
        if (bpf_map_lookup_elem(&blocked_v6, &key))
            return drop();
    }

    return pass();
}

char _license[] SEC("license") = "GPL";
