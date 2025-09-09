// SPDX-License-Identifier: GPL-2.0
#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <arpa/inet.h> 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, __u64);
    __type(value, __u8);
} blocklist_map SEC(".maps");

/* flow_id 생성 */
static __always_inline __u64 make_flow_id(__u32 sip, __u32 dip,
                                          __u16 dport,
                                          __u8 proto) {
    __u64 v = sip;
    v = (v << 32) ^ dip;
    v ^= ((__u64)dport << 16) ^ proto;
    v ^= (v >> 33);
    v *= 0xff51afd7ed558ccdULL;
    v ^= (v >> 33);
    return v;
}

SEC("xdp")
int xdp_sock_kern(struct xdp_md *ctx)
{
    __u32 rx_queue_index = ctx->rx_queue_index;

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    struct iphdr *iph = NULL;
    struct tcphdr *th = NULL;
    struct udphdr *uh = NULL;

    __u32 sip = 0;
    __u32 dip = 0;
    __u8 proto = 0;
    __u16 sport = 0;
    __u16 dport = 0;

    __u64 fid = 0;
    __u8 *blk = NULL;

    void *nh = NULL;

    if ((void*)(eth+1) > data_end) 
	    return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP)) 
	    return XDP_PASS;

    iph = (void*)(eth+1);

    if ((void*)(iph+1) > data_end) 
	    return XDP_PASS;

    sip = iph->saddr;
    dip = iph->daddr;
    proto = iph->protocol;

    nh = (void*)iph + (iph->ihl*4);

    if (proto == IPPROTO_TCP) 
    {
        th = nh;
        if ((void*)(th+1) > data_end) 
		return XDP_PASS;

        sport = ntohs(th->source); 
	dport = ntohs(th->dest);
    } else if (proto == IPPROTO_UDP) 
    {
        uh = nh;
        if ((void*)(uh+1) > data_end) 
		return XDP_PASS;

        sport = ntohs(uh->source); 
	dport = ntohs(uh->dest);
    } else 
	    return XDP_PASS;

    fid = make_flow_id(sip,dip,dport,proto);
    blk = bpf_map_lookup_elem(&blocklist_map, &fid);

    if ( blk && *blk == 1 ) 
    {
	    bpf_printk("DROP sip:[%u.%u.%u.%u][%x] dip:[%u.%u.%u.%u][%x] ifindex:[%d]\n", 
			    NIPQUAD(iph->saddr), iph->saddr, NIPQUAD(iph->daddr), iph->daddr, ctx->ingress_ifindex);

	    return XDP_DROP;
    }

    bpf_printk("ACCEPT sip:[%u.%u.%u.%u][%x] dip:[%u.%u.%u.%u][%x] ifindex:[%d]\n", 
		    NIPQUAD(iph->saddr), iph->saddr, NIPQUAD(iph->daddr), iph->daddr, ctx->ingress_ifindex);

    return bpf_redirect_map(&xsks_map, rx_queue_index, 0);
}

char _license[] SEC("license") = "GPL";
