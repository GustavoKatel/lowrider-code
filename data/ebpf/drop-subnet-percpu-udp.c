#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

// 192.168.50.0
#define BLOCK_SUBNET 0x32A8C0

BPF_TABLE("percpu_array", uint32_t, long, dropcnt, 256);

static inline int drop(uint32_t index) {
    // bpf_trace_printk("drop: index: %d\n", index);
    long *value;
    value = dropcnt.lookup(&index);
    if (value) {
        *value += 1;
        // bpf_trace_printk("index: %d value: %ld\n", index, *value);
    }

    return RETURNCODE;
}

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end)
        return RETURNCODE;

    u32 dest = iph->daddr;
    u32 subnet = iph->daddr & 0x00ffffff;

    // bpf_trace_printk("addr: 0x%x subnet: 0x%x filter: 0x%x\n", dest, subnet, BLOCK_SUBNET);

    // block UDP (17) and subnet
    if(iph->protocol==17 && subnet == BLOCK_SUBNET) {
        return drop(iph->protocol);
    }

    return RETURNCODEOK;
}

static inline int parse_ipv6(void *data, u64 nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;

    if ((void*)&ip6h[1] > data_end)
        return RETURNCODE;
    return drop(ip6h->nexthdr);
}

int bpf_prog(struct CTXTYPE *ctx) {

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;

    // drop packets
    uint16_t h_proto;
    uint64_t nh_off = 0;

    nh_off = sizeof(*eth);

    if (data + nh_off  > data_end)
        return RETURNCODE;

    h_proto = eth->h_proto;

    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return RETURNCODE;
            h_proto = vhdr->h_vlan_encapsulated_proto;
    }
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return RETURNCODE;
            h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (h_proto == htons(ETH_P_IP))
        return parse_ipv4(data, nh_off, data_end);
    else if (h_proto == htons(ETH_P_IPV6))
        return parse_ipv6(data, nh_off, data_end);
    else
        return RETURNCODEOK;
}