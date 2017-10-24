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

#define TCP_DPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))

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
    nh_off += sizeof(struct iphdr);

    if ((void*)&iph[1] > data_end)
        return RETURNCODE;

    u32 dest = iph->daddr;
    u32 subnet = iph->daddr & 0x00ffffff;

    // block TCP (6) and subnet and tcp-flags
    if(iph->protocol==IPPROTO_TCP && subnet == BLOCK_SUBNET) {
        struct tcphdr *tcph = data + nh_off;
        nh_off += sizeof(struct tcphdr);
        if (data + nh_off > data_end) {
            return RETURNCODE;
        }

        u32 doff = tcph->doff << 2;
        u16 payload_length = iph->tot_len - (iph->ihl<<2) - doff;
        unsigned char *payload = data + 14 + (iph->ihl<<2) + doff;

        // bpf_trace_printk("payload: 0x%x payload_len: 0x%x doff: 0x%x\n", payload, payload_length, doff);
        // bpf_trace_printk("data_end: 0x%x\n", data_end);

        if (payload_length < 7) {
            // return drop(0);
            return RETURNCODE;
        }

        if(payload + 2 > data_end) {
            return RETURNCODEOK;
        }

        // bpf_trace_printk("payload len: 0x%x byte0: 0x%x\n", payload_length, *(payload+offset));

        if(payload[1] == 'X') {
            return drop(iph->protocol);
        }

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