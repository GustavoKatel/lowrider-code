#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#define DROP_IF "eth1"
// 192.168.50.0
#define BLOCK_SUBNET 0x32A8C0

static long int drop_count[256] = {0};
static long int last_drop_count[256] = {0};
static long int max_delta[256] = {0};

static struct task_struct *thread_ctrl; // stats printer

int ret;

static int thread_fn(void *unused)
{
    int i;
    long int delta;
    // Allow the SIGKILL signal
    allow_signal(SIGKILL);
    while (!kthread_should_stop()) {

        printk(KERN_INFO "\n{IP protocol-number}: {total dropped pkts} : {pkts/s} : {max pkts/s}\n");

        for(i=0;i<256;i++) {
            if(drop_count[i] == 0) continue;

            delta = abs(drop_count[i] - last_drop_count[i]);
            last_drop_count[i] = drop_count[i];
            max_delta[i] = max(delta, max_delta[i]);

            printk(KERN_INFO "%d : %ld pkts : %d pkts/s : %ld pkts/s\n", i, drop_count[i], delta, max_delta[i]);
        }

        ssleep(1);

        // Check if the signal is pending
        if (signal_pending(thread_ctrl)) {
            break;
        }
    }
    printk(KERN_INFO "Thread Stopping\n");
    do_exit(0);
    return 0;
}

int thread_init (void) {

    char *our_thread = "thread_stats_printer";
    printk(KERN_INFO "in init\n");

    thread_ctrl = kthread_run(&thread_fn,NULL,our_thread);

    return 0;
}

void thread_cleanup(void) {
    if (thread_ctrl) {
        kthread_stop(thread_ctrl);
        printk(KERN_INFO "Thread stopped\n");
    }
}

/* This function to be called by hook. */
static unsigned int
hook_func(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn) (struct sk_buff *))
{
    // struct udphdr *udp_header;
    // struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    struct iphdr *ip_header = ip_hdr(skb);

    // if (ip_header->protocol == 17) {
        // udp_header = udp_hdr(skb); // kernel >= 3.11
    //     udp_header = (struct udphdr *)skb_transport_header(skb); // kernel < 3.11
    //     printk(KERN_INFO "lowrider: Got an udp packet.\n");

    //     return NF_ACCEPT;
    // }

    // return NF_ACCEPT;

    /***************** drop all *******************/
    // if (strcmp(skb->dev->name, DROP_IF) == 0) {
    //     // printk("Dropped packet on %s...\n", DROP_IF);
    //     // drop_count[ip_header->protocol]++;
    //     drop_count[0]++;
    //     return NF_DROP;
    // } else {
    //     return NF_ACCEPT;
    // }

    /****************** drop subnet e udp ******************/
    // u32 dest = ip_header->daddr;
    // u32 subnet = ip_header->daddr & 0x00ffffff;
    // if(ip_header->protocol==17 && subnet == BLOCK_SUBNET) {
    //     // printk("Dropped packet on %s...\n", DROP_IF);
    //     drop_count[ip_header->protocol]++;
    //     // drop_count[0]++;
    //     return NF_DROP;
    // } else {
    //     return NF_ACCEPT;
    // }

    /****************** drop subnet & tcp flags ******************/
    // u32 dest = ip_header->daddr;
    // u32 subnet = ip_header->daddr & 0x00ffffff;
    // if(ip_header->protocol==6 && subnet == BLOCK_SUBNET) {

        //     struct tcphdr *tcph = tcp_hdr(skb);

        //     // printk("Dropped packet on %s...\n", DROP_IF);
    //     if(tcph->syn == 0x1 && tcph->rst == 0x1) {
    //         drop_count[ip_header->protocol]++;
    //         return NF_DROP;
    //     }

    //     return NF_ACCEPT;

    // } else {
    //     return NF_ACCEPT;
    // }

    /****************** drop subnet-tcp-payload-filter ******************/
    u32 dest = ip_header->daddr;
    u32 subnet = ip_header->daddr & 0x00ffffff;
    if(ip_header->protocol==6 && subnet == BLOCK_SUBNET) {

        struct tcphdr *tcph = tcp_hdr(skb);

        unsigned char *payload = (unsigned char *)((unsigned char *)tcph + (tcph->doff << 2));

        // printk("Dropped packet on %s...\n", DROP_IF);
        if(payload[1] == 'X') {
            drop_count[ip_header->protocol]++;
            return NF_DROP;
        }

        return NF_ACCEPT;

    } else {
        return NF_ACCEPT;
    }

}

static struct nf_hook_ops nfho = {
    .hook       = hook_func,
    // .hooknum    = NF_INET_LOCAL_IN,
    .hooknum    = NF_INET_PRE_ROUTING,
    .pf         = PF_INET,
    .priority   = NF_IP_PRI_FIRST,
};

int init_module(void)
{
    printk(KERN_INFO "lowrider: init_module() on %s\n", DROP_IF);

    ret = thread_init();

    if(ret != 0) {
        return ret;
    }

    nf_register_hook(&nfho);                     //register hook

	return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "lowrider: cleanup_module()\n");

    thread_cleanup();

    nf_unregister_hook(&nfho);                     //cleanup – unregister hook
}

MODULE_LICENSE("GPL");