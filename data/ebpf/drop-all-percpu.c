#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

//#define DEBUG 1
#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

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

static inline int drop_error() {
    return drop(255);
}

int bpf_prog(struct CTXTYPE *ctx) {

    return drop(0);
}