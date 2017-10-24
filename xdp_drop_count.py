#!/usr/bin/env python
#
# xdp_drop_count.py Drop incoming packets on XDP layer and count for which
#                   protocol type
#
# Copyright (c) 2016 PLUMgrid
# Copyright (c) 2016 Jan Ruth
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import pyroute2
import time
import sys

flags = 0
def usage():
    print("Usage: {0} [-S] <ifdev>".format(sys.argv[0]))
    print("       -S: use skb mode\n")
    print("e.g.: {0} eth0\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) < 2 or len(sys.argv) > 3:
    usage()

if len(sys.argv) == 2:
    device = sys.argv[1]

if len(sys.argv) == 3:
    if "-S" in sys.argv:
        # XDP_FLAGS_SKB_MODE
        flags |= 2 << 0

    if "-S" == sys.argv[1]:
        device = sys.argv[2]
    else:
        device = sys.argv[1]

# mode = BPF.XDP
mode = BPF.SCHED_CLS

if mode == BPF.XDP:
    ret = "XDP_DROP"
    retok = "XDP_PASS"
    ctxtype = "xdp_md"
else:
    ret = "TC_ACT_SHOT"
    retok = "TC_ACT_OK"
    ctxtype = "__sk_buff"

program = "none"

with open("data/ebpf/drop-subnet-tcp-payload-filter-percpu.c") as programfile:
    program="".join(programfile.readlines())

# load BPF program
b = BPF(text = program, cflags=["-w", "-DRETURNCODE=%s" % ret, "-DRETURNCODEOK=%s" % retok, "-DCTXTYPE=%s" % ctxtype])

fn = b.load_func("bpf_prog", mode)

if mode == BPF.XDP:
    b.attach_xdp(device, fn) #, flags)
    # pass
else:
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    idx = ipdb.interfaces[device].index
    ip.tc("add", "clsact", idx)
    ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
          parent="ffff:fff2", classid=1, direct_action=True)

dropcnt = b.get_table("dropcnt")
prev = [0] * 256
maxDelta = [0] * 256
print("Printing drops per IP protocol-number, hit CTRL+C to stop")
while 1:
    print "\n{IP protocol-number}: {total dropped pkts} : {pkts/s} : {max pkts/s}"
    try:
        for k in dropcnt.keys():
            val = dropcnt.sum(k).value
            i = k.value
            if val:
                delta = val - prev[i]
                prev[i] = val
                maxDelta[i] = max(maxDelta[i], delta)
                print("{} : {} pkts : {} pkt/s : {} pkt/s".format(i, val, delta, maxDelta[i]))
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break;

if mode == BPF.XDP:
    b.remove_xdp(device) #, flags)
else:
    ip.tc("del", "clsact", idx)
    ipdb.release()
