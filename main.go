// xdp_drop.go Drop incoming packets on XDP layer and count for which
// protocol type. Based on:
// https://github.com/iovisor/bcc/blob/master/examples/networking/xdp/xdp_drop_count.py
//
// Copyright (c) 2017 GustavoKatel
// Licensed under the Apache License, Version 2.0 (the "License")

package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	bpf "github.com/GustavoKatel/gobpf/bcc"
	"github.com/vishvananda/netlink"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
*/
import "C"

func usage() {
	fmt.Printf("Usage: %v (xdp|tccls|tcact) <ifdev>\n", os.Args[0])
	fmt.Printf("e.g.: %v xdp eth0\n", os.Args[0])
}

func main() {
	sourceData, dataErr := Asset("data/ebpf/drop-all.c")
	if dataErr != nil {
		fmt.Println(dataErr)
		return
	}

	source := string(sourceData)

	var device string

	if len(os.Args) != 3 {
		usage()
		return
	}

	var ret, ctxtype string
	var mode int
	switch os.Args[1] {
	case "xdp":
		ret = "XDP_DROP"
		ctxtype = "xdp_md"
		mode = C.BPF_PROG_TYPE_XDP
	case "tccls":
		ret = "TC_ACT_SHOT"
		ctxtype = "__sk_buff"
		mode = C.BPF_PROG_TYPE_SCHED_CLS
	case "tcact":
		ret = "TC_ACT_SHOT" // TODO: correct return type
		ctxtype = "__sk_buff"
		mode = C.BPF_PROG_TYPE_SCHED_ACT
		// fmt.Fprintln(os.Stderr, "Not implemented yet")
		// return
	default:
		usage()
		return
	}

	device = os.Args[2]

	module := bpf.NewModule(source, []string{
		"-w",
		"-DRETURNCODE=" + ret,
		"-DCTXTYPE=" + ctxtype,
	})
	defer module.Close()

	fn, err := module.Load("bpf_prog", mode)

	if mode == C.BPF_PROG_TYPE_XDP {
		err = module.AttachXDP(device, fn)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		defer func() {
			if err := module.RemoveXDP(device); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", device, err)
			}
		}()

	} else {
		var link netlink.Link
		var filter netlink.Filter

		link, err = netlink.LinkByName(device)
		if err != nil {
			fmt.Fprintln(os.Stderr, "LinkByName:", err)
			return
		}

		// add clsact qdisc
		qdisc := &netlink.GenericQdisc{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Handle:    netlink.MakeHandle(0xffff, 0),
				Parent:    netlink.HANDLE_CLSACT,
			},
			QdiscType: "clsact",
		}
		// This feature was added in kernel 4.5
		if err := netlink.QdiscAdd(qdisc); err != nil {
			fmt.Fprintf(os.Stderr, "Failed adding clsact qdisc: %v\n", err)
			return
		}

		defer func() {
			if err = netlink.QdiscDel(qdisc); err != nil {
				fmt.Fprintln(os.Stderr, "QdiscDel", err)
			}
		}()

		if mode == C.BPF_PROG_TYPE_SCHED_CLS {
			filter = &netlink.BpfFilter{
				FilterAttrs: netlink.FilterAttrs{
					LinkIndex: link.Attrs().Index,
					Parent:    netlink.HANDLE_MIN_INGRESS,
					Handle:    netlink.MakeHandle(0, 1),
					Protocol:  syscall.ETH_P_ALL,
					Priority:  1,
				},
				Fd:           fn,
				Name:         "bpf_prog",
				DirectAction: true,
			}
			if filter.(*netlink.BpfFilter).Fd < 0 {
				fmt.Fprintln(os.Stderr, "Failed to load bpf program")
				return
			}

		} else { // SCHED_ACT
			// mode == C.BPF_PROG_TYPE_SCHED_ACT
			classID := netlink.MakeHandle(1, 1)
			// create a U32 filter and attach a BPFAction
			filter = &netlink.U32{
				FilterAttrs: netlink.FilterAttrs{
					LinkIndex: link.Attrs().Index,
					// Parent:    netlink.MakeHandle(0xffff, 0),
					Parent:   netlink.HANDLE_MIN_INGRESS,
					Handle:   netlink.MakeHandle(0, 1),
					Priority: 1,
					Protocol: syscall.ETH_P_ALL,
				},
				ClassId: classID,
				Actions: []netlink.Action{
					&netlink.BpfAction{Fd: fn, Name: "bpf_prog"},
				},
			}
		}

		if err := netlink.FilterAdd(filter); err != nil {
			fmt.Fprintln(os.Stderr, "FilterAdd:", err)
			// os.Exit(1)
			return
		}

		filters, errL := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)

		fmt.Printf("filters count: %v\n", len(filters))
		fmt.Printf("Err: %v\n", errL)

		defer func() {
			if err := netlink.FilterDel(filter); err != nil {
				fmt.Fprintln(os.Stderr, "FilterDel", err)
			}
		}()

	}

	fmt.Println("Dropping packets, hit CTRL+C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	dropcnt := bpf.NewTable(module.TableId("dropcnt"), module)
	lastDropCount := make([]uint64, 256)
	dropDelta := make([]uint64, 256)

	tick := time.Tick(1 * time.Second)

	for {
		select {
		case <-tick:
			fmt.Printf("\n{IP protocol-number}: {total dropped pkts} : {pkts/s}\n")
			for entry := range dropcnt.Iter() {
				var key, value uint64
				var err error

				key, err = strconv.ParseUint(entry.Key, 0, 32)
				if err != nil {
					// fmt.Fprintln(os.Stderr, err)
					continue
				}

				value, err = strconv.ParseUint(entry.Value, 0, 32)
				if err != nil {
					// fmt.Fprintln(os.Stderr, err)
					continue
				}

				if value > 0 {
					delta := value - lastDropCount[key]
					lastDropCount[key] = value
					dropDelta[key] = delta
					fmt.Printf("%v: %v pkts : %v pkts/s\n", key, value, delta)
				}
			}
		case <-sig:
			fmt.Println("Exiting...")
			return
		}

	}

}
