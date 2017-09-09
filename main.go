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

	bpf "github.com/GustavoKatel/gobpf/bcc"
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
	fmt.Printf("Usage: %v <ifdev>\n", os.Args[0])
	fmt.Printf("e.g.: %v eth0\n", os.Args[0])
	os.Exit(1)
}

func main() {
	sourceData, dataErr := Asset("data/ebpf/xdp-drop-bpf.c")
	if dataErr != nil {
		fmt.Println(dataErr)
		os.Exit(1)
	}

	source := string(sourceData)

	var device string

	if len(os.Args) != 2 {
		usage()
	}

	device = os.Args[1]

	ret := "XDP_DROP"
	ctxtype := "xdp_md"

	module := bpf.NewModule(source, []string{
		"-w",
		"-DRETURNCODE=" + ret,
		"-DCTXTYPE=" + ctxtype,
	})
	defer module.Close()

	fn, err := module.Load("xdp_prog1", C.BPF_PROG_TYPE_XDP)

	err = module.AttachXDP(device, fn)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	defer func() {
		if err := module.RemoveXDP(device); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", device, err)
		}
	}()

	fmt.Println("Dropping packets, hit CTRL+C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	dropcnt := bpf.NewTable(module.TableId("dropcnt"), module)

	<-sig

	fmt.Printf("\n{IP protocol-number}: {total dropped pkts}\n")
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
			fmt.Printf("%v: %v pkts\n", key, value)
		}
	}
}