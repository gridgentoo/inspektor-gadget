//go:build linux
// +build linux

// Copyright 2019-2021 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tracer

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/filetop/types"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// #include <linux/types.h>
// #include "./bpf/filetop.h"
import "C"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang filetop ./bpf/filetop.bpf.c -- -I./bpf/ -I../../..

type Config struct {
	MountnsMap *ebpf.Map
	TargetPid  int
	AllFiles   bool
	MaxRows    int
	Interval   time.Duration
	SortBy     types.SortBy
	Node       string
}

type Tracer struct {
	config        *Config
	objs          filetopObjects
	readLink      link.Link
	writeLink     link.Link
	resolver      containercollection.ContainerResolver
	statsCallback func([]types.Stats)
	errorCallback func(error)
	done          chan bool
}

func NewTracer(config *Config, resolver containercollection.ContainerResolver,
	statsCallback func([]types.Stats), errorCallback func(error),
) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		resolver:      resolver,
		statsCallback: statsCallback,
		errorCallback: errorCallback,
		done:          make(chan bool),
	}

	if err := t.start(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
}

func (t *Tracer) Stop() {
	close(t.done)

	t.readLink = gadgets.CloseLink(t.readLink)
	t.writeLink = gadgets.CloseLink(t.writeLink)

	t.objs.Close()
}

func (t *Tracer) start() error {
	spec, err := loadFiletop()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if t.config.MountnsMap != nil {
		filterByMntNs = true
		mapReplacements["mount_ns_set"] = t.config.MountnsMap
	}

	consts := map[string]interface{}{
		"target_pid":        uint32(t.config.TargetPid),
		"regular_file_only": !t.config.AllFiles,
		"filter_by_mnt_ns":  filterByMntNs,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("error RewriteConstants: %w", err)
	}

	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}

	if err := spec.LoadAndAssign(&t.objs, &opts); err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	kpread, err := link.Kprobe("vfs_read", t.objs.VfsReadEntry, nil)
	if err != nil {
		return fmt.Errorf("error opening kprobe: %w", err)
	}
	t.readLink = kpread

	kpwrite, err := link.Kprobe("vfs_write", t.objs.VfsWriteEntry, nil)
	if err != nil {
		return fmt.Errorf("error opening kprobe: %w", err)
	}
	t.writeLink = kpwrite

	t.run()

	return nil
}

func (t *Tracer) nextStats() ([]types.Stats, error) {
	stats := []types.Stats{}
	entries := t.objs.Entries

	next_key_out := C.struct_file_id_pub{}
	keys_out := make([]C.struct_file_id_pub, 10240)
	values_out := make([]C.struct_file_stat_pub, 10240)

	count, err := entries.BatchLookupAndDelete(nil, unsafe.Pointer(&next_key_out), keys_out, values_out, nil)
	fmt.Printf("error was %s\n", err)
	fmt.Printf("lookup returned %d keys\n", count)
	if err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("error getting next key: %w", err)
		}
	}

	for i := 0; i < count; i++ {
		fileStat := values_out[i]
		stat := types.Stats{
			Reads:      uint64(fileStat.Reads),
			Writes:     uint64(fileStat.Writes),
			ReadBytes:  uint64(fileStat.Read_bytes),
			WriteBytes: uint64(fileStat.Write_bytes),
			Pid:        uint32(fileStat.Pid),
			Tid:        uint32(fileStat.Tid),
			Filename:   C.GoString(&fileStat.Filename[0]),
			Comm:       C.GoString(&fileStat.Comm[0]),
			FileType:   byte(fileStat.Type_),
			MountNsID:  uint64(fileStat.Mntns_id),
		}
		container := t.resolver.LookupContainerByMntns(stat.MountNsID)
		if container != nil {
			stat.Container = container.Name
			stat.Pod = container.Podname
			stat.Namespace = container.Namespace
			stat.Node = t.config.Node
		}
		stats = append(stats, stat)
	}

	types.SortStats(stats, t.config.SortBy)

	fmt.Printf("returning stats with %d elements\n", len(stats))

	return stats, nil
}

func (t *Tracer) run() {
	ticker := time.NewTicker(t.config.Interval)

	go func() {
		for {
			select {
			case <-t.done:
			case <-ticker.C:
				stats, err := t.nextStats()
				if err != nil {
					t.errorCallback(err)
					return
				}

				n := len(stats)
				if n > t.config.MaxRows {
					n = t.config.MaxRows
				}
				t.statsCallback(stats[:n])
			}
		}
	}()
}
