// Copyright 2021 The Inspektor Gadget authors
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

package localgadgetmanager

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
	top "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	ebpftoptypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"
	dnstypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

var rootTest = flag.Bool("root-test", false, "enable tests requiring root")

const (
	// The product of these to contansts defines the maximum wait
	// time before failing the checkFdList condition. These should
	// be large enough to allow all resources to be freeded. These
	// only affect the duration of the failing tests, hence it's not
	// a big problem to have big delays here.
	checkFdListInterval = 100 * time.Millisecond
	checkFdListAttempts = 20
)

func TestBasic(t *testing.T) {
	if !*rootTest {
		t.Skip("skipping test requiring root.")
	}
	localGadgetManager, err := NewManager(nil)
	if err != nil {
		t.Fatalf("Failed to start local gadget manager: %s", err)
	}
	defer localGadgetManager.Close()

	gadgets := localGadgetManager.ListGadgets()
	if len(gadgets) == 0 {
		t.Fatalf("Failed to get any gadgets")
	}
}

func stacks() string {
	buf := make([]byte, 1024)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

func currentFdList(t *testing.T) (ret string) {
	files, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("Failed to list fds: %s", err)
	}
	for _, file := range files {
		fd, err := strconv.Atoi(file.Name())
		if err != nil {
			continue
		}
		dest, err := os.Readlink("/proc/self/fd/" + file.Name())
		if err != nil {
			continue
		}
		ret += fmt.Sprintf("%d: %s\n", fd, dest)
	}
	return
}

func checkFdList(t *testing.T, initialFdList string, attempts int, sleep time.Duration) {
	for i := 0; ; i++ {
		finalFdList := currentFdList(t)
		if initialFdList == finalFdList {
			return
		}

		if i >= (attempts - 1) {
			t.Fatalf("After %d attempts, fd leaked:\n%s\n%s", attempts, initialFdList, finalFdList)
		}

		time.Sleep(sleep)
	}
}

// TestClose tests that resources aren't leaked after calling Close()
func TestClose(t *testing.T) {
	if !*rootTest {
		t.Skip("skipping test requiring root.")
	}

	initialFdList := currentFdList(t)

	for i := 0; i < 4; i++ {
		localGadgetManager, err := NewManager([]*containerutils.RuntimeConfig{{Name: "docker"}})
		if err != nil {
			t.Fatalf("Failed to start local gadget manager: %s", err)
		}

		if i%2 == 0 {
			testutils.RunDockerFailedContainer(context.Background(), t)
		}

		localGadgetManager.Close()
	}

	checkFdList(t, initialFdList, checkFdListAttempts, checkFdListInterval)
}

func TestEbpftop(t *testing.T) {
	if !*rootTest {
		t.Skip("skipping test requiring root.")
	}
	localGadgetManager, err := NewManager([]*containerutils.RuntimeConfig{{Name: "docker"}})
	if err != nil {
		t.Fatalf("Failed to start local gadget manager: %s", err)
	}
	defer localGadgetManager.Close()

	containerName := "test-local-gadget-dns001"
	err = localGadgetManager.AddTraceResource("ebpftop", "my-tracer", containerName, gadgetv1alpha1.TraceOutputModeStream)
	if err != nil {
		t.Fatalf("Failed to create tracer: %s", err)
	}
	err = localGadgetManager.ExecTraceResourceOperation("my-tracer", gadgetv1alpha1.OperationStart)
	if err != nil {
		t.Fatalf("Failed to start the tracer: %s", err)
	}

	stop := make(chan struct{})

	ch, err := localGadgetManager.StreamTraceResourceOutput("my-tracer", stop)
	if err != nil {
		t.Fatalf("Failed to get stream: %s", err)
	}

	timeout := time.NewTimer(time.Second * 10)

	ctr := 0

	found := false

ebpfeventloop:
	for {
		select {
		case <-timeout.C:
			t.Fatalf("Timeout while waiting for stream events")
			break ebpfeventloop
		case result := <-ch:
			event := top.Event[ebpftoptypes.Stats]{}
			if err := json.Unmarshal([]byte(result), &event); err != nil {
				t.Fatalf("failed to unmarshal json: %s", err)
			}

			for _, s := range event.Stats {
				if s.Type == "Tracing" && s.Name == "ig_top_ebpf_it" {
					found = true
					break ebpfeventloop
				}
			}

			if ctr > 5 {
				break ebpfeventloop
			}
			ctr++
		}
	}

	close(stop)

	err = localGadgetManager.DeleteTraceResource("my-tracer")
	if err != nil {
		t.Fatalf("Failed to delete tracer: %s", err)
	}

	s := stacks()
	keyword := "ebpftop"
	if strings.Contains(s, keyword) {
		t.Fatalf("Error: stack contains %q:\n%s", keyword, s)
	}

	if !found {
		t.Fatalf("Expected ebpf program not found in ebpftop")
	}
}

func TestDNS(t *testing.T) {
	if !*rootTest {
		t.Skip("skipping test requiring root.")
	}
	localGadgetManager, err := NewManager([]*containerutils.RuntimeConfig{{Name: "docker"}})
	if err != nil {
		t.Fatalf("Failed to start local gadget manager: %s", err)
	}
	defer localGadgetManager.Close()

	initialFdList := currentFdList(t)

	containerName := "test-local-gadget-dns001"
	err = localGadgetManager.AddTraceResource("dns", "my-tracer", containerName, gadgetv1alpha1.TraceOutputModeStream)
	if err != nil {
		t.Fatalf("Failed to create tracer: %s", err)
	}
	err = localGadgetManager.ExecTraceResourceOperation("my-tracer", gadgetv1alpha1.OperationStart)
	if err != nil {
		t.Fatalf("Failed to start the tracer: %s", err)
	}

	// select a nameserver that is not symmetrical with endianness
	nameserver := "8.8.4.4"

	testutils.RunDockerContainer(context.Background(), t,
		"dig @"+nameserver+" magic-1-2-3-4.nip.io",
		testutils.WithName(containerName),
		testutils.WithImage("docker.io/tutum/dnsutils"),
	)

	stop := make(chan struct{})

	ch, err := localGadgetManager.StreamTraceResourceOutput("my-tracer", stop)
	if err != nil {
		t.Fatalf("Failed to get stream: %s", err)
	}

	var event dnstypes.Event
	var expectedEvent dnstypes.Event
	var result string

	// check that attached message is sent
	result = <-ch
	event = dnstypes.Event{}
	if err := json.Unmarshal([]byte(result), &event); err != nil {
		t.Fatalf("failed to unmarshal json: %s", err)
	}

	expectedEvent = dnstypes.Event{
		Event: eventtypes.Event{
			Type: eventtypes.DEBUG,
			CommonData: eventtypes.CommonData{
				Node:      "local",
				Namespace: "default",
				Pod:       "test-local-gadget-dns001",
			},
			Message: "tracer attached",
		},
	}

	if event != expectedEvent {
		t.Fatalf("Received: %v, Expected: %v", event, expectedEvent)
	}

	// check dns request is traced
	result = <-ch
	event = dnstypes.Event{}
	if err := json.Unmarshal([]byte(result), &event); err != nil {
		t.Fatalf("failed to unmarshal json: %s", err)
	}

	expectedEvent = dnstypes.Event{
		Event: eventtypes.Event{
			Type: eventtypes.NORMAL,
			CommonData: eventtypes.CommonData{
				Node:      "local",
				Namespace: "default",
				Pod:       "test-local-gadget-dns001",
			},
		},
		ID:         "0000",
		Qr:         dnstypes.DNSPktTypeQuery,
		Nameserver: nameserver,
		DNSName:    "magic-1-2-3-4.nip.io.",
		PktType:    "OUTGOING",
		QType:      "A",
	}

	// normalize
	id := event.ID
	event.ID = "0000"

	if event != expectedEvent {
		t.Fatalf("Received: %v, Expected: %v", event, expectedEvent)
	}

	// check dns response is traced
	result = <-ch
	event = dnstypes.Event{}
	if err := json.Unmarshal([]byte(result), &event); err != nil {
		t.Fatalf("failed to unmarshal json: %s", err)
	}

	expectedEvent.PktType = "HOST"
	expectedEvent.Qr = dnstypes.DNSPktTypeResponse
	expectedEvent.Rcode = "NoError"

	if event.ID != id {
		t.Fatalf("Response ID: %v, Expected: %v", event.ID, id)
	}
	event.ID = "0000"

	if event != expectedEvent {
		t.Fatalf("Received: %v, Expected: %v", event, expectedEvent)
	}

	// check that detached message is sent
	result = <-ch
	event = dnstypes.Event{}
	if err := json.Unmarshal([]byte(result), &event); err != nil {
		t.Fatalf("failed to unmarshal json: %s", err)
	}

	expectedEvent = dnstypes.Event{
		Event: eventtypes.Event{
			Type: eventtypes.DEBUG,
			CommonData: eventtypes.CommonData{
				Node:      "local",
				Namespace: "default",
				Pod:       "test-local-gadget-dns001",
			},
			Message: "tracer detached",
		},
	}

	if event != expectedEvent {
		t.Fatalf("Received: %v, Expected: %v", event, expectedEvent)
	}

	close(stop)

	err = localGadgetManager.DeleteTraceResource("my-tracer")
	if err != nil {
		t.Fatalf("Failed to delete tracer: %s", err)
	}

	s := stacks()
	keyword := "pkg/gadgets/trace/dns/"
	if strings.Contains(s, keyword) {
		t.Fatalf("Error: stack contains %q:\n%s", keyword, s)
	}

	checkFdList(t, initialFdList, checkFdListAttempts, checkFdListInterval)
}

func TestCollector(t *testing.T) {
	if !*rootTest {
		t.Skip("skipping test requiring root.")
	}
	localGadgetManager, err := NewManager([]*containerutils.RuntimeConfig{{Name: "docker"}})
	if err != nil {
		t.Fatalf("Failed to start local gadget manager: %s", err)
	}
	defer localGadgetManager.Close()

	err = localGadgetManager.AddTraceResource("socket-collector", "my-tracer1", "my-container", gadgetv1alpha1.TraceOutputModeStatus)
	if err != nil {
		t.Fatalf("Failed to create tracer: %s", err)
	}
	err = localGadgetManager.ExecTraceResourceOperation("my-tracer1", gadgetv1alpha1.OperationCollect)
	if err != nil {
		t.Fatalf("Failed to run the tracer: %s", err)
	}
}
