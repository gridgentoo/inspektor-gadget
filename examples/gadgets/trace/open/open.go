// Copyright 2022 The Inspektor Gadget authors
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

package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/rlimit"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/open/tracer"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

func main() {
	// In some kernel versions it's needed to bump the rlimits to
	// use run BPF programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		return
	}

	count := uint64(0)

	// Define a callback to be called each time there is an event.
	eventCallback := func(event types.Event) {
		if event.Type != eventtypes.NORMAL {
			fmt.Printf("%s: %s\n", event.Type, event.Message)
		}

		if event.Comm == "cosa" && event.Path == "/dev/null" {
			count++
		}
	}

	// Create the tracer. An empty configuration is passed as we are
	// not interesting on filtering by any container. For the same
	// reason, no enricher is passed.
	tracer, err := tracer.NewTracer(&tracer.Config{}, nil, eventCallback)
	if err != nil {
		fmt.Printf("error creating tracer: %s\n", err)
		return
	}

	// Wait for SIGINT
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	// Clean up everything before exiting.
	tracer.Stop()

	fmt.Printf("there were %d events\n", count)
}
