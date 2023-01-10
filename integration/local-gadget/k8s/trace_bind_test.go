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
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	bindTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/bind/types"
)

func TestTraceBind(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-bind")

	traceBindCmd := &Command{
		Name:         "TraceBind",
		Cmd:          fmt.Sprintf("local-gadget trace bind -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &bindTypes.Event{
				Event:    BuildBaseEvent(ns),
				Comm:     "nc",
				Protocol: "TCP",
				Addr:     "::",
				Port:     9090,
				Options:  ".R...",
			}

			normalize := func(e *bindTypes.Event) {
				// TODO: Handle it once we support getting K8s container name for docker
				// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
				if *containerRuntime == ContainerRuntimeDocker {
					e.Container = "test-pod"
				}

				e.Timestamp = 0
				e.Pid = 0
				e.MountNsID = 0
			}

			// Since we aren't doing any filtering in traceBindCmd we avoid using ExpectAllToMatch
			// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/644
			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceBindCmd,
		SleepForSecondsCommand(2), // wait to ensure local-gadget has started
		BusyboxPodRepeatCommand(ns, "nc -l -p 9090 -w 1"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}
