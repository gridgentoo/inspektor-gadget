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
	tcpTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/types"
)

func TestTraceTCP(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-tcp")

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("nginx-pod", "nginx", ns, "", ""),
		WaitUntilPodReadyCommand(ns, "nginx-pod"),
	}

	RunCommands(commandsPreTest, t)
	NginxIP := GetTestPodIP(ns, "nginx-pod")

	traceTCPCmd := &Command{
		Name:         "TraceTCP",
		Cmd:          fmt.Sprintf("local-gadget trace tcp -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			TestPodIP := GetTestPodIP(ns, "test-pod")

			expectedEntry := &tcpTypes.Event{
				Event:     BuildBaseEvent(ns),
				Comm:      "wget",
				IPVersion: 4,
				Saddr:     TestPodIP,
				Daddr:     NginxIP,
				Dport:     80,
				Operation: "connect",
			}

			normalize := func(e *tcpTypes.Event) {
				// TODO: Handle it once we support getting K8s container name for docker
				// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
				if *containerRuntime == ContainerRuntimeDocker {
					e.Container = "test-pod"
				}

				e.Timestamp = 0
				e.Pid = 0
				e.Sport = 0
				e.MountNsID = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		traceTCPCmd,
		SleepForSecondsCommand(2), // wait to ensure local-gadget has started
		BusyboxPodRepeatCommand(ns, fmt.Sprintf("wget -q -O /dev/null %s:80", NginxIP)),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}
