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
	networkTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestTraceNetwork(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-network")

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("nginx-pod", "nginx", ns, "", ""),
		WaitUntilPodReadyCommand(ns, "nginx-pod"),
	}

	RunTestSteps(commandsPreTest, t)
	nginxIP := GetTestPodIP(ns, "nginx-pod")

	traceNetworkCmd := &Command{
		Name:         "TraceNetwork",
		Cmd:          fmt.Sprintf("local-gadget trace network -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			testPodIP := GetTestPodIP(ns, "test-pod")

			expectedEntries := []*networkTypes.Event{
				{
					Event:      BuildBaseEvent(ns),
					PktType:    "OUTGOING",
					Proto:      "tcp",
					RemoteAddr: nginxIP,
					Port:       80,
				},
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							Namespace: ns,
							Pod:       "nginx-pod",
							Container: "nginx-pod",
						},
					},
					PktType:    "HOST",
					Proto:      "tcp",
					RemoteAddr: testPodIP,
					Port:       80,
				},
			}

			normalize := func(e *networkTypes.Event) {
				// TODO: Handle it once we support getting K8s container name for docker
				// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
				if *containerRuntime == ContainerRuntimeDocker {
					if e.Pod == "nginx-pod" {
						e.Container = "nginx-pod"
					} else if e.Pod == "test-pod" {
						e.Container = "test-pod"
					}
				}
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntries...)
		},
	}

	commands := []*Command{
		traceNetworkCmd,
		BusyboxPodRepeatCommand(ns, fmt.Sprintf("wget -q -O /dev/null %s:80", nginxIP)),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}
