// Copyright 2019-2022 The Inspektor Gadget authors
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

	tracenetworkTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTraceNetwork(t *testing.T) {
	ns := GenerateTestNamespaceName("test-trace-network")

	t.Parallel()

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("nginx-pod", "nginx", ns, "", ""),
		WaitUntilPodReadyCommand(ns, "nginx-pod"),
	}

	RunTestSteps(commandsPreTest, t)
	NginxIP := GetTestPodIP(ns, "nginx-pod")

	traceNetworkCmd := &Command{
		Name:         "StartTraceNetworkGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace network -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			TestPodIP := GetTestPodIP(ns, "test-pod")

			expectedEntry := &tracenetworkTypes.Event{
				Event:           BuildBaseEvent(ns),
				PktType:         "OUTGOING",
				Proto:           "tcp",
				RemoteAddr:      NginxIP,
				Port:            80,
				RemoteKind:      tracenetworkTypes.RemoteKindPod,
				PodIP:           TestPodIP,
				PodLabels:       map[string]string{"run": "test-pod"},
				RemoteNamespace: ns,
				RemoteName:      "nginx-pod",
				RemoteLabels:    map[string]string{"run": "nginx-pod"},
			}

			normalize := func(e *tracenetworkTypes.Event) {
				e.Node = ""
				e.PodHostIP = ""
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		traceNetworkCmd,
		BusyboxPodRepeatCommand(ns, fmt.Sprintf("wget -q -O /dev/null %s:80", NginxIP)),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}
