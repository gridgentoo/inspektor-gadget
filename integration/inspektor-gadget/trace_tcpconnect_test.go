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

	tracetcpconnectTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpconnect/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTraceTcpconnect(t *testing.T) {
	ns := GenerateTestNamespaceName("test-tcpconnect")

	t.Parallel()

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("nginx-pod", "nginx", ns, "", ""),
		WaitUntilPodReadyCommand(ns, "nginx-pod"),
	}

	RunTestSteps(commandsPreTest, t)
	NginxIP := GetTestPodIP(ns, "nginx-pod")

	traceTcpconnectCmd := &Command{
		Name:         "StartTraceTcpconnectGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace tcpconnect -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			TestPodIP := GetTestPodIP(ns, "test-pod")

			expectedEntry := &tracetcpconnectTypes.Event{
				Event:     BuildBaseEvent(ns),
				Comm:      "wget",
				IPVersion: 4,
				Dport:     80,
				Saddr:     TestPodIP,
				Daddr:     NginxIP,
			}

			normalize := func(e *tracetcpconnectTypes.Event) {
				e.Node = ""
				e.Pid = 0
				e.MountNsID = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		traceTcpconnectCmd,
		BusyboxPodRepeatCommand(ns, fmt.Sprintf("wget -q -O /dev/null %s:80", NginxIP)),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}
