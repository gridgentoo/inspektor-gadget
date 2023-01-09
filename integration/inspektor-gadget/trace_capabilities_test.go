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

	tracecapabilitiesTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTraceCapabilities(t *testing.T) {
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running trace capabilities on ARO: See https://github.com/inspektor-gadget/inspektor-gadget/issues/985 for more details")
	}

	ns := GenerateTestNamespaceName("test-trace-capabilities")

	t.Parallel()

	traceCapabilitiesCmd := &Command{
		Name:         "StartTraceCapabilitiesGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace capabilities -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &tracecapabilitiesTypes.Event{
				Event:   BuildBaseEvent(ns),
				Comm:    "nice",
				CapName: "SYS_NICE",
				Cap:     23,
				Audit:   1,
				Verdict: "Deny",
			}

			normalize := func(e *tracecapabilitiesTypes.Event) {
				e.Node = ""
				e.Pid = 0
				e.UID = 0
				e.MountNsID = 0
				// Do not check InsetID to avoid introducing dependency on the kernel version
				e.InsetID = nil
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceCapabilitiesCmd,
		BusyboxPodRepeatCommand(ns, "nice -n -20 echo"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}
