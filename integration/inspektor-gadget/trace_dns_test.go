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

	tracednsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestDns(t *testing.T) {
	ns := GenerateTestNamespaceName("test-trace-dns")

	t.Parallel()

	traceDNSCmd := &Command{
		Name:         "StartTraceDnsGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace dns -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntries := []*tracednsTypes.Event{
				{
					Event:      BuildBaseEvent(ns),
					ID:         "0000",
					Qr:         tracednsTypes.DNSPktTypeQuery,
					Nameserver: "8.8.4.4",
					PktType:    "OUTGOING",
					DNSName:    "inspektor-gadget.io.",
					QType:      "A",
				},
				{
					Event:      BuildBaseEvent(ns),
					ID:         "0000",
					Qr:         tracednsTypes.DNSPktTypeResponse,
					Nameserver: "8.8.4.4",
					PktType:    "HOST",
					DNSName:    "inspektor-gadget.io.",
					QType:      "A",
					Rcode:      "NoError",
				},
				{
					Event:      BuildBaseEvent(ns),
					ID:         "0000",
					Qr:         tracednsTypes.DNSPktTypeQuery,
					Nameserver: "8.8.4.4",
					PktType:    "OUTGOING",
					DNSName:    "inspektor-gadget.io.",
					QType:      "A",
				},
				{
					Event:      BuildBaseEvent(ns),
					ID:         "0000",
					Qr:         tracednsTypes.DNSPktTypeResponse,
					Nameserver: "8.8.4.4",
					PktType:    "HOST",
					DNSName:    "inspektor-gadget.io.",
					QType:      "AAAA",
					Rcode:      "NoError",
				},
			}

			// DNS gadget doesn't provide container data. Remove it.
			for _, entry := range expectedEntries {
				entry.Container = ""
			}

			normalize := func(e *tracednsTypes.Event) {
				e.Node = ""
				e.ID = "0000"
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntries...)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceDNSCmd,
		BusyboxPodRepeatCommand(ns,
			"nslookup -type=a inspektor-gadget.io. 8.8.4.4 ;"+
				"nslookup -type=aaaa inspektor-gadget.io. 8.8.4.4"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}
