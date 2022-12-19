//go:build linux
// +build linux

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

package tracer

import (
	"fmt"
	"os/exec"
	"reflect"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/internal/test"
	snapshotProcessTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type collectorFunc func(config *Config, enricher gadgets.DataEnricher) ([]*snapshotProcessTypes.Event, error)

func BenchmarkEBPFTracer(b *testing.B) {
	benchmarkTracer(b, runeBPFCollector)
}

func BenchmarkProcfsTracer(b *testing.B) {
	benchmarkTracer(b, runProcfsCollector)
}

func benchmarkTracer(b *testing.B, runCollector collectorFunc) {
	utilstest.RequireRoot(b)

	for n := 0; n < b.N; n++ {
		_, err := runCollector(&Config{}, nil)
		if err != nil {
			b.Fatalf("benchmarking collector: %s", err)
		}
	}
}

func TestEBPFTracer(t *testing.T) {
	testTracer(t, runeBPFCollector)
}

func TestProcfsTracer(t *testing.T) {
	testTracer(t, runProcfsCollector)
}

func testTracer(t *testing.T, runCollector collectorFunc) {
	t.Parallel()

	utilstest.RequireRoot(t)

	type testDefinition struct {
		getTracerConfig func(info *utilstest.RunnerInfo) *Config
		runnerConfig    *utilstest.RunnerConfig
		generateEvent   func() (int, error)
		validateEvent   func(t *testing.T, info *utilstest.RunnerInfo, sleepPid int, events []snapshotProcessTypes.Event)
	}

	for name, test := range map[string]testDefinition{
		"captures_all_events_with_no_filters_configured": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *Config {
				return &Config{}
			},
			generateEvent: generateEvent,
			validateEvent: utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, sleepPid int) *snapshotProcessTypes.Event {
				return &snapshotProcessTypes.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Command:   "sleep",
					Pid:       sleepPid,
					Tid:       sleepPid,
					MountNsID: info.MountNsID,
				}
			}),
		},
		"captures_no_events_with_no_matching_filter": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *Config {
				return &Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, 0),
				}
			},
			generateEvent: generateEvent,
			validateEvent: utilstest.ExpectNoEvent[snapshotProcessTypes.Event, int],
		},
		"captures_events_with_matching_filter": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *Config {
				return &Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, sleepPid int, events []snapshotProcessTypes.Event) {
				if len(events) != 2 {
					t.Fatalf("%d events expected, found: %d", 2, len(events))
				}

				expectedEvent := &snapshotProcessTypes.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Command:   "sleep",
					Pid:       sleepPid,
					Tid:       sleepPid,
					MountNsID: info.MountNsID,
				}

				for _, event := range events {
					if reflect.DeepEqual(expectedEvent, &event) {
						return
					}
				}

				t.Fatalf("Event wasn't captured")
			},
		},
	} {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			runner := utilstest.NewRunnerWithTest(t, test.runnerConfig)

			var sleepPid int

			utilstest.RunWithRunner(t, runner, func() error {
				var err error
				sleepPid, err = test.generateEvent()
				return err
			})

			events, err := runCollector(test.getTracerConfig(runner.Info), nil)
			if err != nil {
				t.Fatalf("running collector: %s", err)
			}

			// TODO: This won't be required once we pass pointers everywhere
			validateEvents := []snapshotProcessTypes.Event{}
			for _, event := range events {
				validateEvents = append(validateEvents, *event)
			}

			test.validateEvent(t, runner.Info, sleepPid, validateEvents)
		})
	}
}

// Function that runs a "sleep" process.
func generateEvent() (int, error) {
	cmd := exec.Command("/bin/sleep", "3")
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("running command: %w", err)
	}

	return cmd.Process.Pid, nil
}
