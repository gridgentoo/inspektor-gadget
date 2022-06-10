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

package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	processcollectortypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/process-collector/types"
	socketcollectortypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/socket-collector/types"

	"github.com/spf13/cobra"
)

// All the gadgets within this package use this global variable, so let's
// declare it here.
var params utils.CommonFlags

var SnapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Take a snapshot of a subsystem and print it",
}

type Event interface {
	socketcollectortypes.Event | processcollectortypes.Event
}

func getSnapshotCallback[T Event](
	sort func([]T),
	getColsHeader func([]string) string,
	transformEvent func(T) string,
) func(results []gadgetv1alpha1.Trace) error {
	return func(results []gadgetv1alpha1.Trace) error {
		allEvents := []T{}

		for _, i := range results {
			if len(i.Status.Output) == 0 {
				continue
			}

			var events []T
			if err := json.Unmarshal([]byte(i.Status.Output), &events); err != nil {
				return utils.WrapInErrUnmarshalOutput(err, i.Status.Output)
			}

			allEvents = append(allEvents, events...)
		}

		sort(allEvents)

		// JSON output mode does not need any additional parsing
		if params.OutputMode == utils.OutputModeJSON {
			b, err := json.MarshalIndent(allEvents, "", "  ")
			if err != nil {
				return utils.WrapInErrMarshalOutput(err)
			}
			fmt.Printf("%s\n", b)
			return nil
		}

		// In the snapshot gadgets it's possible to use a tabwriter to print
		// columns because we have the full list of events to print available,
		// hence the tablewriter is able to determine the columns width. In
		// other gadgets we don't know the size of all columns "a priori", hence
		// we have to do a best effort printing fixed-width columns.
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)

		// Print header and the requested columns
		fmt.Fprintln(w, getColsHeader(params.CustomColumns))
		for _, e := range allEvents {
			fmt.Fprintln(w, transformEvent(e))
		}

		w.Flush()

		return nil
	}
}
