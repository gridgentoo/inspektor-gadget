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

package snapshot

import (
	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/pkg/columns"
	processTypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/snapshot/process/types"
)

type ProcessFlags struct {
	ShowThreads bool
}

func GetProcessColumns(flags *ProcessFlags) *columns.Columns[processTypes.Event] {
	cols := processTypes.GetColumns()

	if flags.ShowThreads {
		tidCol, ok := cols.GetColumn("tid")
		if !ok {
			panic(`making "tid" column visible`)
		}

		tidCol.Visible = true
	}

	return cols
}

func RemoveMultiThreads(allProcesses *[]processTypes.Event) {
	// Keep only main thread per PID and filter out other threads
	allProcessesTrimmed := []processTypes.Event{}
	for _, i := range *allProcesses {
		if i.Tid == i.Pid {
			allProcessesTrimmed = append(allProcessesTrimmed, i)
		}
	}
	*allProcesses = allProcessesTrimmed
}

func NewProcessCmd(runCmd func(*cobra.Command, []string) error, flags *ProcessFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "process",
		Short: "Gather information about running processes",
		RunE:  runCmd,
	}

	cmd.PersistentFlags().BoolVarP(
		&flags.ShowThreads,
		"threads",
		"t",
		false,
		"Show all threads",
	)

	return cmd
}
