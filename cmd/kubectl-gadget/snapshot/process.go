// Copyright 2019-2021 The Inspektor Gadget authors
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
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/process-collector/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

var processCollectorParamThreads bool

var processCollectorCmd = &cobra.Command{
	Use:   "process",
	Short: "Gather information about running processes",
	RunE: func(cmd *cobra.Command, args []string) error {
		config := &utils.TraceConfig{
			GadgetName:       "process-collector",
			Operation:        "collect",
			TraceOutputMode:  "Status",
			TraceOutputState: "Completed",
			CommonFlags:      &params,
		}

		return utils.RunTraceAndPrintStatusOutput(config,
			getSnapshotCallback(sortProcesses, getProcessColsHeader, processTransformEvent))
	},
}

func init() {
	SnapshotCmd.AddCommand(processCollectorCmd)
	utils.AddCommonFlags(processCollectorCmd, &params)

	processCollectorCmd.PersistentFlags().BoolVarP(
		&processCollectorParamThreads,
		"threads",
		"t",
		false,
		"Show all threads",
	)
}

func getProcessColsHeader(cols []string) string {
	if len(cols) == 0 {
		if processCollectorParamThreads {
			return "NODE\tNAMESPACE\tPOD\tCONTAINER\tCOMM\tTGID\tPID"
		} else {
			return "NODE\tNAMESPACE\tPOD\tCONTAINER\tCOMM\tPID"
		}
	}

	var sb strings.Builder
	for _, col := range cols {
		switch col {
		case "node":
			sb.WriteString("NODE\t")
		case "namespace":
			sb.WriteString("NAMESPACE\t")
		case "pod":
			sb.WriteString("POD\t")
		case "container":
			sb.WriteString("CONTAINER\t")
		case "comm":
			sb.WriteString("COMM\t")
		case "tgid":
			sb.WriteString("TGID\t")
		case "pid":
			sb.WriteString("PID\t")
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}

// processTransformEvent is called to transform an event to columns
// format according to the parameters
func processTransformEvent(e types.Event) string {
	var sb strings.Builder

	if e.Type != eventtypes.NORMAL {
		utils.ManageSpecialEvent(e.Event, params.Verbose)
		return ""
	}

	switch params.OutputMode {
	case utils.OutputModeColumns:
		if processCollectorParamThreads {
			sb.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%d\t%d",
				e.Node, e.Namespace, e.Pod, e.Container,
				e.Command, e.Tgid, e.Pid))
		} else {
			sb.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%d",
				e.Node, e.Namespace, e.Pod, e.Container,
				e.Command, e.Pid))
		}
	case utils.OutputModeCustomColumns:
		for _, col := range params.CustomColumns {
			switch col {
			case "node":
				sb.WriteString(fmt.Sprintf("%s\t", e.Node))
			case "namespace":
				sb.WriteString(fmt.Sprintf("%s\t", e.Namespace))
			case "pod":
				sb.WriteString(fmt.Sprintf("%s\t", e.Pod))
			case "container":
				sb.WriteString(fmt.Sprintf("%s\t", e.Container))
			case "comm":
				sb.WriteString(fmt.Sprintf("%s\t", e.Command))
			case "tgid":
				sb.WriteString(fmt.Sprintf("%d\t", e.Tgid))
			case "pid":
				sb.WriteString(fmt.Sprintf("%d\t", e.Pid))
			}
			sb.WriteRune(' ')
		}
	}

	return sb.String()
}

func sortProcesses(allProcesses []types.Event) {
	if !processCollectorParamThreads {
		allProcessesTrimmed := []types.Event{}
		for _, i := range allProcesses {
			if i.Tgid == i.Pid {
				allProcessesTrimmed = append(allProcessesTrimmed, i)
			}
		}
		allProcesses = allProcessesTrimmed
	}

	sort.Slice(allProcesses, func(i, j int) bool {
		pi, pj := allProcesses[i], allProcesses[j]
		switch {
		case pi.Node != pj.Node:
			return pi.Node < pj.Node
		case pi.Namespace != pj.Namespace:
			return pi.Namespace < pj.Namespace
		case pi.Pod != pj.Pod:
			return pi.Pod < pj.Pod
		case pi.Container != pj.Container:
			return pi.Container < pj.Container
		case pi.Command != pj.Command:
			return pi.Command < pj.Command
		case pi.Tgid != pj.Tgid:
			return pi.Tgid < pj.Tgid
		default:
			return pi.Pid < pj.Pid
		}
	})
}
