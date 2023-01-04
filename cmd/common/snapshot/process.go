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

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	columnssort "github.com/inspektor-gadget/inspektor-gadget/pkg/columns/sort"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
)

const OutputModeProcessTree = "tree"

type ProcessFlags struct {
	showThreads    bool
	showParentsPID bool
}

type ProcessParser struct {
	commonutils.GadgetParser[types.Event]

	flags        *ProcessFlags
	outputConfig *commonutils.OutputConfig
}

func newProcessParser(outputConfig *commonutils.OutputConfig, flags *ProcessFlags, cols *columns.Columns[types.Event], options ...commonutils.Option) (SnapshotParser[types.Event], error) {
	if flags.showThreads {
		col, _ := cols.GetColumn("tid")
		col.Visible = true
	}

	if flags.showParentsPID {
		col, _ := cols.GetColumn("ppid")
		col.Visible = true
	}

	gadgetParser, err := commonutils.NewGadgetParser(outputConfig, cols, options...)
	if err != nil {
		return nil, commonutils.WrapInErrParserCreate(err)
	}

	return &ProcessParser{
		flags:        flags,
		GadgetParser: *gadgetParser,
		outputConfig: outputConfig,
	}, nil
}

func NewProcessParserWithK8sInfo(outputConfig *commonutils.OutputConfig, flags *ProcessFlags) (SnapshotParser[types.Event], error) {
	return newProcessParser(outputConfig, flags, types.GetColumns(), commonutils.WithMetadataTag(commonutils.KubernetesTag))
}

func NewProcessParserWithRuntimeInfo(outputConfig *commonutils.OutputConfig, flags *ProcessFlags) (SnapshotParser[types.Event], error) {
	return newProcessParser(outputConfig, flags, types.GetColumns(), commonutils.WithMetadataTag(commonutils.ContainerRuntimeTag))
}

func (p *ProcessParser) GetOutputConfig() *commonutils.OutputConfig {
	return p.outputConfig
}

func (p *ProcessParser) SortEvents(allProcesses *[]*types.Event) {
	if !p.flags.showThreads {
		allProcessesTrimmed := []*types.Event{}
		for _, i := range *allProcesses {
			if i.Tid == i.Pid {
				allProcessesTrimmed = append(allProcessesTrimmed, i)
			}
		}
		*allProcesses = allProcessesTrimmed
	}

	columnssort.SortEntries(types.GetColumns().GetColumnMap(), *allProcesses,
		[]string{"node", "namespace", "pod", "container", "cmd", "tgid", "pid"})
}

func (p *ProcessParser) UseCustomPrinter() bool {
	if p.outputConfig.OutputMode == OutputModeProcessTree {
		return true
	}
	return false
}

func (p *ProcessParser) CustomPrintEvents(processes []*types.Event) error {
	return types.PrintTree(processes)
}

func NewProcessCmd(runCmd func(*cobra.Command, []string) error, flags *ProcessFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "process",
		Short: "Gather information about running processes",
		RunE:  runCmd,
	}

	cmd.PersistentFlags().BoolVarP(
		&flags.showThreads,
		"threads",
		"t",
		false,
		"Show all threads",
	)
	cmd.PersistentFlags().BoolVarP(
		&flags.showParentsPID,
		"parent-pids",
		"",
		false,
		"Show parents PID",
	)

	return cmd
}
