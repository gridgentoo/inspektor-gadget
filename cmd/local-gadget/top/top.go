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

package top

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"

	commontop "github.com/inspektor-gadget/inspektor-gadget/cmd/common/top"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/sort"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets/trace"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	localgadgetmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/local-gadget-manager"
)

// TopLocalGadget represents a gadget belonging to the top category.
type TopLocalGadget[Stats any] struct {
	commontop.TopGadget[Stats]

	commonFlags        *utils.CommonFlags
	stats              []*Stats
	createAndRunTracer func(*ebpf.Map, gadgets.DataEnricher, func(*top.Event[Stats])) (trace.Tracer, error)
}

func addCommonTopFlags[Stats any](
	command *cobra.Command,
	commonTopFlags *commontop.CommonTopFlags,
	commonFlags *utils.CommonFlags,
	colMap columns.ColumnMap[Stats],
	sortBySliceDefault []string,
) {
	command.Flags().IntVarP(&commonTopFlags.MaxRows, "max-rows", "m", top.MaxRowsDefault, "Maximum rows to print")
	validCols, _ := sort.FilterSortableColumns(colMap, colMap.GetColumnNames())
	command.Flags().StringVarP(
		&commonTopFlags.SortBy, "sort",
		"",
		strings.Join(sortBySliceDefault, ","), fmt.Sprintf("Sort by columns. Join multiple columns with ','. Prefix a column with '-' to sort in descending order. Available columns: (%s)", strings.Join(validCols, ", ")))
	utils.AddCommonFlags(command, commonFlags)
}

// Run runs a TopGadget and prints the output after parsing it using the
// TopParser's methods.
func (g *TopLocalGadget[Stats]) Run(args []string) error {
	localGadgetManager, err := localgadgetmanager.NewManager(g.commonFlags.RuntimeConfigs)
	if err != nil {
		return commonutils.WrapInErrManagerInit(err)
	}
	defer localGadgetManager.Close()

	// TODO: Improve filtering, see further details in
	// https://github.com/inspektor-gadget/inspektor-gadget/issues/644.
	containerSelector := containercollection.ContainerSelector{
		Name: g.commonFlags.Containername,
	}

	// Create mount namespace map to filter by containers
	mountnsmap, err := localGadgetManager.CreateMountNsMap(containerSelector)
	if err != nil {
		return commonutils.WrapInErrManagerCreateMountNsMap(err)
	}
	defer localGadgetManager.RemoveMountNsMap()

	if len(args) == 1 {
		g.CommonTopFlags.OutputInterval, err = strconv.Atoi(args[0])
		if err != nil {
			return commonutils.WrapInErrInvalidArg("<interval>", fmt.Errorf("%q is not a valid value", args[0]))
		}
	} else {
		g.CommonTopFlags.OutputInterval = top.IntervalDefault
	}

	sortByColumns := strings.Split(g.CommonTopFlags.SortBy, ",")
	_, invalidCols := sort.FilterSortableColumns(g.ColMap, sortByColumns)

	if len(invalidCols) > 0 {
		return commonutils.WrapInErrInvalidArg("--sort", fmt.Errorf("invalid columns to sort by: %q", strings.Join(invalidCols, ",")))
	}
	g.CommonTopFlags.ParsedSortBy = sortByColumns

	g.StartPrintLoop()

	// Define a callback to be called each time there is an event.
	eventCallback := func(event *top.Event[Stats]) {
		g.stats = event.Stats
	}

	gadgetTracer, err := g.createAndRunTracer(mountnsmap, &localGadgetManager.ContainerCollection, eventCallback)
	if err != nil {
		return commonutils.WrapInErrGadgetTracerCreateAndRun(err)
	}
	defer gadgetTracer.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	return nil
}

func (g *TopLocalGadget[Stats]) PrintStats() {
	top.SortStats(g.stats, g.CommonTopFlags.ParsedSortBy, &g.ColMap)

	for idx, stat := range g.stats {
		if idx == g.CommonTopFlags.MaxRows {
			break
		}

		switch g.OutputConfig.OutputMode {
		case commonutils.OutputModeJSON:
			b, err := json.Marshal(stat)
			if err != nil {
				fmt.Fprint(os.Stderr, fmt.Sprint(commonutils.WrapInErrMarshalOutput(err)))
				continue
			}

			fmt.Println(string(b))
		case commonutils.OutputModeColumns:
			fallthrough
		case commonutils.OutputModeCustomColumns:
			fmt.Println(g.Parser.TransformIntoColumns(stat))
		}
	}
}

func NewTopCmd() *cobra.Command {
	cmd := commontop.NewCommonTopCmd()

	cmd.AddCommand(newBlockIOCmd())
	cmd.AddCommand(newEbpfCmd())
	cmd.AddCommand(newFileCmd())
	cmd.AddCommand(newTCPCmd())

	return cmd
}
