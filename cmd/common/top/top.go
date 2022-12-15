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

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type TopEvent interface {
	any

	// TODO: The Go compiler does not support accessing a struct field x.f where
	// x is of type parameter type even if all types in the type parameter's
	// type set have a field f. We may remove this restriction in Go 1.19. See
	// https://tip.golang.org/doc/go1.18#generics.
	GetBaseEvent() *eventtypes.Event
}

// TopParser defines the interface that every top-gadget parser has to
// implement.
type TopParser[Stats any] interface {
	// BuildColumnsHeader returns a header to be used when the user requests to
	// present the output in columns.
	BuildColumnsHeader() string
	TransformIntoColumns(*Stats) string

	// GetOutputConfig returns the output configuration.
	GetOutputConfig() *commonutils.OutputConfig
}

type CommonTopFlags struct {
	OutputInterval int
	MaxRows        int
	SortBy         string
	ParsedSortBy   []string
}

type TopGadget[Stats any] struct {
	Name           string
	CommonTopFlags *CommonTopFlags
	Parser         TopParser[Stats]
	ColMap         columns.ColumnMap[Stats]
}

func (g *TopGadget[Stats]) PrintHeader() {
	outputConfig := g.Parser.GetOutputConfig()
	if outputConfig.OutputMode == commonutils.OutputModeJSON {
		return
	}

	if term.IsTerminal(int(os.Stdout.Fd())) {
		commonutils.ClearScreen()
	} else {
		fmt.Println("")
	}

	fmt.Println(g.Parser.BuildColumnsHeader())
}

func (g *TopGadget[Stats]) PrintStats(stats []*Stats) {
	top.SortStats(stats, g.CommonTopFlags.ParsedSortBy, &g.ColMap)

	for idx, stat := range stats {
		if idx == g.CommonTopFlags.MaxRows {
			break
		}

		outputConfig := g.Parser.GetOutputConfig()
		switch outputConfig.OutputMode {
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

func NewCommonTopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "top",
		Short: "Gather, sort and periodically report events according to a given criteria",
	}
}
