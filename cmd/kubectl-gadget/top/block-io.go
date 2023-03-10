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
	"github.com/spf13/cobra"

	commontop "github.com/inspektor-gadget/inspektor-gadget/cmd/common/top"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/block-io/types"
)

func newBlockIOCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var flags commontop.CommonTopFlags

	cols := types.GetColumns()

	cmd := commontop.NewBlockIOCmd(func(cmd *cobra.Command, args []string) error {
		parser, err := commonutils.NewGadgetParserWithK8sInfo(&commonFlags.OutputConfig, cols)
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		gadget := &TopGadget[types.Stats]{
			TopGadget: commontop.TopGadget[types.Stats]{
				CommonTopFlags: &flags,
				OutputConfig:   &commonFlags.OutputConfig,
				Parser:         parser,
				ColMap:         cols.ColumnMap,
			},
			name:        "biotop",
			commonFlags: &commonFlags,
			nodeStats:   make(map[string][]*types.Stats),
		}

		return gadget.Run(args)
	})

	commontop.AddCommonTopFlags(cmd, &flags, cols.ColumnMap, types.SortByDefault)
	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
