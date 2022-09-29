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
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/pkg/columns"
	socketTypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
)

type SocketFlags struct {
	Extended bool
	Protocol string

	ParsedProtocol socketTypes.Proto
}

func GetSocketColumns(flags *SocketFlags) *columns.Columns[socketTypes.Event] {
	cols := socketTypes.GetColumns()

	if flags.Extended {
		inodeCol, ok := cols.GetColumn("inode")
		if !ok {
			panic(`making "inode" column visible`)
		}

		inodeCol.Visible = true
	}

	return cols
}

func NewSocketCmd(runCmd func(*cobra.Command, []string) error, flags *SocketFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "socket",
		Short: "Gather information about TCP and UDP sockets",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if flags.ParsedProtocol, err = socketTypes.ParseProtocol(flags.Protocol); err != nil {
				return err
			}

			return nil
		},
		RunE: runCmd,
	}

	var protocols []string
	for protocol := range socketTypes.ProtocolsMap {
		protocols = append(protocols, protocol)
	}

	cmd.PersistentFlags().StringVarP(
		&flags.Protocol,
		"proto",
		"",
		"all",
		fmt.Sprintf("Show only sockets using this protocol (%s)", strings.Join(protocols, ", ")),
	)
	cmd.PersistentFlags().BoolVarP(
		&flags.Extended,
		"extend",
		"e",
		false,
		"Display other/more information (like socket inode)",
	)

	return cmd
}
