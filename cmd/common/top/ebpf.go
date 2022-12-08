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
	"fmt"

	"github.com/spf13/cobra"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"
)

type EbpfParser struct {
	commonutils.GadgetParser[types.Stats]
	outputConfig *commonutils.OutputConfig
}

func newEbpfParser(outputConfig *commonutils.OutputConfig, flags *CommonTopFlags, cols *columns.Columns[types.Stats], options ...commonutils.Option) (TopParser[types.Stats], error) {
	gadgetParser, err := commonutils.NewGadgetParser(outputConfig, cols, options...)
	if err != nil {
		return nil, commonutils.WrapInErrParserCreate(err)
	}

	return &EbpfParser{
		GadgetParser: *gadgetParser,
		outputConfig: outputConfig,
	}, nil
}

func NewEbpfParserWithK8sInfo(outputConfig *commonutils.OutputConfig, flags *CommonTopFlags) (TopParser[types.Stats], error) {
	return newEbpfParser(outputConfig, flags, types.GetColumns(), commonutils.WithMetadataTag(commonutils.KubernetesTag))
}

func NewEbpfParserWithRuntimeInfo(outputConfig *commonutils.OutputConfig, flags *CommonTopFlags) (TopParser[types.Stats], error) {
	return newEbpfParser(outputConfig, flags, types.GetColumns(), commonutils.WithMetadataTag(commonutils.ContainerRuntimeTag))
}

func (s *EbpfParser) GetOutputConfig() *commonutils.OutputConfig {
	return s.outputConfig
}

func NewEbpfCmd(runCmd func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   fmt.Sprintf("ebpf [interval=%d]", top.IntervalDefault),
		Short: "Periodically report ebpf runtime stats",
		RunE:  runCmd,
	}

	return cmd
}
