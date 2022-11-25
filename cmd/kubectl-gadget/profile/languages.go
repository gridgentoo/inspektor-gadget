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

package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/languages/types"
)

type LanguagesParser struct {
	commonutils.GadgetParser[types.Report]
	commonutils.OutputConfig
	cpuFlags *CPUFlags
}

func newLanguagesCmd() *cobra.Command {
	var commonFlags utils.CommonFlags

	cmd := &cobra.Command{
		Use:          "languages",
		Short:        "Show languages used in the cluster",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			parser, err := commonutils.NewGadgetParserWithK8sInfo(&commonFlags.OutputConfig, types.GetColumns())
			if err != nil {
				return commonutils.WrapInErrParserCreate(err)
			}

			languagesGadget := &ProfileGadget{
				gadgetName:    "profile-languages",
				commonFlags:   &commonFlags,
				inProgressMsg: "Capturing data",
				parser: &LanguagesParser{
					GadgetParser: *parser,
					OutputConfig: commonFlags.OutputConfig,
				},
			}

			return languagesGadget.Run()
		},
	}

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}

func (p *LanguagesParser) DisplayResultsCallback(traceOutputMode string, results []string) error {
	if p.OutputConfig.OutputMode != commonutils.OutputModeJSON {
		//mt.Println(p.BuildColumnsHeader())
		fmt.Printf("%-20s %-20s %-20s %-20s %-15s %-5s\n",
			"node",
			"namespace",
			"pod",
			"container",
			"language",
			"execs",
		)
	}

	for _, r := range results {
		var report types.Report
		if err := json.Unmarshal([]byte(r), &report); err != nil {
			return commonutils.WrapInErrUnmarshalOutput(err, r)
		}

		fmt.Println(p.TransformReport(&report))
	}

	return nil
}

func (p *LanguagesParser) TransformReport(report *types.Report) string {
	switch p.OutputConfig.OutputMode {
	case commonutils.OutputModeJSON:
		b, err := json.Marshal(report)
		if err != nil {
			fmt.Fprint(os.Stderr, fmt.Sprint(commonutils.WrapInErrMarshalOutput(err)))
			return ""
		}

		return string(b)
	case commonutils.OutputModeColumns:
		fallthrough
	case commonutils.OutputModeCustomColumns:
		var ret strings.Builder
		//return p.TransformIntoColumns(report)
		for key, val := range report.Languages {
			ret.WriteString(fmt.Sprintf("%-20s %-20s %-20s %-20s %-15s %-5d\n",
				key.Node,
				key.Namespace,
				key.Pod,
				key.Container,
				key.Name,
				*val.Executions,
			))
		}

		return ret.String()
	}
	return ""
}
