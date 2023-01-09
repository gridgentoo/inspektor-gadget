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

package trace

import (
	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"

	commontrace "github.com/inspektor-gadget/inspektor-gadget/cmd/common/trace"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets/trace"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	signalTracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/tracer"
	signalTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/types"
)

func newSignalCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var flags commontrace.SignalFlags

	runCmd := func(*cobra.Command, []string) error {
		parser, err := commonutils.NewGadgetParserWithRuntimeInfo(
			&commonFlags.OutputConfig,
			signalTypes.GetColumns(),
		)
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		signalGadget := &TraceGadget[signalTypes.Event]{
			commonFlags: &commonFlags,
			parser:      parser,
			createAndRunTracer: func(mountnsmap *ebpf.Map, enricher gadgets.DataEnricher, eventCallback func(*signalTypes.Event)) (trace.Tracer, error) {
				return signalTracer.NewTracer(&signalTracer.Config{
					MountnsMap:   mountnsmap,
					TargetSignal: flags.Sig,
					TargetPid:    int32(flags.Pid),
					FailedOnly:   flags.Failed,
					KillOnly:     flags.KillOnly,
				}, enricher, eventCallback)
			},
		}

		return signalGadget.Run()
	}

	cmd := commontrace.NewSignalCmd(runCmd, &flags)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
