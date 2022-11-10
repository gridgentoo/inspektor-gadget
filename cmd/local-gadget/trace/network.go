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
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	commontrace "github.com/inspektor-gadget/inspektor-gadget/cmd/common/trace"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	networkTracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/tracer"
	networkTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	localgadgetmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/local-gadget-manager"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func newNetworkCmd() *cobra.Command {
	var commonFlags utils.CommonFlags

	// The network gadget works in a different way than most gadgets: It
	// attaches a new eBPF program to each container when it's created instead
	// of using an eBPF map with the mount namespaces IDs to filter the events.
	// For this reason we can't use the TraceGadget implementation here.
	runCmd := func(*cobra.Command, []string) error {
		localGadgetManager, err := localgadgetmanager.NewManager(commonFlags.RuntimeConfigs)
		if err != nil {
			return commonutils.WrapInErrManagerInit(err)
		}
		defer localGadgetManager.Close()

		// local-gadget is designed to trace containers, hence enable this column
		cols := networkTypes.GetColumns()
		col, _ := cols.GetColumn("container")
		col.Visible = true

		parser, err := commonutils.NewGadgetParserWithRuntimeInfo(&commonFlags.OutputConfig, cols)
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		// This callback is used by the ConnectionToContainerCollection to
		// notify when containers are attached and detached, or any error during
		// that operations. The actual events generated by the tracer will be
		// retrieved using the Pop() method.
		eventCallback := func(container *containercollection.Container, event networkTypes.Event) {
			// Enrich notifications with data from container
			event.Namespace = container.Namespace
			event.Pod = container.Podname
			event.Container = container.Name

			baseEvent := event.GetBaseEvent()
			if baseEvent.Type == eventtypes.NORMAL {
				fmt.Fprintf(os.Stderr, "Warning: unexpected event: %v", event)
				return
			}

			commonutils.HandleSpecialEvent(baseEvent, commonFlags.Verbose)
		}

		tracer, err := networkTracer.NewTracer(&localGadgetManager.ContainerCollection)
		if err != nil {
			return fmt.Errorf("creating tracer: %w", err)
		}
		defer tracer.Close()

		if commonFlags.OutputMode != commonutils.OutputModeJSON {
			fmt.Println(parser.BuildColumnsHeader())
		}

		selector := containercollection.ContainerSelector{
			Name: commonFlags.Containername,
		}

		config := &networktracer.ConnectToContainerCollectionConfig[networkTypes.Event]{
			Tracer:        tracer,
			Resolver:      &localGadgetManager.ContainerCollection,
			Selector:      selector,
			EventCallback: eventCallback,
			Base:          networkTypes.Base,
		}
		conn, err := networktracer.ConnectToContainerCollection(config)
		if err != nil {
			return fmt.Errorf("connecting tracer to container collection: %w", err)
		}
		defer conn.Close()

		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

		ticker := time.NewTicker(time.Second)

		for {
			select {
			case <-stop:
				ticker.Stop()
				return nil
			case <-ticker.C:
				if err := printEvents(localGadgetManager, parser, &commonFlags, tracer); err != nil {
					fmt.Fprintf(os.Stderr, "Error: printing events: %s", err)
				}
			}
		}
	}

	cmd := commontrace.NewNetworkCmd(runCmd)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}

func printEvents(
	localGadgetManager *localgadgetmanager.LocalGadgetManager,
	parser *commonutils.GadgetParser[networkTypes.Event],
	commonFlags *utils.CommonFlags,
	tracer *networkTracer.Tracer,
) error {
	newEvents, err := tracer.Pop()
	if err != nil {
		return fmt.Errorf("getting new events: %w", err)
	}

	for _, event := range newEvents {
		// for now, ignore events on the host netns
		if event.Container == "" {
			continue
		}

		switch commonFlags.OutputMode {
		case commonutils.OutputModeJSON:
			b, err := json.Marshal(event)
			if err != nil {
				return commonutils.WrapInErrMarshalOutput(err)
			}

			fmt.Println(string(b))
		case commonutils.OutputModeColumns:
			fallthrough
		case commonutils.OutputModeCustomColumns:
			fmt.Println(parser.TransformIntoColumns(event))
		}
	}

	return nil
}
