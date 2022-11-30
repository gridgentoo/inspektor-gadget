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
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"

	commonprofile "github.com/inspektor-gadget/inspektor-gadget/cmd/common/profile"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets/profile"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	localgadgetmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/local-gadget-manager"
)

// ProfileGadget represents a gadget belonging to the profile category.
type ProfileGadget[Report any] struct {
	commonFlags   *utils.CommonFlags
	inProgressMsg string
	parser        commonprofile.ProfileParser

	Timeout            int
	createAndRunTracer func(*ebpf.Map, gadgets.DataEnricher) (profile.Tracer, error)
}

// Run runs a ProfileGadget and prints the output after parsing it using the
// ProfileParser's methods.
func (g *ProfileGadget[Report]) Run() error {
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

	gadgetTracer, err := g.createAndRunTracer(mountnsmap, &localGadgetManager.ContainerCollection)
	if err != nil {
		return commonutils.WrapInErrGadgetTracerCreateAndRun(err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	if g.Timeout != 0 {
		go func() {
			time.Sleep(time.Duration(g.Timeout) * time.Second)
			c <- os.Interrupt
		}()
	}

	if g.commonFlags.OutputMode != commonutils.OutputModeJSON {
		if g.Timeout != 0 {
			fmt.Printf(g.inProgressMsg + "...")
		} else {
			fmt.Printf("%s... Hit Ctrl-C to end.", g.inProgressMsg)
		}
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	result, err := gadgetTracer.Stop()
	if err != nil {
		return err
	}

	// Trick to have ^C on the same line than above message, so the gadget
	// output begins on a "clean" line.
	fmt.Println()

	err = g.parser.DisplayResultsCallback("", []string{result})
	if err != nil {
		return err
	}

	return nil
}

func NewProfileCmd() *cobra.Command {
	cmd := commonprofile.NewCommonProfileCmd()

	cmd.AddCommand(newBlockIOCmd())
	cmd.AddCommand(newCPUCmd())

	return cmd
}
