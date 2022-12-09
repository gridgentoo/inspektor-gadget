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

package docker

import (
	"context"
	"fmt"
	"testing"
	"time"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
)

func TestFilterByContainerName(t *testing.T) {
	t.Parallel()

	cn := "test-filtered-container"
	listContainersCmd := &Command{
		Name:     "RunFilterByContainerName",
		Cmd:      fmt.Sprintf("./local-gadget list-containers -o json --runtimes=docker --containername=%s", cn),
		SkipLogs: true,
		ExpectedOutputFn: func(output string) error {
			expectedContainer := &containercollection.Container{
				Podname:   cn,
				Name:      cn,
				Namespace: "default",
				Runtime:   "docker",
			}

			normalize := func(c *containercollection.Container) {
				c.ID = ""
				c.Pid = 0
				c.OciConfig = nil
				c.Bundle = ""
				c.Mntns = 0
				c.Netns = 0
				c.CgroupPath = ""
				c.CgroupID = 0
				c.CgroupV1 = ""
				c.CgroupV2 = ""
				c.Labels = nil
				c.PodUID = ""
			}

			return ExpectAllInArrayToMatch(output, normalize, expectedContainer)
		},
	}

	// start a long-running container
	ctx := context.Background()
	testutils.RunDockerContainer(ctx, t,
		testutils.WithName(cn),
		testutils.WithoutWait(),
		testutils.WithoutRemoval(),
		testutils.WithCommand("sleep inf"),
	)
	defer testutils.RemoveDockerContainer(ctx, t, cn)

	listContainersCmd.Run(t)
}

func TestWatchContainers(t *testing.T) {
	t.Parallel()

	cn := "test-watched-container"
	watchContainersCmd := &Command{
		Name:         "RunWatchContainers",
		Cmd:          "./local-gadget list-containers -o json --watch --runtimes=docker",
		StartAndStop: true,
		SkipLogs:     true,
		ExpectedOutputFn: func(output string) error {
			expectedContainer := &containercollection.Container{
				Podname:   cn,
				Name:      cn,
				Namespace: "default",
				Runtime:   "docker",
			}

			normalize := func(c *containercollection.Container) {
				c.ID = ""
				c.Pid = 0
				c.OciConfig = nil
				c.Bundle = ""
				c.Mntns = 0
				c.Netns = 0
				c.CgroupPath = ""
				c.CgroupID = 0
				c.CgroupV1 = ""
				c.CgroupV2 = ""
				c.Labels = nil
				c.PodUID = ""
			}

			return ExpectEntriesToMatch(output, normalize, expectedContainer)
		},
	}

	// start a long-running command i.e with StartAndStop
	watchContainersCmd.Run(t)
	defer watchContainersCmd.Stop(t)
	time.Sleep(2 * time.Second)

	testutils.RunDockerContainer(context.Background(), t,
		testutils.WithName(cn),
	)
}
