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

package integration

import (
	"context"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
)

// dockerContainer implements TestStep for docker containers
type dockerContainer struct {
	name         string
	cmd          string
	options      []containerOption
	cleanup      bool
	startAndStop bool
	started      bool
}

func (d *dockerContainer) Run(t *testing.T) {
	opts := append(optionsFromContainerOptions(d.options), testutils.WithName(d.name))
	testutils.RunDockerContainer(context.Background(), t, d.cmd, opts...)
}

func (d *dockerContainer) Start(t *testing.T) {
	if d.started {
		t.Logf("Warn(%s): trying to start already running container\n", d.name)
		return
	}
	opts := append(optionsFromContainerOptions(d.options), testutils.WithName(d.name), testutils.WithoutRemoval(), testutils.WithoutWait())
	testutils.RunDockerContainer(context.Background(), t, d.cmd, opts...)
	d.started = true
}

func (d *dockerContainer) Stop(t *testing.T) {
	testutils.RemoveDockerContainer(context.Background(), t, d.name)
	d.started = false
}

func (d *dockerContainer) IsCleanup() bool {
	return d.cleanup
}

func (d *dockerContainer) IsStartAndStop() bool {
	return d.startAndStop
}

func (d *dockerContainer) Running() bool {
	return d.started
}
