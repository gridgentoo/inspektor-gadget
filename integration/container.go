// Copyright 2023 The Inspektor Gadget authors
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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
)

func NewContainer(runtime, name, cmd string, opts ...containerOption) TestStep {
	switch runtime {
	case "docker":
		return &dockerContainer{
			name:    name,
			cmd:     cmd,
			options: opts,
		}
	}
	return nil
}

func NewStartAndStopContainer(runtime, name, cmd string, opts ...containerOption) TestStep {
	switch runtime {
	case "docker":
		return &dockerContainer{
			name:         name,
			cmd:          cmd,
			options:      opts,
			startAndStop: true,
		}
	}
	return nil
}

// containerOption wraps testutils.Option to allow certain values only
type containerOption struct {
	opt testutils.Option
}

func optionsFromContainerOptions(containerOptions []containerOption) []testutils.Option {
	var opts []testutils.Option
	for _, co := range containerOptions {
		opts = append(opts, co.opt)
	}
	return opts
}

func WithContainerImage(image string) containerOption {
	return containerOption{opt: testutils.WithImage(image)}
}

func WithContainerSeccompProfile(profile string) containerOption {
	return containerOption{opt: testutils.WithSeccompProfile(profile)}
}
