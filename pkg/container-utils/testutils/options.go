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

package testutils

type Option func(*ContainerOptions)

type ContainerOptions struct {
	Name           string
	Image          string
	Command        string
	SeccompProfile string
	Wait           bool
	Logs           bool
	Removal        bool
}

func DefaultContainerOptions() *ContainerOptions {
	return &ContainerOptions{
		Name:    "test-container",
		Image:   "busybox",
		Command: "echo foo",
		Logs:    true,
		Wait:    true,
		Removal: true,
	}
}

func WithName(name string) Option {
	return func(opts *ContainerOptions) {
		opts.Name = name
	}
}

func WithImage(image string) Option {
	return func(opts *ContainerOptions) {
		opts.Image = image
	}
}

func WithCommand(cmd string) Option {
	return func(opts *ContainerOptions) {
		opts.Command = cmd
	}
}

func WithSeccompProfile(profile string) Option {
	return func(opts *ContainerOptions) {
		opts.SeccompProfile = profile
	}
}

func WithoutWait() Option {
	return func(opts *ContainerOptions) {
		opts.Wait = false
	}
}

func WithoutLogs() Option {
	return func(opts *ContainerOptions) {
		opts.Logs = false
	}
}

func WithoutRemoval() Option {
	return func(opts *ContainerOptions) {
		opts.Removal = false
	}
}
