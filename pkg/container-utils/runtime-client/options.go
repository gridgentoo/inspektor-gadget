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

package runtimeclient

import (
	log "github.com/sirupsen/logrus"
)

type ContainerOptions struct {
	state   string
	details bool
}

// State returns the state filter option.
func (opts *ContainerOptions) State() string {
	return opts.state
}

// IsStateFilterSet returns true if the state filter option is set.
func (opts *ContainerOptions) IsStateFilterSet() bool {
	return opts.state != ""
}

func (opts *ContainerOptions) MatchRequestedState(state string) bool {
	if opts.IsStateFilterSet() && opts.state != state {
		log.Debugf("RuntimeClient: container state %q does not match requested state %q", state, opts.state)
		return false
	}
	return true
}

func (opts *ContainerOptions) MustIncludeDetails() bool {
	return opts.details
}

type Option func(*ContainerOptions)

func defaultOptions() *ContainerOptions {
	return &ContainerOptions{
		state:   "",
		details: false,
	}
}

func ParseOptions(options ...Option) *ContainerOptions {
	opts := defaultOptions()
	for _, o := range options {
		o(opts)
	}
	return opts
}

func WithState(state string) Option {
	return func(opts *ContainerOptions) {
		opts.state = state
	}
}

func WithDetails() Option {
	return func(opts *ContainerOptions) {
		opts.details = true
	}
}
