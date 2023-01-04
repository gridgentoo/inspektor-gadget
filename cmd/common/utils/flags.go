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

package utils

import (
	"errors"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
)

const (
	OutputModeColumns       = "columns"
	OutputModeJSON          = "json"
	OutputModeCustomColumns = "custom-columns"
)

var SupportedOutputModes = []string{OutputModeColumns, OutputModeJSON, OutputModeCustomColumns}

// OutputConfig contains the flags that describes how to print the gadget's output
type OutputConfig struct {
	// OutputMode specifies the format output should be printed
	OutputMode string

	// List of columns to print (only meaningful when OutputMode is "columns=...")
	CustomColumns []string

	// Verbose prints additional information
	Verbose bool

	// customOutputMode is the name of the custom output mode.
	customOutputMode string
}

type OutputConfigOption func(*OutputConfig)

func WithCustomOutputMode(m string) OutputConfigOption {
	return func(outputConfig *OutputConfig) {
		outputConfig.customOutputMode = m
	}
}

func AddOutputFlags(command *cobra.Command, outputConfig *OutputConfig, options ...OutputConfigOption) {
	for _, option := range options {
		option(outputConfig)
	}

	supportedOutputModes := SupportedOutputModes
	if len(outputConfig.customOutputMode) != 0 {
		supportedOutputModes = append(SupportedOutputModes, outputConfig.customOutputMode)
	}

	command.PersistentFlags().StringVarP(
		&outputConfig.OutputMode,
		"output",
		"o",
		OutputModeColumns,
		fmt.Sprintf("Output format (%s).", strings.Join(supportedOutputModes, ", ")),
	)

	command.PersistentFlags().BoolVarP(
		&outputConfig.Verbose,
		"verbose", "v",
		false,
		"Print debug information",
	)
}

func (config *OutputConfig) ParseOutputConfig() error {
	if config.Verbose {
		log.StandardLogger().SetLevel(log.DebugLevel)
	}

	if len(config.customOutputMode) != 0 && config.OutputMode == config.customOutputMode {
		return nil
	}

	switch {
	case config.OutputMode == OutputModeColumns:
		fallthrough
	case config.OutputMode == OutputModeJSON:
		return nil
	case strings.HasPrefix(config.OutputMode, OutputModeCustomColumns):
		parts := strings.Split(config.OutputMode, "=")
		if len(parts) != 2 {
			return WrapInErrInvalidArg(OutputModeCustomColumns,
				errors.New("expects a comma separated list of columns to use"))
		}

		cols := strings.Split(strings.ToLower(parts[1]), ",")
		for _, col := range cols {
			if len(col) == 0 {
				return WrapInErrInvalidArg(OutputModeCustomColumns,
					errors.New("column can't be empty"))
			}
		}

		config.CustomColumns = cols
		config.OutputMode = OutputModeCustomColumns
		return nil
	default:
		return WrapInErrOutputModeNotSupported(config.OutputMode)
	}
}

type RuntimesSocketPathConfig struct {
	Docker     string
	Containerd string
	Crio       string
}

func AddRuntimesSocketPathFlags(command *cobra.Command, config *RuntimesSocketPathConfig) {
	command.PersistentFlags().StringVarP(
		&config.Docker,
		"docker-socketpath", "",
		runtimeclient.DockerDefaultSocketPath,
		"Docker Engine API Unix socket path",
	)

	command.PersistentFlags().StringVarP(
		&config.Containerd,
		"containerd-socketpath", "",
		runtimeclient.ContainerdDefaultSocketPath,
		"containerd CRI Unix socket path",
	)

	command.PersistentFlags().StringVarP(
		&config.Crio,
		"crio-socketpath", "",
		runtimeclient.CrioDefaultSocketPath,
		"CRI-O CRI Unix socket path",
	)
}
