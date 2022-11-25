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

package tracer

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/xyproto/ainur"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/languages/types"
	execTracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	execTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
)

type Config struct {
	MountnsMap *ebpf.Map
}

type Tracer struct {
	enricher   gadgets.DataEnricher
	execTracer *execTracer.Tracer
	config     *Config

	report *types.Report
}

var languages = [...]string{"java", "node", "php", "python", "ruby"}

func getInterpretedLanguage(pid int) (string, error) {
	exe := fmt.Sprintf("/proc/%d/exe", pid)
	realPath, err := os.Readlink(exe)
	if err != nil {
		return "", err
	}

	for _, language := range languages {
		if strings.Contains(realPath, language) {
			return language, nil
		}
	}

	maps := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(maps)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	libc := false

	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Fields(line)
		if len(fields) != 6 {
			continue
		}

		mapname := fields[5]
		for _, language := range languages {
			if strings.Contains(mapname, fmt.Sprintf("/lib%s", language)) {
				return language, nil
			}

			if strings.Contains(mapname, "libc-") || strings.Contains(mapname, "libc.") {
				libc = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	if libc {
		return "c", nil
	}

	return "", errors.New("failed to determine language")
}

func getLanguage(pid int) (string, error) {
	// If we get it's a interpreted language, return it
	language, err := getInterpretedLanguage(pid)
	if err == nil {
		return language, nil
	}

	// Otherwise, look for compiler information
	compiler, err := ainur.Examine(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", err
	}

	if compiler == "unkown" {
		return "", errors.New("compiler is unknown")
	}

	parts := strings.Split(compiler, " ")
	if len(parts) != 2 {
		return "", errors.New("bad compiler found")
	}

	language = strings.ToLower(parts[0])
	// TODO: is this logic right? (What about other compilers?)
	if language == "gcc" {
		language = "c"
	}

	return language, nil
}

func NewTracer(config *Config, enricher gadgets.DataEnricher) (*Tracer, error) {
	if enricher == nil {
		return nil, errors.New("enricher is mandatory for this gadget")
	}

	report := &types.Report{
		Languages: make(map[types.Key]types.Language),
	}

	eventCallback := func(event execTypes.Event) {
		enricher.Enrich(&event.CommonData, event.MountNsID)

		languageStr, err := getLanguage(int(event.Pid))
		if err != nil {
			return
		}

		key := types.Key{
			CommonData: event.CommonData,
			Name:       languageStr,
		}

		// TODO: what went wrong in this case?
		if key.Name == "" {
			return
		}

		language, ok := report.Languages[key]
		if !ok {
			one := uint64(1)
			report.Languages[key] = types.Language{Executions: &one}
			return
		}

		*language.Executions++
	}

	eConfig := &execTracer.Config{MountnsMap: config.MountnsMap}
	eTracer, err := execTracer.NewTracer(eConfig, enricher, eventCallback)
	if err != nil {
		return nil, err
	}

	t := &Tracer{
		enricher:   enricher,
		execTracer: eTracer,
		config:     config,
		report:     report,
	}

	return t, nil
}

func (t *Tracer) Stop() (*types.Report, error) {
	if t.execTracer != nil {
		t.execTracer.Stop()
	}

	return t.report, nil
}
