// Copyright 2022 The Inspektor Gadget authors
// Copyright (c) 2016 GitHub, Inc.
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

package gadgets

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/xyproto/ainur"
)

// Implementation ported from https://github.com/iovisor/bcc/blob/v0.25.0/src/cc/bcc_proc.c#L4999

var languages = [...]string{"java", "node", "php", "python", "ruby"}

var LanguageNotFound = errors.New("determining process language")

// getProcessInterpretedLanguage returns the programming language of a
// pid if this is a interpreted language. Current logic is able to
// detect java, node, php, python and ruby. This logic first checks if
// the path of the binary contains any of the expected langauges, if yes
// it returns that. Otherwise it checks in the memory mappings for
// traces of those languages.
func getProcessInterpretedLanguage(pid int) (string, bool, error) {
	exe := fmt.Sprintf("/proc/%d/exe", pid)
	realPath, err := os.Readlink(exe)
	if err != nil {
		return "", false, err
	}

	// TODO: if the binary contains any of the languages names then
	// this will assume that's the language used for it. For
	// instance, if falsely detects that "calico-node" uses "node".
	for _, language := range languages {
		if strings.Contains(realPath, language) {
			return language, false, nil
		}
	}

	maps := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(maps)
	if err != nil {
		return "", false, err
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
				return language, false, nil
			}

			if strings.Contains(mapname, "libc-") || strings.Contains(mapname, "libc.") {
				libc = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", false, err
	}

	if libc {
		return "", true, nil
	}

	return "", false, LanguageNotFound
}

// GetProcessLanguage returns the programming language of a pid. It
// first tries to check for interpreted languages, then it fallbacks and
// looks for compiler information in the binary.
func GetProcessLanguage(pid int) (string, error) {
	// If we get it's a interpreted language, return it
	language, libc, err := getProcessInterpretedLanguage(pid)
	if err == nil {
		if libc {
			return language, nil
		}
	} else if !errors.Is(err, LanguageNotFound) {
		return language, nil
	}

	// Otherwise, look for compiler information
	var parts []string

	compiler, err := ainur.Examine(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		goto outErr
	}

	if compiler == "unkown" {
		goto outErr
	}

	// ainur returns "compiler version"
	parts = strings.Split(compiler, " ")
	if len(parts) != 2 {
		goto outErr
	}

	language = strings.ToLower(parts[0])
	// TODO: is this logic right? (What about other compilers?)
	if language == "gcc" {
		language = "c"
	}

outErr:
	if language != "" {
		return language, nil
	}

	if libc {
		return "c", nil
	}

	return "", LanguageNotFound
}
