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

package types

import (
	"errors"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Key struct {
	eventtypes.CommonData
	Name string `json:"name,omitempty" column:"name"`
}

func (k Key) MarshalText() (text []byte, err error) {
	val := k.Node + "/" + k.Namespace + "/" + k.Pod + "/" + k.Container + "/" + k.Name
	return []byte(val), nil
}

func (k *Key) UnmarshalText(text []byte) error {
	str := string(text)
	parts := strings.Split(str, "/")
	if len(parts) != 5 {
		return errors.New("bad input")
	}

	k.Node = parts[0]
	k.Namespace = parts[1]
	k.Pod = parts[2]
	k.Container = parts[3]
	k.Name = parts[4]

	return nil
}

type Language struct {
	Executions *uint64 `json:"executions,omitempty" column:"executions"`
}

type Report struct {
	Languages map[Key]Language `json:"languages,omitempty" column:"languages"`
}

func GetColumns() *columns.Columns[Report] {
	return columns.MustCreateColumns[Report]()
}
