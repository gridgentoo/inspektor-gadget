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
	"github.com/kinvolk/inspektor-gadget/pkg/columns"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event
	Command   string `json:"comm" column:"comm,maxWidth:16"`
	Pid       int    `json:"pid" column:"pid,minWidth:7"`
	Tid       int    `json:"tid" column:"tid,minWidth:7,hide"`
	MountNsID uint64 `json:"mntns" column:"mntns,width:12,hide"`
}

func (e Event) GetBaseEvent() eventtypes.Event {
	return e.Event
}

func GetColumns() *columns.Columns[Event] {
	return columns.MustCreateColumns[Event]()
}

func GetSortingOrder() []string {
	return []string{
		"node",
		"namespace",
		"pod",
		"container",
		"comm",
		"pid",
		"tid",
	}
}
