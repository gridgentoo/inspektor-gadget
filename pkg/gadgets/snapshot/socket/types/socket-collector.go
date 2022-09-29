// Copyright 2021 The Inspektor Gadget authors
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
	"fmt"
	"strings"

	"github.com/kinvolk/inspektor-gadget/pkg/columns"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type Proto int

const (
	INVALID Proto = iota
	ALL
	TCP
	UDP
)

var ProtocolsMap = map[string]Proto{
	"all": ALL,
	"tcp": TCP,
	"udp": UDP,
}

type Event struct {
	eventtypes.Event

	Protocol      string `json:"protocol" column:"proto,width:5,fixed,order:500"` // 500 = Ensure it's greater than all columns in eventtypes.Event
	LocalAddress  string `json:"localAddress"`
	LocalPort     uint16 `json:"localPort"`
	RemoteAddress string `json:"remoteAddress"`
	RemotePort    uint16 `json:"remotePort"`
	Status        string `json:"status" column:"status,minWidth:6,maxWidth:12,order:503"`
	InodeNumber   uint64 `json:"inodeNumber" column:"inode,width:12,order:504,hide"`
}

func ParseProtocol(protocol string) (Proto, error) {
	if r, ok := ProtocolsMap[strings.ToLower(protocol)]; ok {
		return r, nil
	}

	return INVALID, fmt.Errorf("%q is not a valid protocol value", protocol)
}

func (e Event) GetBaseEvent() eventtypes.Event {
	return e.Event
}

func GetColumns() *columns.Columns[Event] {
	cols := columns.MustCreateColumns[Event]()

	cols.MustAddColumn(columns.Column[Event]{
		Name: "local",
		Extractor: func(e *Event) string {
			return fmt.Sprintf("%s:%d", e.LocalAddress, e.LocalPort)
		},
		MaxWidth: 20, // len("XXX.XXX.XXX.XXX") + maxChars(uint16)
		Order:    501,
		Visible:  true,
	})

	cols.MustAddColumn(columns.Column[Event]{
		Name: "remote",
		Extractor: func(e *Event) string {
			return fmt.Sprintf("%s:%d", e.RemoteAddress, e.RemotePort)
		},
		MaxWidth: 20, // len("XXX.XXX.XXX.XXX") + maxChars(uint16)
		Order:    502,
		Visible:  true,
	})

	// Container information is not yet available for this gadget
	cCol, ok := cols.GetColumn("container")
	if !ok {
		panic(`disabling "container" column for snapshot socket gadget`)
	}
	cCol.Visible = false

	rcCol, ok := cols.GetColumn("runtimeContainerName")
	if !ok {
		panic(`disabling "runtimeContainerName" column for snapshot socket gadget`)
	}
	rcCol.Visible = false

	return cols
}

func GetSortingOrder() []string {
	return []string{
		"node",
		"namespace",
		"pod",
		"container",
		"protocol",
		"status",
		"localaddress",
		"remoteaddress",
		"localport",
		"remoteport",
		"inode",
	}
}
