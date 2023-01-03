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
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event

	Command   string `json:"comm" column:"comm,template:comm"`
	Pid       int    `json:"pid" column:"pid,template:pid"`
	Tid       int    `json:"tid" column:"tid,template:pid,hide"`
	ParentPid int    `json:"ppid" column:"ppid,template:pid,hide"`
	MountNsID uint64 `json:"mntns" column:"mntns,template:ns"`
}

func GetColumns() *columns.Columns[Event] {
	return columns.MustCreateColumns[Event]()
}

type nodeProcess struct {
	event    *Event
	children []*nodeProcess
}

func createTree(processes []*Event) (*nodeProcess, error) {
	var root *nodeProcess

	nodes := make(map[int]*nodeProcess, len(processes))
	// Create a node for each processes.
	for _, process := range processes {
		nodes[process.Pid] = &nodeProcess{
			event:    process,
			children: make([]*nodeProcess, 0),
		}
	}

	// Link all nodes together.
	for _, node := range nodes {
		ppid := node.event.ParentPid
		if _, ok := nodes[ppid]; !ok {
			if root != nil {
				// Even if there are orphan process, they should have a parent process
				// as they will get the reaper as parent process:
				// https://elixir.bootlin.com/linux/v6.1.3/source/kernel/exit.c#L653
				// Note that above code is both called when calling exit() system call
				// and when receiving a fatal signal.
				return nil, fmt.Errorf("tree has two root processes: %v and %v\nthis should not happen please verify the correctness of the tree", root, node)
			}

			root = node

			continue
		}

		nodes[ppid].children = append(nodes[ppid].children, node)
	}

	if root == nil {
		return nil, fmt.Errorf("container has no root process")
	}

	return root, nil
}

func treeToString(node *nodeProcess) string {
	var builder strings.Builder
	treeToStringBuilder(node, &builder, 0)

	return builder.String()
}

func treeToStringBuilder(node *nodeProcess, builder *strings.Builder, depth int) {
	fmt.Fprintf(builder, "%s|-%s(%d)\n", strings.Repeat("\t", depth), node.event.Command, node.event.Pid)
	if len(node.children) == 0 {
		return
	}

	for _, child := range node.children {
		treeToStringBuilder(child, builder, depth+1)
	}
}

func WriteTree(output io.Writer, processes []*Event) error {
	containers := make(map[string][]*Event, len(processes))
	for _, process := range processes {
		_, ok := containers[process.Container]
		if !ok {
			containers[process.Container] = make([]*Event, 0)
		}
		containers[process.Container] = append(containers[process.Container], process)
	}

	for _, container := range containers {
		tree, err := createTree(container)
		if err != nil {
			return err
		}

		if tree.event.Namespace != "" {
			fmt.Fprintf(output, "%s/", tree.event.Namespace)
		}
		if tree.event.Pod != "" && tree.event.Pod != tree.event.Container {
			fmt.Fprintf(output, "%s/", tree.event.Pod)
		}
		fmt.Fprintln(output, tree.event.Container)

		fmt.Fprint(output, treeToString(tree))
	}

	return nil
}

func PrintTree(processes []*Event) error {
	return WriteTree(os.Stdout, processes)
}
