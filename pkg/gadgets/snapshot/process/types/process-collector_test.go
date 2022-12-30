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
	"bufio"
	"fmt"
	"strings"
	"testing"
)

type stsTestCase struct {
	val      uint64
	valMax   uint64
	width    uint64
	expected string
}

func TestCreateTree(t *testing.T) {
	t.Parallel()

	events := []*Event{
		{
			Pid: 42,
		},
		{
			Pid:       43,
			ParentPid: 42,
		},
		{
			Pid:       44,
			ParentPid: 42,
		},
		{
			Pid:       45,
			ParentPid: 42,
		},
		{
			Pid:       46,
			ParentPid: 43,
		},
	}

	tree, err := createTree(events)
	if err != nil {
		t.Fatalf("fail to create tree: %v", err)
	}

	expectedPid := 42
	if tree.event.Pid != expectedPid {
		t.Fatalf("root PID is wrong, expected %d got %d", expectedPid, tree.event.Pid)
	}

	childrenNumber := len(tree.children)
	expectedChildrenNumber := 3
	if childrenNumber != expectedChildrenNumber {
		t.Fatalf("expected %d children got %d", expectedChildrenNumber, childrenNumber)
	}

	expectedChildrenPIDs := []int{43, 44, 45}
parentLoop:
	for _, node := range tree.children {
		for _, expectedChildrenPID := range expectedChildrenPIDs {
			if node.event.Pid == expectedChildrenPID {
				continue parentLoop
			}
		}
		t.Fatalf("node PID is wrong, expected one from %v got %d", expectedChildrenPIDs, node.event.Pid)
	}

	var specificNode *nodeProcess
	searchingPid := 43
	for _, node := range tree.children {
		if node.event.Pid == searchingPid {
			specificNode = node

			break
		}
	}
	if specificNode == nil {
		t.Fatalf("no node with PID %d", searchingPid)
	}

	childrenNumber = len(specificNode.children)
	expectedChildrenNumber = 1
	if childrenNumber != expectedChildrenNumber {
		t.Fatalf("expected %d children got %d", expectedChildrenNumber, childrenNumber)
	}

	pid := specificNode.children[0].event.Pid
	expectedChildPid := 46
	if pid != expectedChildPid {
		t.Fatalf("child PID is wrong, expected %d got %d", expectedChildPid, pid)
	}
}

func TestCreateTreeEmpty(t *testing.T) {
	_, err := createTree(nil)
	if err == nil {
		t.Fatalf("error is nil while it was expected when creating empty tree")
	}
}

func TestCreateTreeNoRoot(t *testing.T) {
	// Each node is the parent of the other, so this is not a tree but a graph.
	events := []*Event{
		{
			Pid:       42,
			ParentPid: 43,
		},
		{
			Pid:       43,
			ParentPid: 42,
		},
	}

	_, err := createTree(events)
	if err == nil {
		t.Fatalf("error is nil while it was expected when creating tree without root")
	}
}

func TestCreateTreeSeveralRoots(t *testing.T) {
	// Each node has no parent.
	events := []*Event{
		{
			Pid: 42,
		},
		{
			Pid: 43,
		},
	}

	_, err := createTree(events)
	if err == nil {
		t.Fatalf("error is nil while it was expected when creating tree with several roots")
	}
}

func TestTreeToString(t *testing.T) {
	t.Parallel()

	nodes := make([]*nodeProcess, 5)
	i := 42
	for j := range nodes {
		nodes[j] = &nodeProcess{
			event: &Event{
				Command: fmt.Sprintf("foo-%d", i),
				Pid:     i,
			},
			children: make([]*nodeProcess, 0),
		}

		i++
	}

	// Node 0 is the root and has two children: 1 and 2
	nodes[0].children = append(nodes[0].children, nodes[1])
	nodes[0].children = append(nodes[0].children, nodes[2])

	// Node 2 has two children: 3 and 4 (which are leaf nodes)
	nodes[2].children = append(nodes[2].children, nodes[3])
	nodes[2].children = append(nodes[2].children, nodes[4])

	i = 0
	treeString := treeToString(nodes[0])
	scanner := bufio.NewScanner(strings.NewReader(treeString))

	for scanner.Scan() {
		line := scanner.Text()
		expected := fmt.Sprintf("%s(%d)", nodes[i].event.Command, nodes[i].event.Pid)
		if !strings.Contains(line, expected) {
			t.Fatalf("mismatched line %q does not contain %q", line, expected)
		}

		i++
	}
}
