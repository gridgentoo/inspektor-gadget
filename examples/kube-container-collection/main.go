// Copyright 2019-2021 The Inspektor Gadget authors
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

package main

import (
	"fmt"
	"os"

	"k8s.io/client-go/kubernetes"

	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/kinvolk/inspektor-gadget/pkg/container-utils"
	"github.com/kinvolk/inspektor-gadget/pkg/container-utils/containerd"
	"github.com/kinvolk/inspektor-gadget/pkg/container-utils/docker"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/pubsub"
)

var (
	client *kubernetes.Clientset
	cc     *containercollection.ContainerCollection
)

func callback(notif pubsub.PubSubEvent) {
	switch notif.Type {
	case pubsub.EventTypeAddContainer:
		fmt.Printf("Container added: %v pid %d\n", notif.Container.Id, notif.Container.Pid)
		fmt.Printf("%+v\n", &notif.Container)
	case pubsub.EventTypeRemoveContainer:
		fmt.Printf("Container removed: %v pid %d\n", notif.Container.Id, notif.Container.Pid)
	default:
		return
	}
}

func main() {
	containerEventFuncs := []pubsub.FuncNotify{callback}

	cc = &containercollection.ContainerCollection{}
	err := cc.ContainerCollectionInitialize(
		containercollection.WithPubSub(containerEventFuncs...),
		containercollection.WithCgroupEnrichment(),
		containercollection.WithLinuxNamespaceEnrichment(),
		containercollection.WithRuncFanotify(),
		containercollection.WithMultipleContainerRuntimesEnrichment([]*containerutils.RuntimeConfig{
			{Name: docker.Name},
			{Name: containerd.Name},
		}))
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Ready\n")

	cc.ContainerRange(func(c *pb.ContainerDefinition) {
		fmt.Printf("%+v\n", c)
	})

	select {}
}
