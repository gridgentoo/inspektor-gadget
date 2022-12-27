// Copyright 2019-2022 The Inspektor Gadget authors
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

package containerd

import (
	"context"
	"fmt"
	"time"

	"github.com/containerd/containerd"
	tasks "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types/task"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
)

const (
	DefaultTimeout = 2 * time.Second

	LabelK8sContainerName         = "io.kubernetes.container.name"
	LabelK8sContainerdKind        = "io.cri-containerd.kind"
	LabelK8sContainerdKindSandbox = "sandbox"
)

type ContainerdClient struct {
	client *containerd.Client
}

func NewContainerdClient(socketPath string) (runtimeclient.ContainerRuntimeClient, error) {
	if socketPath == "" {
		socketPath = runtimeclient.ContainerdDefaultSocketPath
	}

	client, err := containerd.New(socketPath,
		containerd.WithTimeout(DefaultTimeout),
		containerd.WithDefaultNamespace("k8s.io"),
	)
	if err != nil {
		return nil, err
	}

	return &ContainerdClient{
		client: client,
	}, nil
}

func (c *ContainerdClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

func (c *ContainerdClient) isSandboxContainer(container containerd.Container) bool {
	labels, err := container.Labels(context.TODO())
	if err != nil {
		return false
	}

	if kind, ok := labels[LabelK8sContainerdKind]; ok {
		return kind == LabelK8sContainerdKindSandbox
	}

	return false
}

func (c *ContainerdClient) GetContainers() ([]*runtimeclient.ContainerData, error) {
	taskResponse, err := c.client.TaskService().List(context.TODO(), &tasks.ListTasksRequest{})
	if err != nil {
		return nil, err
	}

	ret := make([]*runtimeclient.ContainerData, 0, len(taskResponse.Tasks))
	for _, task := range taskResponse.Tasks {

		container, err := c.getContainerdContainer(task.ID)
		if err != nil {
			return nil, err
		}

		if c.isSandboxContainer(container) {
			continue
		}

		containerData, err := c.containerdTaskAndContainerToContainerData(task, container)
		if err != nil {
			return nil, err
		}

		ret = append(ret, containerData)
	}

	return ret, nil
}

func (c *ContainerdClient) GetContainer(containerID string) (*runtimeclient.ContainerData, error) {
	response, err := c.client.TaskService().Get(context.TODO(), &tasks.GetRequest{
		ContainerID: containerID,
	})
	if err != nil {
		return nil, err
	}

	containerData, err := c.ContainerdTaskToContainerData(response.Process)
	if err != nil {
		return nil, err
	}
	return containerData, nil
}

func (c *ContainerdClient) GetContainerDetails(containerID string) (*runtimeclient.ContainerDetailsData, error) {
	response, err := c.client.TaskService().Get(context.TODO(), &tasks.GetRequest{
		ContainerID: containerID,
	})
	if err != nil {
		return nil, err
	}
	proc := response.Process

	container, err := c.getContainerdContainer(proc.ID)
	if err != nil {
		return nil, err
	}

	containerData, err := c.containerdTaskAndContainerToContainerData(proc, container)
	if err != nil {
		return nil, err
	}

	spec, err := container.Spec(context.TODO())
	if err != nil {
		return nil, err
	}

	mountData := make([]runtimeclient.ContainerMountData, len(spec.Mounts))
	for i := range spec.Mounts {
		mount := spec.Mounts[i]
		mountData[i] = runtimeclient.ContainerMountData{
			Source:      mount.Source,
			Destination: mount.Destination,
		}
	}

	return &runtimeclient.ContainerDetailsData{
		ContainerData: *containerData,
		Pid:           int(proc.Pid),
		CgroupsPath:   spec.Linux.CgroupsPath,
		Mounts:        mountData,
	}, nil
}

// Convert the state from container status to state of runtime client.
func processStatusStateToRuntimeClientState(status task.Status) (runtimeClientState string) {
	switch status {
	case task.StatusCreated:
		runtimeClientState = runtimeclient.StateCreated
	case task.StatusRunning:
		runtimeClientState = runtimeclient.StateRunning
	case task.StatusStopped:
		runtimeClientState = runtimeclient.StateExited
	default:
		runtimeClientState = runtimeclient.StateUnknown
	}
	return
}

func guessContainerName(container containerd.Container) string {
	labels, err := container.Labels(context.TODO())
	if err != nil {
		return container.ID()
	}

	if k8sName, ok := labels[LabelK8sContainerName]; ok {
		return k8sName
	}

	return container.ID()
}

func (c *ContainerdClient) ContainerdTaskToContainerData(proc *task.Process) (*runtimeclient.ContainerData, error) {
	container, err := c.getContainerdContainer(proc.ID)
	if err != nil {
		return nil, err
	}

	return c.containerdTaskAndContainerToContainerData(proc, container)
}

func (c *ContainerdClient) getContainerdContainer(id string) (containerd.Container, error) {
	containers, err := c.client.Containers(context.TODO(), fmt.Sprintf("id==%s", id))
	if err != nil {
		return nil, err
	}
	if len(containers) != 1 {
		return nil, fmt.Errorf("expected 1 container with id %q, got %d", id, len(containers))
	}

	return containers[0], nil
}

func (c *ContainerdClient) containerdTaskAndContainerToContainerData(proc *task.Process, container containerd.Container) (*runtimeclient.ContainerData, error) {
	labels, err := container.Labels(context.TODO())
	if err != nil {
		return nil, err
	}

	containerData := &runtimeclient.ContainerData{
		ID:      proc.ID,
		Name:    guessContainerName(container),
		State:   processStatusStateToRuntimeClientState(proc.Status),
		Runtime: runtimeclient.ContainerdName,
	}
	runtimeclient.EnrichWithK8sMetadata(containerData, labels)
	return containerData, nil
}
