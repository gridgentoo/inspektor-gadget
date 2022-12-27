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
	log "github.com/sirupsen/logrus"

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

func (c *ContainerdClient) GetContainers() ([]*runtimeclient.ContainerData, error) {
	taskResponse, err := c.client.TaskService().List(context.TODO(), &tasks.ListTasksRequest{})
	if err != nil {
		return nil, fmt.Errorf("listing tasks: %w", err)
	}

	ret := make([]*runtimeclient.ContainerData, 0, len(taskResponse.Tasks))
	for _, task := range taskResponse.Tasks {
		container, err := c.getContainerdContainer(task.ID)
		if err != nil {
			return nil, err
		}

		if isSandboxContainer(container) {
			log.Debugf("ContainerdClient: container %q is a sandbox container. Temporary skipping it", container.ID())
			continue
		}

		containerData, err := taskAndContainerToContainerData(task, container)
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
		return nil, fmt.Errorf("listing task for container %q: %w", containerID, err)
	}

	containerData, err := c.taskToContainerData(response.Process)
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
		return nil, fmt.Errorf("listing task for container %q: %w", containerID, err)
	}
	proc := response.Process

	container, err := c.getContainerdContainer(proc.ID)
	if err != nil {
		return nil, err
	}

	containerData, err := taskAndContainerToContainerData(proc, container)
	if err != nil {
		return nil, err
	}

	spec, err := container.Spec(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("getting spec for container %q: %w", containerID, err)
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

// getContainerdContainer returns the corresponding container.Container instance to
// the given id
func (c *ContainerdClient) getContainerdContainer(id string) (containerd.Container, error) {
	containers, err := c.client.Containers(context.TODO(), fmt.Sprintf("id==%s", id))
	if err != nil {
		return nil, fmt.Errorf("listing container with id %q: %w", id, err)
	}
	if len(containers) != 1 {
		return nil, fmt.Errorf("expected 1 container with id %q, got %d", id, len(containers))
	}

	return containers[0], nil
}

// Construct a ContainerData from task.Process
func (c *ContainerdClient) taskToContainerData(proc *task.Process) (*runtimeclient.ContainerData, error) {
	container, err := c.getContainerdContainer(proc.ID)
	if err != nil {
		return nil, err
	}

	return taskAndContainerToContainerData(proc, container)
}

// Constructs a ContainerData from a task.Process and containerd.Container
// The extra containerd.Container parameter saves an additional call to the API
func taskAndContainerToContainerData(proc *task.Process, container containerd.Container) (*runtimeclient.ContainerData, error) {
	labels, err := container.Labels(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("listing labels of container %q: %w", proc.ID, err)
	}

	containerData := &runtimeclient.ContainerData{
		ID:      proc.ID,
		Name:    getContainerName(container),
		State:   processStatusStateToRuntimeClientState(proc.Status),
		Runtime: runtimeclient.ContainerdName,
	}
	runtimeclient.EnrichWithK8sMetadata(containerData, labels)
	return containerData, nil
}

// Checks if the K8s Label for the Containerkind equals to sandbox
func isSandboxContainer(container containerd.Container) bool {
	labels, err := container.Labels(context.TODO())
	if err != nil {
		return false
	}

	if kind, ok := labels[LabelK8sContainerdKind]; ok {
		return kind == LabelK8sContainerdKindSandbox
	}

	return false
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

// getContainerName returns the name of the container. If the container is
// managed by Kubernetes, it returns the name of the container as defined in
// Kubernetes. Otherwise, it returns the container ID.
func getContainerName(container containerd.Container) string {
	labels, err := container.Labels(context.TODO())
	if err != nil {
		return container.ID()
	}

	if k8sName, ok := labels[LabelK8sContainerName]; ok {
		return k8sName
	}

	return container.ID()
}
