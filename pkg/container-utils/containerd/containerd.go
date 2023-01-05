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

func (c *ContainerdClient) GetContainers(options ...runtimeclient.Option) ([]*runtimeclient.ContainerData, error) {
	opts := runtimeclient.ParseOptions(options...)

	containers, err := c.client.Containers(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("listing containers: %w", err)
	}

	ret := make([]*runtimeclient.ContainerData, 0)
	for _, container := range containers {
		if c.isSandboxContainer(container) {
			log.Debugf("ContainerdClient: container %q is a sandbox container. Temporary skipping it", container.ID())
			continue
		}

		containerData, err := c.containerToContainerData(container)
		if err != nil {
			return nil, fmt.Errorf("converting container %q to ContainerData: %w", container.ID(), err)
		}

		var task containerd.Task = nil

		if opts.IsStateFilterSet() {
			if task == nil {
				task, err = container.Task(context.TODO(), nil)
				if err != nil {
					// It could happen if the container is not running
					log.Debugf("ContainerdClient: couldn't get container task for %q. Skipping it: %s",
						container.ID(), err)
					continue
				}
			}

			status, err := task.Status(context.TODO())
			if err != nil {
				return nil, fmt.Errorf("getting task status for container %q: %w", container.ID(), err)
			}

			if !opts.MatchRequestedState(containerdProcessStatusToRuntimeClientState(string(status.Status))) {
				log.Debugf("ContainerdClient: container %q is not in expected state. Skipping it.", container.ID())
				continue
			}
		}

		if opts.MustIncludeDetails() {
			if task == nil {
				task, err = container.Task(context.TODO(), nil)
				if err != nil {
					// It could happen if the container is not running
					log.Debugf("ContainerdClient: couldn't get container task for %q. Skipping it: %s",
						container.ID(), err)
					continue
				}
			}

			details, err := c.getContainerDetails(container, task)
			if err != nil {
				return nil, fmt.Errorf("getting container details for %q: %w", container.ID(), err)
			}
			containerData.Details = details
		}

		ret = append(ret, containerData)
	}

	return ret, nil
}

func (c *ContainerdClient) GetContainer(containerID string, options ...runtimeclient.Option) (*runtimeclient.ContainerData, error) {
	opts := runtimeclient.ParseOptions(options...)

	containerID, err := runtimeclient.ParseContainerID(runtimeclient.ContainerdName, containerID)
	if err != nil {
		return nil, fmt.Errorf("parsing container ID: %w", err)
	}

	container, err := c.getContainer(containerID)
	if err != nil {
		return nil, err
	}

	if c.isSandboxContainer(container) {
		return nil, fmt.Errorf("container %q is a sandbox container. Temporary skipping it", container.ID())
	}

	containerData, err := c.containerToContainerData(container)
	if err != nil {
		return nil, fmt.Errorf("converting container %q to ContainerData: %w", container.ID(), err)
	}

	var task containerd.Task = nil

	if opts.IsStateFilterSet() {
		if task == nil {
			task, err = container.Task(context.TODO(), nil)
			if err != nil {
				return nil, fmt.Errorf("getting task for container %q: %w", container.ID(), err)
			}
		}

		status, err := task.Status(context.TODO())
		if err != nil {
			return nil, fmt.Errorf("getting task status for container %q: %w", container.ID(), err)
		}

		if !opts.MatchRequestedState(containerdProcessStatusToRuntimeClientState(string(status.Status))) {
			return nil, fmt.Errorf("container %q is not in expected state. It is in %q state",
				container.ID(), status.Status)
		}
	}

	if opts.MustIncludeDetails() {
		if task == nil {
			task, err = container.Task(context.TODO(), nil)
			if err != nil {
				return nil, fmt.Errorf("getting task for container %q: %w", container.ID(), err)
			}
		}

		details, err := c.getContainerDetails(container, task)
		if err != nil {
			return nil, err
		}
		containerData.Details = details
	}

	return containerData, nil
}

func (c *ContainerdClient) getContainerDetails(container containerd.Container, task containerd.Task) (*runtimeclient.ContainerDetailsData, error) {
	spec, err := container.Spec(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("getting container %q spec: %w", container.ID(), err)
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
		Pid:         int(task.Pid()),
		CgroupsPath: spec.Linux.CgroupsPath,
		Mounts:      mountData,
	}, nil
}

// Convert the state from containerd process status to state of runtime client.
func containerdProcessStatusToRuntimeClientState(status string) (runtimeClientState string) {
	switch status {
	case string(containerd.Created):
		runtimeClientState = runtimeclient.StateCreated
	case string(containerd.Running):
		runtimeClientState = runtimeclient.StateRunning
	case string(containerd.Stopped):
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

func (c *ContainerdClient) getContainer(id string) (containerd.Container, error) {
	containers, err := c.client.Containers(context.TODO(), fmt.Sprintf("id==%s", id))
	if err != nil {
		return nil, fmt.Errorf("getting container %q: %w", id, err)
	}
	if len(containers) != 1 {
		return nil, fmt.Errorf("expected 1 container with id %q, got %d", id, len(containers))
	}

	return containers[0], nil
}

func (c *ContainerdClient) containerToContainerData(container containerd.Container) (*runtimeclient.ContainerData, error) {
	labels, err := container.Labels(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("getting container %q labels: %w", container.ID(), err)
	}

	containerData := &runtimeclient.ContainerData{
		ID:      container.ID(),
		Name:    getContainerName(container),
		Runtime: runtimeclient.ContainerdName,
	}
	runtimeclient.EnrichWithK8sMetadata(containerData, labels)
	return containerData, nil
}
