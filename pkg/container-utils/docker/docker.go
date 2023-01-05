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

package docker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	dockertypes "github.com/docker/docker/api/types"
	dockerfilters "github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/cgroups"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
)

const (
	DefaultTimeout = 2 * time.Second
)

// DockerClient implements the ContainerRuntimeClient interface but using the
// Docker Engine API instead of the CRI plugin interface (Dockershim). It was
// necessary because Dockershim does not always use the same approach of CRI-O
// and containerd. For instance, Dockershim does not provide the container pid1
// with the ContainerStatus() call as containerd and CRI-O do.
type DockerClient struct {
	client     *client.Client
	socketPath string
}

func NewDockerClient(socketPath string) (runtimeclient.ContainerRuntimeClient, error) {
	if socketPath == "" {
		socketPath = runtimeclient.DockerDefaultSocketPath
	}

	cli, err := client.NewClientWithOpts(
		client.WithAPIVersionNegotiation(),
		client.WithHost("unix://"+socketPath),
		client.WithTimeout(DefaultTimeout),
	)
	if err != nil {
		return nil, err
	}

	return &DockerClient{
		client:     cli,
		socketPath: socketPath,
	}, nil
}

func listContainers(c *DockerClient, filter *dockerfilters.Args) ([]dockertypes.Container, error) {
	opts := dockertypes.ContainerListOptions{
		// We need to request for all containers (also non-running) because
		// when we are enriching a container that is being created, it is
		// not in "running" state yet.
		All: true,
	}
	if filter != nil {
		opts.Filters = *filter
	}

	containers, err := c.client.ContainerList(context.Background(), opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers with options %+v: %w",
			opts, err)
	}

	return containers, nil
}

func (c *DockerClient) GetContainers(options ...runtimeclient.Option) ([]*runtimeclient.ContainerData, error) {
	opts := runtimeclient.ParseOptions(options...)

	containers, err := listContainers(c, nil)
	if err != nil {
		return nil, err
	}

	ret := make([]*runtimeclient.ContainerData, 0)

	for _, container := range containers {
		state := containerStatusStateToRuntimeClientState(container.State)
		if !opts.MatchRequestedState(state) {
			log.Debugf("DockerClient: container %q is not in expected state. It is in %q. Skipping it.",
				container.ID, state)
			continue
		}

		if !opts.MustIncludeDetails() {
			ret = append(ret, DockerContainerToContainerData(&container))
			continue
		}

		detailedContainer, err := c.getContainerDetails(container.ID, opts)
		if err != nil {
			log.Warnf("DockerClient: couldn't get container details for %q. Skipping it: %s",
				container.ID, err)
			continue
		}
		if detailedContainer.Details == nil {
			log.Warnf("DockerClient: container %q doesn't have details. Skipping it.", container.ID)
			continue
		}
		ret = append(ret, detailedContainer)
	}

	return ret, nil
}

func (c *DockerClient) GetContainer(containerID string, options ...runtimeclient.Option) (*runtimeclient.ContainerData, error) {
	opts := runtimeclient.ParseOptions(options...)

	containerID, err := runtimeclient.ParseContainerID(runtimeclient.DockerName, containerID)
	if err != nil {
		return nil, err
	}

	if opts.MustIncludeDetails() {
		detailedContainer, err := c.getContainerDetails(containerID, opts)
		if err != nil {
			return nil, err
		}

		return detailedContainer, nil
	}

	filter := dockerfilters.NewArgs()
	filter.Add("id", containerID)

	containers, err := listContainers(c, &filter)
	if err != nil {
		return nil, err
	}

	if len(containers) == 0 {
		return nil, fmt.Errorf("container %q not found", containerID)
	}
	if len(containers) > 1 {
		log.Warnf("DockerClient: multiple containers (%d) with ID %q. Taking the first one: %+v",
			len(containers), containerID, containers)
	}

	if !opts.MatchRequestedState(containerStatusStateToRuntimeClientState(containers[0].State)) {
		return nil, fmt.Errorf("container %q is not in expected state", containerID)
	}

	return DockerContainerToContainerData(&containers[0]), nil
}

func (c *DockerClient) getContainerDetails(containerID string, opts *runtimeclient.ContainerOptions) (*runtimeclient.ContainerData, error) {
	containerJSON, err := c.client.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return nil, err
	}

	if containerJSON.State == nil {
		return nil, errors.New("container state is nil")
	}
	if containerJSON.State.Pid == 0 {
		return nil, errors.New("got zero pid")
	}
	if containerJSON.Config == nil {
		return nil, errors.New("container config is nil")
	}
	if containerJSON.HostConfig == nil {
		return nil, errors.New("container host config is nil")
	}

	state := containerStatusStateToRuntimeClientState(containerJSON.State.Status)
	if !opts.MatchRequestedState(state) {
		return nil, fmt.Errorf("container %q is not in expected state. It is in %q",
			containerID, state)
	}

	detailedContainer := runtimeclient.ContainerData{
		ID:      containerJSON.ID,
		Name:    strings.TrimPrefix(containerJSON.Name, "/"),
		Runtime: runtimeclient.DockerName,
		Details: &runtimeclient.ContainerDetailsData{
			Pid:         containerJSON.State.Pid,
			CgroupsPath: string(containerJSON.HostConfig.Cgroup),
		},
	}
	if len(containerJSON.Mounts) > 0 {
		detailedContainer.Details.Mounts = make([]runtimeclient.ContainerMountData, len(containerJSON.Mounts))
		for i, containerMount := range containerJSON.Mounts {
			detailedContainer.Details.Mounts[i] = runtimeclient.ContainerMountData{
				Destination: containerMount.Destination,
				Source:      containerMount.Source,
			}
		}
	}

	// Fill K8S information.
	runtimeclient.EnrichWithK8sMetadata(&detailedContainer, containerJSON.Config.Labels)

	// Try to get cgroups information from /proc/<pid>/cgroup as a fallback.
	// However, don't fail if such a file is not available, as it would prevent the
	// whole feature to work on systems without this file.
	if detailedContainer.Details.CgroupsPath == "" {
		log.Debugf("DockerClient: cgroups info not available on Docker for container %q. Trying /proc/%d/cgroup as a fallback",
			containerID, detailedContainer.Details.Pid)

		// Get cgroup paths for V1 and V2.
		cgroupPathV1, cgroupPathV2, err := cgroups.GetCgroupPaths(detailedContainer.Details.Pid)
		if err == nil {
			cgroupsPath := cgroupPathV1
			if cgroupsPath == "" {
				cgroupsPath = cgroupPathV2
			}
			detailedContainer.Details.CgroupsPath = cgroupsPath
		} else {
			log.Warnf("failed to get cgroups info of container %q from /proc/%d/cgroup: %s",
				containerID, detailedContainer.Details.Pid, err)
		}
	}

	return &detailedContainer, nil
}

func (c *DockerClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}

	return nil
}

// Convert the state from container status to state of runtime client.
func containerStatusStateToRuntimeClientState(containerState string) (runtimeClientState string) {
	switch containerState {
	case "created":
		runtimeClientState = runtimeclient.StateCreated
	case "running":
		runtimeClientState = runtimeclient.StateRunning
	case "exited":
		runtimeClientState = runtimeclient.StateExited
	case "dead":
		runtimeClientState = runtimeclient.StateExited
	default:
		runtimeClientState = runtimeclient.StateUnknown
	}
	return
}

func DockerContainerToContainerData(container *dockertypes.Container) *runtimeclient.ContainerData {
	containerData := &runtimeclient.ContainerData{
		ID:      container.ID,
		Name:    strings.TrimPrefix(container.Names[0], "/"),
		Runtime: runtimeclient.DockerName,
	}

	// Fill K8S information.
	runtimeclient.EnrichWithK8sMetadata(containerData, container.Labels)

	return containerData
}
