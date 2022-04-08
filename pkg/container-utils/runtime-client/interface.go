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

package runtimeclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"

	"google.golang.org/grpc"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

type ContainerData struct {
	// ID is the container ID without the container runtime prefix. For
	// instance, "cri-o://" for CRI-O.
	ID string

	// Name is the container name. In the case the container runtime response
	// with multiples, Name contains only the first element.
	Name string

	// Running defines whether or not the container is in the running state
	Running bool
}

// ContainerRuntimeClient defines the the interface to communicate with the
// different container runtimes.
type ContainerRuntimeClient interface {
	// Initialize creates the client to communicate with the container runtime
	// and ensures that the connection was established.
	Initialize() error

	// PidFromContainerID returns the pid1 of the container identified by the
	// specified ID. In case of errors, it can return -1 if there is any problem
	// retrieving the container information or parsing the response. Or, 0 if
	// the pid is not present within the retrieved information.
	PidFromContainerID(containerID string) (int, error)

	// GetContainers returns a slice with the information of all the containers
	// (not only running) or only the container identified by the provided ID.
	// The container information is represented with the ContainerData data
	// structure.
	GetContainers(containerID string) ([]*ContainerData, error)

	// Close tears down the connection with the client.
	Close() error
}

// CRIClient implements the ContainerRuntimeClient interface using the CRI
// plugin interface to communicate with the different container runtimes.
type CRIClient struct {
	Name            string
	RuntimeEndpoint string
	ConnTimeout     time.Duration

	conn   *grpc.ClientConn
	client pb.RuntimeServiceClient
}

func (c *CRIClient) Initialize() error {
	conn, err := grpc.Dial(
		c.RuntimeEndpoint,
		grpc.WithInsecure(),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", c.RuntimeEndpoint, c.ConnTimeout)
		}),
	)
	if err != nil {
		return err
	}

	client := pb.NewRuntimeServiceClient(conn)

	// Verify that we established the connection by making a simple call. It is
	// useful when the CRI is not known a priori, and we are trying all of them.
	_, err = client.Status(context.Background(), &pb.StatusRequest{})
	if err != nil {
		return err
	}

	c.conn = conn
	c.client = client

	return nil
}

// parseExtraInfo parses the container extra information returned by
// ContainerStatus(). It keeps backward compatibility after the ContainerInfo
// format was modified in:
// cri-o v1.18.0: https://github.com/cri-o/cri-o/commit/be8e876cdabec4e055820502fed227aa44971ddc
// containerd v1.6.0-beta.1: https://github.com/containerd/containerd/commit/85b943eb47bc7abe53b9f9e3d953566ed0f65e6c
func parseExtraInfo(extraInfo map[string]string) (int, error) {
	info, ok := extraInfo["info"]
	if !ok {
		// Try with old format
		pidStr, ok := extraInfo["pid"]
		if !ok {
			return -1, fmt.Errorf("container status reply from runtime doesn't contain pid")
		}

		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			return -1, fmt.Errorf("failed to parse pid %q: %w", pidStr, err)
		}

		return pid, nil
	}

	type InfoContent struct {
		Pid int `json:"pid"`
	}

	var infoContent InfoContent
	err := json.Unmarshal([]byte(info), &infoContent)
	if err != nil {
		return -1, fmt.Errorf("failed extracting pid from container status reply: %w", err)
	}

	return infoContent.Pid, nil
}

func (c *CRIClient) PidFromContainerID(containerID string) (int, error) {
	// If ID contains a prefix, it must match the runtime name: "<name>://<ID>"
	split := regexp.MustCompile(`://`).Split(containerID, -1)
	if len(split) == 2 {
		if split[0] != c.Name {
			return -1, fmt.Errorf("invalid container runtime %q, it should be %q",
				containerID, c.Name)
		}
		containerID = split[1]
	} else {
		containerID = split[0]
	}

	request := &pb.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}

	res, err := c.client.ContainerStatus(context.Background(), request)
	if err != nil {
		return -1, err
	}

	return parseExtraInfo(res.Info)
}

func (c *CRIClient) GetContainers(containerID string) ([]*ContainerData, error) {
	var ret []*ContainerData

	request := &pb.ListContainersRequest{
		Filter: &pb.ContainerFilter{
			Id: containerID,
		},
	}

	res, err := c.client.ListContainers(context.Background(), request)
	if err != nil {
		return ret, fmt.Errorf("failed to list containers after request %+v: %w",
			request, err)
	}

	for _, container := range res.GetContainers() {
		ret = append(ret, &ContainerData{
			ID:      container.Id,
			Name:    container.GetMetadata().Name,
			Running: container.GetState() == pb.ContainerState_CONTAINER_RUNNING,
		})
	}

	return ret, nil
}

func (c *CRIClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}