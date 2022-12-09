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

package testutils

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

func RunDockerContainer(ctx context.Context, t *testing.T, options ...Option) {
	opts := DefaultContainerOptions()
	for _, o := range options {
		o(opts)
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("Failed to connect to Docker: %s", err)
	}

	_ = cli.ContainerRemove(ctx, opts.Name, types.ContainerRemoveOptions{})

	reader, err := cli.ImagePull(ctx, opts.Image, types.ImagePullOptions{})
	if err != nil {
		t.Fatalf("Failed to pull image container: %s", err)
	}
	io.Copy(io.Discard, reader)

	hostConfig := &container.HostConfig{}
	if opts.SeccompProfile != "" {
		hostConfig.SecurityOpt = []string{fmt.Sprintf("seccomp=%s", opts.SeccompProfile)}
	}

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: opts.Image,
		Cmd:   []string{"/bin/sh", "-c", opts.Command},
		Tty:   false,
	}, hostConfig, nil, nil, opts.Name)
	if err != nil {
		t.Fatalf("Failed to create container: %s", err)
	}
	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		t.Fatalf("Failed to start container: %s", err)
	}

	if opts.Wait {
		statusCh, errCh := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("Failed to wait for container: %s", err)
			}
		case <-statusCh:
		}
	}

	if opts.Logs {
		out, err := cli.ContainerLogs(ctx, resp.ID, types.ContainerLogsOptions{ShowStdout: true})
		if err != nil {
			t.Fatalf("Failed to get container logs: %s", err)
		}
		buf := new(bytes.Buffer)
		buf.ReadFrom(out)
		t.Logf("Container %s output:\n%s", opts.Image, string(buf.Bytes()))
	}

	if opts.Removal {
		err = cli.ContainerRemove(ctx, opts.Name, types.ContainerRemoveOptions{Force: true})
		if err != nil {
			t.Fatalf("Failed to remove container: %s", err)
		}
	}

	err = cli.Close()
	if err != nil {
		t.Fatalf("Failed to close docker client: %s", err)
	}
}

func RemoveDockerContainer(ctx context.Context, t *testing.T, name string) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("Failed to connect to Docker: %s", err)
	}

	err = cli.ContainerRemove(ctx, name, types.ContainerRemoveOptions{Force: true})
	if err != nil {
		t.Fatalf("Failed to remove container: %s", err)
	}
}
