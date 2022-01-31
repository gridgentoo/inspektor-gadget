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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/opencontainers/runc/libcontainer/configs"
	ocispec "github.com/opencontainers/runtime-spec/specs-go"
	api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	//"k8s.io/apimachinery/pkg/types"

	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
	"github.com/kinvolk/inspektor-gadget/pkg/runcfanotify"
)

var (
	outputList   = flag.String("output", "add,remove", "comma-separated list of events to print [add,remove,config]")
	outputAdd    = false
	outputRemove = false
	outputConfig = false

	hookPreStart = flag.String("prestart", "", "command to run in the PreStart hook")
	hookPostStop = flag.String("poststop", "", "command to run in the PostStop hook")
	env          = flag.String("env", "", "the environ")
	dir          = flag.String("dir", "", "dir")
	timeout      = flag.String("timeout", "10s", "timeout")

	publishKubernetesEvent = flag.Bool("publish-kubernetes-event", false, "Publish an event using the Kubernetes Event API")
	kubeconfig             = flag.String("kubeconfig", "", "kubeconfig")
	node                   = flag.String("node", "", "Node name")

	notifier *runcfanotify.RuncNotifier
	client   *kubernetes.Clientset
)

func publishEvent(reason, message string) {
	eventTime := metav1.NewTime(time.Now())
	event := &api.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%v.%x", *node, time.Now().UnixNano()),
			Namespace: "default",
		},
		Source: api.EventSource{
			Component: "RuncHook",
			Host:      *node,
		},
		Count:               1,
		ReportingController: "github.com/kinvolk/inspektor-gadget",
		ReportingInstance:   os.Getenv("POD_NAME"), // pod name
		FirstTimestamp:      eventTime,
		LastTimestamp:       eventTime,
		InvolvedObject: api.ObjectReference{
			Kind: "Node",
			Name: *node,
			// Uncomment to make it visible in 'kubectl describe node'
			//UID: types.UID(*node),
		},
		Type:    api.EventTypeNormal,
		Reason:  reason,
		Message: message,
	}

	if _, err := client.CoreV1().Events("default").Create(context.TODO(), event, metav1.CreateOptions{}); err != nil {
		fmt.Printf("couldn't create event: %s\n", err)
	}
}

func callback(notif runcfanotify.ContainerEvent) {
	// ociState will be given as stdin to the command
	ociState := &ocispec.State{
		Version: ocispec.Version,
		ID:      notif.ContainerID,
		Pid:     int(notif.ContainerPID),
		// TODO: Make runcfanotify return the bundle dir path too.
		Bundle: "",
	}
	if notif.ContainerConfig != nil && notif.ContainerConfig.Annotations != nil {
		ociState.Annotations = notif.ContainerConfig.Annotations
	} else {
		ociState.Annotations = make(map[string]string)
	}

	cmd := ""
	switch notif.Type {
	case runcfanotify.EventTypeAddContainer:
		ociState.Status = ocispec.StateCreated
		config := ""
		if notif.ContainerConfig != nil {
			b, err := json.MarshalIndent(notif.ContainerConfig, "", "  ")
			if err != nil {
				fmt.Printf("%s\n", err)
			} else {
				config = string(b)
			}
		}
		if outputAdd {
			fmt.Printf("Container added: %v pid %d\n", notif.ContainerID, notif.ContainerPID)
			if config != "" && outputConfig {
				fmt.Printf("%s\n", config)
			}
		}
		if *publishKubernetesEvent && config != "" {
			publishEvent("NewContainerConfig", config)
		}

		if *hookPreStart != "" {
			cmd = *hookPreStart
		}
	case runcfanotify.EventTypeRemoveContainer:
		ociState.Status = ocispec.StateStopped
		if outputRemove {
			fmt.Printf("Container removed: %v pid %d\n", notif.ContainerID, notif.ContainerPID)
		}
		if *hookPostStop != "" {
			cmd = *hookPostStop
		}
	default:
		return
	}

	if cmd != "" {
		t, _ := time.ParseDuration(*timeout)
		command := &configs.Command{
			Path:    "/bin/sh",
			Args:    []string{"/bin/sh", "-c", cmd},
			Env:     strings.Split(*env, " "),
			Dir:     *dir,
			Timeout: &t,
		}

		err := command.Run(ociState)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
		}
	}
}

func main() {
	flag.Parse()

	output := strings.Split(*outputList, ",")
	for _, o := range output {
		switch o {
		case "add":
			outputAdd = true
		case "remove":
			outputRemove = true
		case "config":
			outputConfig = true
		case "":
			// strings.Split() can generate empty strings
		default:
			fmt.Printf("invalid option: %q\n", o)
			os.Exit(1)
		}
	}

	if *publishKubernetesEvent {
		var err error
		if *kubeconfig == "" && os.Getenv("KUBECONFIG") != "" {
			*kubeconfig = os.Getenv("KUBECONFIG")
		}
		client, err = k8sutil.NewClientset(*kubeconfig)
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}
	}

	supported := runcfanotify.Supported()
	if !supported {
		fmt.Printf("runcfanotify not supported\n")
		os.Exit(1)
	}

	var err error
	notifier, err = runcfanotify.NewRuncNotifier(callback)
	if err != nil {
		fmt.Printf("runcfanotify failed: %v\n", err)
		os.Exit(1)
	}
	select {}
}
