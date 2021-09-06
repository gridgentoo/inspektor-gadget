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

package seccomp

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"

	commonseccomp "github.com/containers/common/pkg/seccomp"
	"github.com/opencontainers/runtime-spec/specs-go"
	libseccomp "github.com/seccomp/libseccomp-golang"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apimachineryruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	seccompprofilev1alpha1 "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	seccomptracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/seccomp/tracer"
)

type Trace struct {
	resolver gadgets.Resolver
	client   client.Client

	started bool
}

type TraceFactory struct {
	gadgets.BaseFactory
}

type TraceSingleton struct {
	mu     sync.Mutex
	tracer *seccomptracer.Tracer
	users  int
}

var traceSingleton TraceSingleton

func NewFactory() gadgets.TraceFactory {
	return &TraceFactory{}
}

func (f *TraceFactory) Description() string {
	return `The seccomp gadget traces system calls for each container in order to generate seccomp policies on-demand.`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Status":           {},
		"ExternalResource": {},
	}
}

func (f *TraceFactory) AddToScheme(scheme *apimachineryruntime.Scheme) {
	utilruntime.Must(seccompprofilev1alpha1.AddToScheme(scheme))
}

func (f *TraceFactory) DeleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		traceSingleton.mu.Lock()
		defer traceSingleton.mu.Unlock()
		traceSingleton.users--
		if traceSingleton.users == 0 {
			traceSingleton.tracer.Close()
			traceSingleton.tracer = nil
		}
	}
}

func (f *TraceFactory) Operations() map[string]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			client:   f.Client,
			resolver: f.Resolver,
		}
	}
	return map[string]gadgets.TraceOperation{
		"start": {
			Doc: "Start recording syscalls",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
			Order: 1,
		},
		"generate": {
			Doc: "Generate a seccomp profile",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Generate(trace)
			},
			Order: 2,
		},
		"stop": {
			Doc: "Stop recording syscalls",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
			Order: 3,
		},
	}
}

func (t *Trace) Operation(trace *gadgetv1alpha1.Trace,
	operation string,
	params map[string]string) {

	if trace.ObjectMeta.Namespace != gadgets.TRACE_DEFAULT_NAMESPACE {
		trace.Status.OperationError = fmt.Sprintf("This gadget only accepts operations on traces in the %s namespace", gadgets.TRACE_DEFAULT_NAMESPACE)
		return
	}
	switch operation {
	case "start":
		t.Start(trace)
	case "generate":
		t.Generate(trace)
	case "stop":
		t.Stop(trace)
	default:
		trace.Status.OperationError = fmt.Sprintf("Unknown operation %q", operation)
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.OperationError = ""
		trace.Status.Output = ""
		trace.Status.State = "Started"
		return
	}

	traceSingleton.mu.Lock()
	defer traceSingleton.mu.Unlock()
	if traceSingleton.tracer == nil {
		var err error
		traceSingleton.tracer, err = seccomptracer.NewTracer()
		if err != nil {
			trace.Status.OperationError = fmt.Sprintf("Failed to start seccomp tracer: %s", err)
			return
		}
	}
	traceSingleton.users++
	t.started = true

	trace.Status.OperationError = ""
	trace.Status.Output = ""
	trace.Status.State = "Started"
	return
}

func (t *Trace) Generate(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}
	if trace.Spec.Filter == nil || trace.Spec.Filter.Namespace == "" || trace.Spec.Filter.Podname == "" {
		trace.Status.OperationError = "Missing pod"
		return
	}
	if len(trace.Spec.Filter.Labels) != 0 {
		trace.Status.OperationError = "Seccomp gadget does not support filtering by labels"
		return
	}

	var mntns uint64
	if trace.Spec.Filter.ContainerName != "" {
		mntns = t.resolver.LookupMntnsByContainer(
			trace.Spec.Filter.Namespace,
			trace.Spec.Filter.Podname,
			trace.Spec.Filter.ContainerName,
		)
		if mntns == 0 {
			trace.Status.OperationError = fmt.Sprintf("Container %s/%s/%s not found on this node",
				trace.Spec.Filter.Namespace,
				trace.Spec.Filter.Podname,
				trace.Spec.Filter.ContainerName,
			)
			return
		}
	} else {
		mntnsMap := t.resolver.LookupMntnsByPod(
			trace.Spec.Filter.Namespace,
			trace.Spec.Filter.Podname,
		)
		if len(mntnsMap) == 0 {
			trace.Status.OperationError = fmt.Sprintf("Pod %s/%s not found on this node",
				trace.Spec.Filter.Namespace,
				trace.Spec.Filter.Podname,
			)
			return
		}

		containerList := []string{}
		for k, v := range mntnsMap {
			mntns = v
			containerList = append(containerList, k)
		}
		sort.Strings(containerList)

		if len(mntnsMap) > 1 {
			trace.Status.OperationError = fmt.Sprintf("Pod %s/%s has several containers: %v",
				trace.Spec.Filter.Namespace,
				trace.Spec.Filter.Podname,
				containerList,
			)
			return
		}
		if mntns == 0 {
			trace.Status.OperationError = fmt.Sprintf("Pod %s/%s has unknown mntns",
				trace.Spec.Filter.Namespace,
				trace.Spec.Filter.Podname,
			)
			return
		}
	}

	b := traceSingleton.tracer.Peek(mntns)

	switch trace.Spec.OutputMode {
	case "Status":
		policy := syscallArrToLinuxSeccomp(b)
		output, err := json.MarshalIndent(policy, "", "  ")
		if err != nil {
			trace.Status.OperationError = fmt.Sprintf("Failed to marshal seccomp policy: %s", err)
			return
		}

		trace.Status.Output = string(output)
		trace.Status.OperationError = ""
	case "ExternalResource":
		parts := strings.SplitN(trace.Spec.Output, "/", 2)
		var r *seccompprofilev1alpha1.SeccompProfile
		if len(parts) == 2 {
			r = syscallArrToSeccompPolicy(parts[0], parts[1], b)
		} else {
			r = syscallArrToSeccompPolicy(trace.ObjectMeta.Namespace, trace.Spec.Output, b)
		}
		err := t.client.Create(context.TODO(), r)
		if err != nil {
			trace.Status.OperationError = fmt.Sprintf("Failed to update resource: %s", err)
			return
		}
		trace.Status.OperationError = ""
	case "File":
		fallthrough
	default:
		trace.Status.OperationError = fmt.Sprintf("OutputMode not supported: %s", trace.Spec.OutputMode)
	}
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	traceSingleton.mu.Lock()
	defer traceSingleton.mu.Unlock()
	traceSingleton.users--
	if traceSingleton.users == 0 {
		traceSingleton.tracer.Close()
		traceSingleton.tracer = nil
	}

	t.started = false

	trace.Status.OperationError = ""
	trace.Status.State = "Stopped"
	return
}

/* Function arches() under the Apache License, Version 2.0 by the containerd authors:
 * https://github.com/containerd/containerd/blob/66fec3bbbf91520a1433faa16e99e5a314a61902/contrib/seccomp/seccomp_default.go#L29
 */
func arches() []specs.Arch {
	switch runtime.GOARCH {
	case "amd64":
		return []specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchX32}
	case "arm64":
		return []specs.Arch{specs.ArchARM, specs.ArchAARCH64}
	case "mips64":
		return []specs.Arch{specs.ArchMIPS, specs.ArchMIPS64, specs.ArchMIPS64N32}
	case "mips64n32":
		return []specs.Arch{specs.ArchMIPS, specs.ArchMIPS64, specs.ArchMIPS64N32}
	case "mipsel64":
		return []specs.Arch{specs.ArchMIPSEL, specs.ArchMIPSEL64, specs.ArchMIPSEL64N32}
	case "mipsel64n32":
		return []specs.Arch{specs.ArchMIPSEL, specs.ArchMIPSEL64, specs.ArchMIPSEL64N32}
	case "s390x":
		return []specs.Arch{specs.ArchS390, specs.ArchS390X}
	default:
		return []specs.Arch{}
	}
}

func syscallArrToNameList(v []byte) []string {
	names := []string{}
	for i, val := range v {
		if val == 0 {
			continue
		}
		call1 := libseccomp.ScmpSyscall(i)
		name, err := call1.GetName()
		if err != nil {
			name = fmt.Sprintf("syscall%d", i)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func syscallArrToLinuxSeccomp(v []byte) *specs.LinuxSeccomp {
	syscalls := []specs.LinuxSyscall{
		{
			Names:  syscallArrToNameList(v),
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{},
		},
	}

	s := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: arches(),
		Syscalls:      syscalls,
	}
	return s
}

func syscallArrToSeccompPolicy(namespace, name string, v []byte) *seccompprofilev1alpha1.SeccompProfile {
	syscalls := []*seccompprofilev1alpha1.Syscall{
		{
			Names:  syscallArrToNameList(v),
			Action: commonseccomp.ActAllow,
			Args:   []*seccompprofilev1alpha1.Arg{},
		},
	}

	ret := seccompprofilev1alpha1.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: seccompprofilev1alpha1.SeccompProfileSpec{
			BaseProfileName: "",
			DefaultAction:   commonseccomp.ActErrno,
			Architectures:   nil,
			Syscalls:        syscalls,
		},
	}
	for _, a := range arches() {
		arch := seccompprofilev1alpha1.Arch(a)
		ret.Spec.Architectures = append(ret.Spec.Architectures, &arch)
	}

	return &ret
}
