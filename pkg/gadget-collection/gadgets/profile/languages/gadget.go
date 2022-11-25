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

package profile

import (
	"encoding/json"
	"fmt"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	languagesTracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/languages/tracer"
)

type Trace struct {
	helpers gadgets.GadgetHelpers

	started bool
	tracer  *languagesTracer.Tracer
}

type TraceFactory struct {
	gadgets.BaseFactory
}

func NewFactory() gadgets.TraceFactory {
	return &TraceFactory{
		BaseFactory: gadgets.BaseFactory{DeleteTrace: deleteTrace},
	}
}

func (f *TraceFactory) Description() string {
	return `Analyze CPU performance by sampling stack traces`
}

func (f *TraceFactory) OutputModesSupported() map[gadgetv1alpha1.TraceOutputMode]struct{} {
	return map[gadgetv1alpha1.TraceOutputMode]struct{}{
		gadgetv1alpha1.TraceOutputModeStatus: {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.tracer != nil && trace.started {
		trace.tracer.Stop()
	}
}

func (f *TraceFactory) Operations() map[gadgetv1alpha1.Operation]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			helpers: f.Helpers,
		}
	}

	return map[gadgetv1alpha1.Operation]gadgets.TraceOperation{
		gadgetv1alpha1.OperationStart: {
			Doc: "Start gadget",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		gadgetv1alpha1.OperationStop: {
			Doc: "Stop gadget and print results",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.State = gadgetv1alpha1.TraceStateStarted
		return
	}

	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)

	var err error

	mountNsMap, err := t.helpers.TracerMountNsMap(traceName)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to find tracer's mount ns map: %s", err)
		return
	}
	config := &languagesTracer.Config{
		MountnsMap: mountNsMap,
	}
	t.tracer, err = languagesTracer.NewTracer(config, t.helpers)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to create tracer: %s", err)
		return
	}

	t.started = true

	trace.Status.State = gadgetv1alpha1.TraceStateStarted
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	ret, err := t.tracer.Stop()
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to stop tracer: %s", err)
		return
	}

	t.tracer = nil
	t.started = false

	o, err := json.Marshal(ret)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to marshal result: %s", err)
		return
	}

	// TODO: How big can it be?
	trace.Status.Output = string(o)
	trace.Status.State = gadgetv1alpha1.TraceStateCompleted
}
