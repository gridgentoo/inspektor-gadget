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

package snisnoop

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	sniTracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/sni/tracer"
	sniTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/sni/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Trace struct {
	helpers gadgets.GadgetHelpers
	client  client.Client

	started bool

	tracer *sniTracer.Tracer
	conn   *networktracer.ConnectionToContainerCollection
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
	return `The snisnoop gadget retrieves Server Name Indication (SNI) from TLS requests.`
}

func (f *TraceFactory) OutputModesSupported() map[gadgetv1alpha1.TraceOutputMode]struct{} {
	return map[gadgetv1alpha1.TraceOutputMode]struct{}{
		gadgetv1alpha1.TraceOutputModeStream: {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		if trace.conn != nil {
			trace.conn.Close()
		}
		trace.tracer.Close()
		trace.tracer = nil
	}
}

func (f *TraceFactory) Operations() map[gadgetv1alpha1.Operation]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			client:  f.Client,
			helpers: f.Helpers,
		}
	}

	return map[gadgetv1alpha1.Operation]gadgets.TraceOperation{
		gadgetv1alpha1.OperationStart: {
			Doc: "Start snisnoop",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		gadgetv1alpha1.OperationStop: {
			Doc: "Stop snisnoop",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

func (t *Trace) publishEvent(trace *gadgetv1alpha1.Trace, event *sniTypes.Event) {
	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)
	t.helpers.PublishEvent(
		traceName,
		eventtypes.EventString(event),
	)
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.State = gadgetv1alpha1.TraceStateStarted
		return
	}

	var err error
	t.tracer, err = sniTracer.NewTracer()
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start sni tracer: %s", err)
		return
	}

	eventCallback := func(container *containercollection.Container, event *sniTypes.Event) {
		// Enrich event with data from container
		event.Node = trace.Spec.Node
		if !container.HostNetwork {
			event.Namespace = container.Namespace
			event.Pod = container.Podname
		}

		t.publishEvent(trace, event)
	}

	config := &networktracer.ConnectToContainerCollectionConfig[sniTypes.Event]{
		Tracer:        t.tracer,
		Resolver:      t.helpers,
		Selector:      *gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter),
		EventCallback: eventCallback,
		Base:          sniTypes.Base,
	}
	t.conn, err = networktracer.ConnectToContainerCollection(config)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start sni tracer: %s", err)
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

	if t.conn != nil {
		t.conn.Close()
	}
	t.tracer.Close()
	t.tracer = nil
	t.started = false

	trace.Status.State = gadgetv1alpha1.TraceStateStopped
}
