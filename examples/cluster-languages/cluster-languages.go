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

package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/tracer"
)

var gauge *prometheus.GaugeVec

type key struct {
	Namespace string
	Container string
	Language  string
}

var (
	processLanguages = prometheus.NewDesc(
		"processes_languages",
		"Programming language of different processes.",
		[]string{"namespace", "container", "language"}, nil,
	)

	containerCollection *containercollection.ContainerCollection
)

type ProcessCollector struct {
	mu sync.Mutex
}

func (pc *ProcessCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(pc, ch)
}

func getStats() (map[key]*int, error) {
	config := &tracer.Config{
		GetLanguage: true,
	}
	events, err := tracer.RunCollector(config, containerCollection)
	if err != nil {
		return nil, err
	}

	stats := map[key]*int{}

	for _, event := range events {
		key := key{
			Namespace: event.Namespace,
			Container: event.Container,
			Language:  event.Language,
		}
		if val, ok := stats[key]; ok {
			*val++
		} else {
			one := 1
			stats[key] = &one
		}
	}

	return stats, nil
}

func (pc *ProcessCollector) Collect(ch chan<- prometheus.Metric) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	stats, err := getStats()
	if err != nil {
		log.Printf("error collecting stats: %s\n", err)
		return
	}

	for key, val := range stats {
		ch <- prometheus.MustNewConstMetric(
			processLanguages, prometheus.GaugeValue, float64(*val),
			key.Namespace, key.Container, key.Language,
		)
	}
}

func main() {
	containerCollection = &containercollection.ContainerCollection{}

	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithRuncFanotify(),
		containercollection.WithLinuxNamespaceEnrichment(),
		containercollection.WithMultipleContainerRuntimesEnrichment(
			[]*containerutils.RuntimeConfig{
				{Name: runtimeclient.DockerName},
				{Name: runtimeclient.ContainerdName},
			}),
	}

	if err := containerCollection.Initialize(opts...); err != nil {
		fmt.Printf("containerCollection.Initialize: %s\n", err)
		return
	}
	defer containerCollection.Close()

	// Create a non-global registry.
	reg := prometheus.NewPedanticRegistry()

	processCollector := &ProcessCollector{}

	reg.MustRegister(processCollector)

	// Expose metrics and custom registry via an HTTP server
	// using the HandleFor function. "/metrics" is the usual endpoint for that.
	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	log.Fatal(http.ListenAndServe(":2112", nil))
}
