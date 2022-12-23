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

package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/cli-runtime/pkg/genericclioptions"
)

const kubeConfig = `apiVersion: v1
clusters:
- cluster:
    server: k8s:443
  name: k8s
- cluster:
    server: kubernetes:443
  name: kubernetes
contexts:
- context:
    cluster: k8s
  name: k8s
- context:
    cluster: kubernetes
  name: kubernetes
current-context: k8s
kind: Config
preferences: {}
`

func TestKubeRestConfig(t *testing.T) {
	// prepare kubeConfig
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(kubeConfig), os.ModePerm); err != nil {
		t.Fatalf("failed to write kubeconfig at path=%q", path)
	}

	// set/test we can read multipath KUBECONFIG
	t.Setenv("KUBECONFIG", fmt.Sprintf("%s:%s", path, path))
	_, err := kubeRestConfig(&genericclioptions.ConfigFlags{})
	if err != nil {
		t.Fatalf("expected no error while creating config but got=%s", err)
	}

	// test we can read multiple contexts
	validateHostInContext(t, "", "k8s:443")
	validateHostInContext(t, "k8s", "k8s:443")
	validateHostInContext(t, "kubernetes", "kubernetes:443")
}

func validateHostInContext(t *testing.T, context, host string) {
	restConfig, err := kubeRestConfig(&genericclioptions.ConfigFlags{Context: &context})
	if err != nil {
		t.Fatalf("expected no error while creating config but got=%s", err)
	}
	if restConfig.Host != host {
		t.Fatalf("expected host=%q, got host=%q for context=%s", host, restConfig.Host, context)
	}
}
