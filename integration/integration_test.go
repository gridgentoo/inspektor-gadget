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
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	K8sDistroARO        = "aro"
	K8sDistroMinikubeGH = "minikube-github"
)

var supportedK8sDistros = []string{K8sDistroARO, K8sDistroMinikubeGH}

var (
	integration = flag.Bool("integration", false, "run integration tests")

	// image such as docker.io/kinvolk/gadget:latest
	image = flag.String("image", "", "gadget container image")

	doNotDeploy = flag.Bool("no-deploy", false, "don't deploy Inspektor Gadget")

	k8sDistro = flag.String("k8s-distro", "", "allows to skip tests that are not supported on a given Kubernetes distribution")
)

func runCommands(cmds []*command, t *testing.T) {
	// defer all cleanup commands so we are sure to exit clean whatever
	// happened
	defer func() {
		for _, cmd := range cmds {
			if cmd.cleanup {
				cmd.run(t)
			}
		}
	}()

	// defer stopping commands
	defer func() {
		for _, cmd := range cmds {
			if cmd.startAndStop && cmd.started {
				// Wait a bit before stopping the command.
				time.Sleep(15 * time.Second)
				cmd.stop(t)
			}
		}
	}()

	// run all commands but cleanup ones
	for _, cmd := range cmds {
		if cmd.cleanup {
			continue
		}

		cmd.run(t)
	}
}

func TestMain(m *testing.M) {
	flag.Parse()

	if !*integration {
		fmt.Println("Skipping integration test.")

		os.Exit(0)
	}

	if os.Getenv("KUBECTL_GADGET") == "" {
		fmt.Fprintf(os.Stderr, "please set $KUBECTL_GADGET.")

		os.Exit(-1)
	}

	if *image != "" {
		os.Setenv("GADGET_IMAGE_FLAG", "--image "+*image)
	}

	if *k8sDistro != "" {
		found := false
		for _, val := range supportedK8sDistros {
			if *k8sDistro == val {
				found = true
				break
			}
		}

		if !found {
			fmt.Fprintf(os.Stderr, "Error: invalid argument '-k8s-distro': %q. Valid values: %s\n",
				*k8sDistro, strings.Join(supportedK8sDistros, ", "))

			os.Exit(-1)
		}
	}

	seed := time.Now().UTC().UnixNano()
	rand.Seed(seed)
	fmt.Printf("using random seed: %d\n", seed)

	initialDelay := 15
	if *k8sDistro == K8sDistroARO {
		// ARO and any other Kubernetes distribution that uses Red Hat
		// Enterprise Linux CoreOS (RHCOS) requires more time to initialise
		// because we automatically download the kernel headers for it. See
		// gadget-container/entrypoint.sh.
		initialDelay = 60
	}

	initCommands := []*command{
		deployInspektorGadget,
		deploySPO,
		waitUntilInspektorGadgetPodsDeployed,
		waitUntilInspektorGadgetPodsInitialized(initialDelay),
	}

	cleanup := func() {
		fmt.Printf("Clean inspektor-gadget:\n")
		cleanupInspektorGadget.runWithoutTest()

		fmt.Printf("Clean SPO:\n")
		cleanupSPO.runWithoutTest()
	}

	if !*doNotDeploy {
		// defer the cleanup to be sure it's called if the test
		// fails (hence calling runtime.Goexit())
		defer cleanup()

		fmt.Printf("Setup inspektor-gadget:\n")
		for _, cmd := range initCommands {
			err := cmd.runWithoutTest()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				cleanup()
				os.Exit(-1)
			}
		}
	}

	ret := m.Run()

	if !*doNotDeploy {
		// os.Exit() doesn't call deferred functions, hence do the cleanup manually.
		cleanup()
	}

	os.Exit(ret)
}

func TestBindsnoop(t *testing.T) {
	ns := generateTestNamespaceName("test-bindsnoop")

	t.Parallel()

	bindsnoopCmd := &command{
		description: "Start bindsnoop gadget",
		cmd:         fmt.Sprintf("$KUBECTL_GADGET bindsnoop -n %s", ns),
		verifyOutputCallback: func(output string) error {
			return matchRegExp(output, fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+\d+\s+nc`, ns))
		},
		startAndStop: true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		bindsnoopCmd,
		{
			description:          "Run pod which calls bind()",
			cmd:                  busyboxPodCommand(ns, "while true; do nc -l -p 9090 -w 1; done"),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestBiolatency(t *testing.T) {
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running biolatency gadget on ARO: it fails to compile eBPF program, see issue #572")
	}

	t.Parallel()

	commands := []*command{
		{
			description: "Run biolatency gadget",
			cmd:         "id=$($KUBECTL_GADGET biolatency start --node $(kubectl get node --no-headers | cut -d' ' -f1 | head -1)); sleep 15; $KUBECTL_GADGET biolatency stop $id",
			verifyOutputCallback: func(output string) error {
				return matchRegExp(output, `usecs\s+:\s+count\s+distribution`)
			},
		},
	}

	runCommands(commands, t)
}

func TestBiotop(t *testing.T) {
	ns := generateTestNamespaceName("test-biotop")

	t.Parallel()

	biotopCmd := &command{
		description:  "Start biotop gadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET biotop --node $(kubectl get pod -n %s test-pod -o jsonpath='{.spec.nodeName}')", ns),
		startAndStop: true,
		verifyOutputCallback: func(output string) error {
			return matchRegExp(output, `test-pod\s+test-pod\s+\d+\s+dd`)
		},
	}

	// Gadget must be executed after running the test-pod to be able to retrieve
	// the node where it is running. Required to support multi-node clusters.
	commands := []*command{
		createTestNamespaceCommand(ns),
		{
			description:          "Run pod which generates I/O",
			cmd:                  busyboxPodCommand(ns, "while true; do dd if=/dev/zero of=/tmp/test count=4096; done"),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		biotopCmd,
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestCapabilities(t *testing.T) {
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running capabilities gadget on ARO: it runs but does not provide output, see issue #570")
	}

	ns := generateTestNamespaceName("test-capabilities")

	t.Parallel()

	capabilitiesCmd := &command{
		description:  "Start capabilities gadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET capabilities -n %s", ns),
		startAndStop: true,
		verifyOutputCallback: func(output string) error {
			return matchRegExp(output, fmt.Sprintf(`%s\s+test-pod.*nice.*CAP_SYS_NICE`, ns))
		},
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		capabilitiesCmd,
		{
			description:          "Run pod which fails to run nice",
			cmd:                  busyboxPodCommand(ns, "while true; do nice -n -20 echo; done"),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestDns(t *testing.T) {
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running dns gadget on ARO: fails with 'operation not permitted' error, see issue #569")
	}

	ns := generateTestNamespaceName("test-dns")

	t.Parallel()

	dnsCmd := &command{
		description:  "Start dns gadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET dns -n %s", ns),
		startAndStop: true,
		verifyOutputCallback: func(output string) error {
			return matchRegExp(output, `test-pod\s+OUTGOING\s+A\s+microsoft.com`)
		},
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		dnsCmd,
		{
			description:          "Run pod which interacts with dns",
			cmd:                  fmt.Sprintf("kubectl run --restart=Never --image=wbitt/network-multitool -n %s test-pod -- sh -c 'while true; do nslookup microsoft.com; done'", ns),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestExecsnoop(t *testing.T) {
	ns := generateTestNamespaceName("test-execsnoop")

	t.Parallel()

	execsnoopCmd := &command{
		description:  "Start execsnoop gadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET execsnoop -n %s", ns),
		startAndStop: true,
		verifyOutputCallback: func(output string) error {
			return matchRegExp(output, fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+date`, ns))
		},
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		execsnoopCmd,
		{
			description:          "Run pod which does a lot of exec",
			cmd:                  busyboxPodCommand(ns, "while true; do date; done"),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestFiletop(t *testing.T) {
	ns := generateTestNamespaceName("test-filetop")

	t.Parallel()

	filetopCmd := &command{
		description:  "Start filetop gadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET filetop -n %s", ns),
		startAndStop: true,
		verifyOutputCallback: func(output string) error {
			return matchRegExp(output, fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+\d+\s+\S*\s+0\s+\d+\s+0\s+\d+\s+R\s+date`, ns))
		},
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		filetopCmd,
		{
			description:          "Run pod which does IO",
			cmd:                  busyboxPodCommand(ns, "while true; do echo date >> /tmp/date.txt; done"),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestFsslower(t *testing.T) {
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running fsslower gadget on ARO: it runs but does not provide output, see issue #571")
	}

	ns := generateTestNamespaceName("test-fsslower")

	t.Parallel()

	fsslowerCmd := &command{
		description:  "Start fsslower gadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET fsslower -n %s -t ext4 -m 0", ns),
		startAndStop: true,
		verifyOutputCallback: func(output string) error {
			return matchRegExp(output, fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+cat`, ns))
		},
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		fsslowerCmd,
		{
			description:          "Run pod which touches a file",
			cmd:                  busyboxPodCommand(ns, `echo "this is foo" > foo && while true; do cat foo && sleep 0.1; done`),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestMountsnoop(t *testing.T) {
	ns := generateTestNamespaceName("test-mountsnoop")

	t.Parallel()

	mountsnoopCmd := &command{
		description:  "Start mountsnoop gadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET mountsnoop -n %s", ns),
		startAndStop: true,
		verifyOutputCallback: func(output string) error {
			return matchRegExp(output, `test-pod\s+test-pod\s+mount.*mount\("/mnt", "/mnt", .*\) = -2`)
		},
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		mountsnoopCmd,
		{
			description:          "Run pod which tries to mount a directory",
			cmd:                  busyboxPodCommand(ns, "while true; do mount /mnt /mnt; done"),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestNetworkpolicy(t *testing.T) {
	ns := generateTestNamespaceName("test-networkpolicy")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		{
			description:          "Run test pod",
			cmd:                  busyboxPodCommand(ns, "while true; do wget -q -O /dev/null https://kinvolk.io; done"),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		{
			description: "Run network-policy gadget",
			cmd:         fmt.Sprintf("$KUBECTL_GADGET network-policy monitor -n %s --output ./networktrace.log & sleep 15; kill $!; head networktrace.log", ns),
			verifyOutputCallback: func(output string) error {
				return matchRegExp(output, fmt.Sprintf(`"type":"connect".*"%s".*"test-pod"`, ns))
			},
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestOomkill(t *testing.T) {
	ns := generateTestNamespaceName("test-oomkill")

	t.Parallel()

	oomkillCmd := &command{
		description:  "Start oomkill gadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET oomkill -n %s", ns),
		startAndStop: true,
		verifyOutputCallback: func(output string) error {
			return matchRegExp(output, `\d+\s+tail`)
		},
	}

	limitPodYaml := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: %s
spec:
  containers:
  - name: test-pod-container
    image: busybox
    resources:
      limits:
        memory: "128Mi"
    command: ["/bin/sh", "-c"]
    args:
    - while true; do tail /dev/zero; done
`, ns)

	commands := []*command{
		createTestNamespaceCommand(ns),
		oomkillCmd,
		{
			description:          "Run pod which exhaust memory with memory limits",
			cmd:                  fmt.Sprintf("echo '%s' | kubectl apply -f -", limitPodYaml),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestOpensnoop(t *testing.T) {
	ns := generateTestNamespaceName("test-opensnoop")

	t.Parallel()

	opensnoopCmd := &command{
		description:  "Start opensnoop gadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET opensnoop -n %s", ns),
		startAndStop: true,
		verifyOutputCallback: func(output string) error {
			return matchRegExp(output, fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+\d+\s+whoami\s+3`, ns))
		},
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		opensnoopCmd,
		{
			description:          "Run pod which calls open()",
			cmd:                  busyboxPodCommand(ns, "while true; do whoami; done"),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestProcessCollector(t *testing.T) {
	requirements := []*command{
		{
			description:          "Verify kernel version",
			cmd:                  "kubectl get node -o jsonpath='{.items[*].status.nodeInfo.kernelVersion}'",
			verifyOutputCallback: verifyIteratorsSupport,
			actionOnError:        Skip, // If this command fails, the rest of the test will be skipped
		},
	}

	runCommands(requirements, t)

	// ns := generateTestNamespaceName("test-process-collector")

	// t.Parallel()

	// commands := []*command{
	// 	createTestNamespaceCommand(ns),
	// 	{
	// 		description:          "Run nginx pod",
	// 		cmd:                  fmt.Sprintf("kubectl run --restart=Never --image=nginx -n %s test-pod", ns),
	// 		verifyOutputCallback: verifyTestPodCreation,
	// 	},
	// 	waitUntilTestPodReadyCommand(ns),
	// 	{
	// 		description: "Run process-collector gadget",
	// 		cmd:         fmt.Sprintf("$KUBECTL_GADGET process-collector -n %s", ns),
	// 		verifyOutputCallback: func(output string) error {
	// 			return matchRegExp(output, fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+nginx\s+\d+`, ns))
	// 		},
	// 	},
	// 	deleteTestNamespaceCommand(ns),
	// }
	//
	// runCommands(commands, t)
}

func TestProfile(t *testing.T) {
	ns := generateTestNamespaceName("test-profile")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		{
			description:          "Run test pod",
			cmd:                  busyboxPodCommand(ns, "while true; do echo foo > /dev/null; done"),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		{
			description: "Run profile gadget",
			cmd:         fmt.Sprintf("$KUBECTL_GADGET profile -n %s -p test-pod -K & sleep 15; kill $!", ns),
			verifyOutputCallback: func(output string) error {
				return matchRegExp(output, `sh;\w+;\w+;\w+open`) // echo is builtin.
			},
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestSeccompadvisor(t *testing.T) {
	ns := generateTestNamespaceName("test-seccomp-advisor")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		{
			description:          "Run test pod",
			cmd:                  busyboxPodCommand(ns, "while true; do echo foo; done"),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		{
			description: "Run seccomp-advisor gadget",
			cmd:         fmt.Sprintf("id=$($KUBECTL_GADGET seccomp-advisor start -n %s -p test-pod); sleep 30; $KUBECTL_GADGET seccomp-advisor stop $id", ns),
			verifyOutputCallback: func(output string) error {
				return matchRegExp(output, `write`)
			},
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestAuditSeccomp(t *testing.T) {
	ns := generateTestNamespaceName("test-audit-seccomp")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		{
			description: "Create SeccompProfile",
			cmd: fmt.Sprintf(`
				kubectl apply -f - <<EOF
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: log
  namespace: %s
  annotations:
    description: "Log some syscalls"
spec:
  defaultAction: SCMP_ACT_ALLOW
  architectures:
  - SCMP_ARCH_X86_64
  syscalls:
  - action: SCMP_ACT_KILL
    names:
    - unshare
  - action: SCMP_ACT_LOG
    names:
    - mkdir
EOF
			`, ns),
			verifyOutputCallback: func(output string) error {
				return matchRegExp(output, "seccompprofile.security-profiles-operator.x-k8s.io/log created")
			},
		},
		{
			description: "Run test pod",
			cmd: fmt.Sprintf(`
				kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: %s
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/%s/log.json
  restartPolicy: Never
  containers:
  - name: container1
    image: busybox
    command: ["sh"]
    args: ["-c", "while true; do unshare -i; sleep 1; done"]
EOF
			`, ns, ns),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		{
			description: "Run audit-seccomp gadget",
			cmd:         fmt.Sprintf("$KUBECTL_GADGET audit-seccomp -n %s & sleep 5; kill $!", ns),
			verifyOutputCallback: func(output string) error {
				return matchRegExp(output, fmt.Sprintf(`%s\s+test-pod\s+container1\s+unshare\s+\d+\s+unshare\s+kill_thread`, ns))
			},
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestSigsnoop(t *testing.T) {
	ns := generateTestNamespaceName("test-sigsnoop")

	t.Parallel()

	sigsnoopCmd := &command{
		description:  "Start sigsnoop gadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET sigsnoop -n %s", ns),
		startAndStop: true,
		verifyOutputCallback: func(output string) error {
			return matchRegExp(output, fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+\d+\s+sh\s+SIGTERM`, ns))
		},
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		sigsnoopCmd,
		{
			description:          "Run pod which sends signal",
			cmd:                  busyboxPodCommand(ns, "while true; do sleep 3 & kill $!; done"),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestSnisnoop(t *testing.T) {
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running snisnoop gadget on ARO: fails with 'operation not permitted' error, see issue #569")
	}

	ns := generateTestNamespaceName("test-snisnoop")

	t.Parallel()

	snisnoopCmd := &command{
		description:  "Start snisnoop gadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET snisnoop -n %s", ns),
		startAndStop: true,
		verifyOutputCallback: func(output string) error {
			return matchRegExp(output, `test-pod\s+kinvolk.io`)
		},
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		snisnoopCmd,
		{
			description:          "Run pod which interacts with snisnoop",
			cmd:                  busyboxPodCommand(ns, "while true; do wget -q -O /dev/null https://kinvolk.io; done"),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestSocketCollector(t *testing.T) {
	requirements := []*command{
		{
			description:          "Verify kernel version",
			cmd:                  "kubectl get node -o jsonpath='{.items[*].status.nodeInfo.kernelVersion}'",
			verifyOutputCallback: verifyIteratorsSupport,
			actionOnError:        Skip, // If this command fails, the rest of the test will be skipped
		},
	}

	runCommands(requirements, t)

	ns := generateTestNamespaceName("test-socket-collector")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		{
			description:          "Run nginx pod",
			cmd:                  fmt.Sprintf("kubectl run --restart=Never --image=nginx -n %s test-pod", ns),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		{
			description: "Run socket-collector gadget",
			cmd:         fmt.Sprintf("$KUBECTL_GADGET socket-collector -n %s", ns),
			verifyOutputCallback: func(output string) error {
				return matchRegExp(output, fmt.Sprintf(`%s\s+test-pod\s+TCP\s+0\.0\.0\.0`, ns))
			},
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestTcpconnect(t *testing.T) {
	ns := generateTestNamespaceName("test-tcpconnect")

	t.Parallel()

	tcpconnectCmd := &command{
		description:  "Start tcpconnect gadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET tcpconnect -n %s", ns),
		startAndStop: true,
		verifyOutputCallback: func(output string) error {
			return matchRegExp(output, fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+\d+\s+wget`, ns))
		},
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		tcpconnectCmd,
		{
			description:          "Run pod which opens TCP socket",
			cmd:                  busyboxPodCommand(ns, "while true; do wget -q -O /dev/null -T 3 http://1.1.1.1; done"),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestTcptracer(t *testing.T) {
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running tcptracer gadget on ARO: it runs but does not provide output, see issue #568")
	}

	ns := generateTestNamespaceName("test-tcptracer")

	t.Parallel()

	tcptracerCmd := &command{
		description:  "Start tcptracer gadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET tcptracer -n %s", ns),
		startAndStop: true,
		verifyOutputCallback: func(output string) error {
			return matchRegExp(output, `C\s+\d+\s+wget\s+\d\s+[\w\.:]+\s+1\.1\.1\.1\s+\d+\s+80`)
		},
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		tcptracerCmd,
		{
			description:          "Run pod which opens TCP socket",
			cmd:                  busyboxPodCommand(ns, "while true; do wget -q -O /dev/null -T 3 http://1.1.1.1; done"),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestTcptop(t *testing.T) {
	ns := generateTestNamespaceName("test-tcptop")

	t.Parallel()

	tcptopCmd := &command{
		description:  "Start tcptop gadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET tcptop --node $(kubectl get pod -n %s test-pod -o jsonpath='{.spec.nodeName}') -n %s -p test-pod", ns, ns),
		startAndStop: true,
		verifyOutputCallback: func(output string) error {
			return matchRegExp(output, `wget`)
		},
	}

	// Gadget must be executed after running the test-pod to be able to retrieve
	// the node where it is running. Required to support multi-node clusters.
	commands := []*command{
		createTestNamespaceCommand(ns),
		{
			description:          "Run pod which opens TCP socket",
			cmd:                  busyboxPodCommand(ns, "while true; do wget -q -O /dev/null https://kinvolk.io; done"),
			verifyOutputCallback: verifyTestPodCreation,
		},
		waitUntilTestPodReadyCommand(ns),
		tcptopCmd,
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestTraceloop(t *testing.T) {
	ns := generateTestNamespaceName("test-traceloop")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		{
			description: "Start the traceloop gadget",
			cmd:         "$KUBECTL_GADGET traceloop start",
		},
		{
			description: "Wait traceloop to be started",
			cmd:         "sleep 15",
		},
		{
			description: "Run multiplication pod",
			cmd:         fmt.Sprintf("kubectl run --restart=Never -n %s --image=busybox multiplication -- sh -c 'RANDOM=output ; echo \"3*7*2\" | bc > /tmp/file-$RANDOM ; sleep infinity'", ns),
		},
		{
			description: "Wait until multiplication pod is ready",
			cmd:         fmt.Sprintf("sleep 5 ; kubectl wait -n %s --for=condition=ready pod/multiplication ; kubectl get pod -n %s ; sleep 2", ns, ns),
		},
		{
			description: "Check traceloop list",
			cmd:         fmt.Sprintf("sleep 20 ; $KUBECTL_GADGET traceloop list -n %s --no-headers | grep multiplication | awk '{print $1\" \"$6}'", ns),
			verifyOutputCallback: func(output string) error {
				return equalTo(output, "multiplication started\n")
			},
		},
		{
			description: "Check traceloop show",
			cmd:         fmt.Sprintf(`TRACE_ID=$($KUBECTL_GADGET traceloop list -n %s --no-headers | `, ns) + `grep multiplication | awk '{printf "%s", $4}') ; $KUBECTL_GADGET traceloop show $TRACE_ID | grep -C 5 write`,
			verifyOutputCallback: func(output string) error {
				return matchRegExp(output, "\\[bc\\] write\\(1, \"42\\\\n\", 3\\)")
			},
		},
		{
			description: "traceloop list",
			cmd:         "$KUBECTL_GADGET traceloop list -A",
			cleanup:     true,
		},
		{
			description: "Stop the traceloop gadget",
			cmd:         "$KUBECTL_GADGET traceloop stop",
			verifyOutputCallback: func(output string) error {
				return equalTo(output, "")
			},
			cleanup: true,
		},
		{
			description: "Wait until traceloop is stopped",
			cmd:         "sleep 15",
			cleanup:     true,
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}
