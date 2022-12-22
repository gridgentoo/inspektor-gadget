---
title: 'Using trace capabilities'
weight: 20
description: >
  Trace security capability checks.
---

![Screencast of the trace capabilities gadget](capabilities.gif)

The trace capabilities gadget allows us to see what capability security checks
are triggered by applications running in Kubernetes Pods.

Linux [capabilities](https://linux.die.net/man/7/capabilities) allow for a finer
privilege control because they can give root-like capabilities to processes without
giving them full root access. They can also be taken away from root processes.
If a pod is directly executing programs as root, we can further lock it down
by taking capabilities away. Sometimes we need to add capabilities which
are not there by default. You can see the list of default and available
capabilities [in Docker](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities).
Specially if our pod is directly run as user instead of root (runAsUser: ID),
we can give some more capabilities (think as partly root) and still take all
unused capabilities to really lock it down.

### On Kubernetes

Here we have a small demo app which logs failures due to lacking capabilities.
Since none of the default capabilities is dropped, we have to find
out what non-default capability we have to add.

```bash
$ cat docs/examples/app-set-priority.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: set-priority
  labels:
    k8s-app: set-priority
spec:
  selector:
    matchLabels:
      name: set-priority
  template:
    metadata:
      labels:
        name: set-priority
    spec:
      containers:
      - name: set-priority
        image: busybox
        command: [ "sh", "-c", "while /bin/true ; do nice -n -20 echo ; sleep 5; done" ]

$ kubectl apply -f docs/examples/app-set-priority.yaml
deployment.apps/set-priority created
$ kubectl logs -lname=set-priority
nice: setpriority(-20): Permission denied
nice: setpriority(-20): Permission denied
```

We could see the error messages in the pod's log.
Let's use Inspektor Gadget to watch the capability checks:

```bash
$ kubectl gadget trace capabilities --selector name=set-priority
NODE             NAMESPACE        POD                            CONTAINER        PID     COMM             UID     CAP  CAPNAME      AUDIT  VERDICT
minikube         default          set-priority-5646554d9d-pk4gg  set-priority     110385  nice             0       23   SYS_NICE     1      Deny
minikube         default          set-priority-5646554d9d-pk4gg  set-priority     110592  nice             0       23   SYS_NICE     1      Deny
minikube         default          set-priority-5646554d9d-pk4gg  set-priority     110764  nice             0       23   SYS_NICE     1      Deny
minikube         default          set-priority-5646554d9d-pk4gg  set-priority     110965  nice             0       23   SYS_NICE     1      Deny
minikube         default          set-priority-5646554d9d-pk4gg  set-priority     111134  nice             0       23   SYS_NICE     1      Deny
^C
Terminating...
```

We can leave the gadget with Ctrl-C.
In the output we see that the `SYS_NICE` capability got checked when `nice` was run.
We should probably add it to our pod template for `nice` to work. We can also drop
all other capabilities from the default list (see link above) since `nice`
did not use them:

The meaning of the columns is:

* `CAP`: capability number.
* `CAPNAME`: capability name in a human friendly format.
* `AUDIT`: whether the kernel should audit the security request or not.
* `VERDICT`: whether the capability was present (allow) or not (deny)

```bash
$ cat docs/examples/app-set-priority-locked-down.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: set-priority
  labels:
    k8s-app: set-priority
spec:
  selector:
    matchLabels:
      name: set-priority
  template:
    metadata:
      labels:
        name: set-priority
    spec:
      containers:
      - name: set-priority
        image: busybox
        command: [ "sh", "-c", "while /bin/true ; do nice -n -20 echo ; sleep 5; done" ]
        securityContext:
          capabilities:
            add: ["SYS_NICE"]
            drop: [all]

```

At this moment we have to make sure that we are allowed to grant `SYS_NICE` for new pods in the
restricted pod security policy.

```bash
$ kubectl get psp
NAME                       PRIV    CAPS               SELINUX    RUNASUSER   FSGROUP     SUPGROUP    READONLYROOTFS   VOLUMES
nginx-ingress-controller   false   NET_BIND_SERVICE   RunAsAny   MustRunAs   MustRunAs   MustRunAs   false            configMap,secret
privileged                 true    *                  RunAsAny   RunAsAny    RunAsAny    RunAsAny    false            *
restricted                 false                      RunAsAny   MustRunAs   MustRunAs   MustRunAs   false            configMap, …
```

For privileged pods adding `SYS_NICE` would work, but not for the default pods.
We can change that by editing the policy.

```bash
$ kubectl edit psp restricted  # opens the editor to add the below two lines
spec:
  allowPrivilegeEscalation: false
  allowedCapabilities:  # <- add these two
  - SYS_NICE            #    lines here
  …

```

After saving we can verify that we are allowed to add new pods which grant `SYS_NICE`.

```bash
$ kubectl get psp
NAME                       PRIV    CAPS               SELINUX    RUNASUSER   FSGROUP     SUPGROUP    READONLYROOTFS   VOLUMES
nginx-ingress-controller   false   NET_BIND_SERVICE   RunAsAny   MustRunAs   MustRunAs   MustRunAs   false            configMap,secret
privileged                 true    *                  RunAsAny   RunAsAny    RunAsAny    RunAsAny    false            *
restricted                 false   SYS_NICE           RunAsAny   MustRunAs   MustRunAs   MustRunAs   false            configMap, …
```

Let's verify that our locked-down version works.

```bash
$ kubectl delete -f docs/examples/app-set-priority.yaml
deployment.apps "set-priority" deleted
$ kubectl apply -f docs/examples/app-set-priority-locked-down.yaml
deployment.apps/set-priority created
$ kubectl logs -lname=set-priority

```

The logs are clean, so everything works!

We can see the same checks but this time with the `Allow` verdict:

```bash
$ kubectl gadget trace capabilities --selector name=set-priority
NODE             NAMESPACE        POD                            CONTAINER        PID     COMM             UID     CAP  CAPNAME      AUDIT  VERDICT
minikube         default          set-priority-768db6dcf7-rp8gd  set-priority     10158   nice             0       23   SYS_NICE     1      Allow
minikube         default          set-priority-768db6dcf7-rp8gd  set-priority     10365   nice             0       23   SYS_NICE     1      Allow
```

You may include a kernel call stack for more context with `--print-stack`.  (If
we see additional `SYS_ADMIN` checks we can ignore them since only priviledged
pods have this capability and it's not a default capability.)

You can now delete the pod you created:
```
$ kubectl delete -f docs/examples/app-set-priority-locked-down.yaml
```

### With local-gadget

TODO
