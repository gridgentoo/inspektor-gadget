---
title: 'Using top tcp'
weight: 20
description: >
  Periodically report TCP activity.
---

The top tcp gadget is used to visualize active TCP connections.

### On Kubernetes

First, we need to create one pod for us to play with:

```bash
$ kubectl run test-pod --image busybox:latest sleep inf
```

You can now use the gadget, but output will be empty:

```bash
$ kubectl gadget top tcp
NODE            NAMESPACE       POD             CONTAINER       PID     COMM    IP REMOTE                LOCAL                 SENT    RECV
```

Indeed, it is waiting for TCP connection to occur.
So, open *another terminal* and keep and eye on the first one, `exec` the container and use `wget`:

```bash
$ kubectl exec -ti test-pod -- wget kinvolk.io
```

On *the first terminal*, you should see:

```
NODE            NAMESPACE       POD             CONTAINER       PID     COMM    IP REMOTE                LOCAL                 SENT    RECV
minikube        default         test-pod        test-pod        134110  wget    4  188.114.96.3:443      172.17.0.2:38190      0       2
minikube        default         test-pod        test-pod        134110  wget    4  188.114.96.3:80       172.17.0.2:33286      0       1
```

This line corresponds to the TCP connection initiated by `wget`.

#### Clean everything

Congratulations! You reached the end of this guide!
You can now delete the pod you created:

```bash
$ kubectl delete pod test-pod
pod "test-pod" deleted
```

### With local-gadget

Start a container that runs `nginx` and access it locally:

```bash
$ docker run --rm --name test-top-tcp nginx /bin/sh -c 'nginx; while true; do curl localhost; sleep 1; done'
```

Start the gadget, it'll show the different connections created the localhost:

```bash
$ sudo local-gadget top tcp -c test-top-tcp
CONTAINER                                              PID         COMM             IP LOCAL                 REMOTE                SENT                 RECV
test-top-tcp                                           564780      nginx            4  127.0.0.1:80          127.0.0.1:35904       238B                 73B
test-top-tcp                                           564813      curl             4  127.0.0.1:35904       127.0.0.1:80          73B                  853B
```
