---
title: 'Using trace sni'
weight: 20
description: >
  Trace Server Name Indication (SNI) from TLS requests.
---

The trace sni gadget is used to trace the [Server Name Indication (SNI)](https://en.wikipedia.org/wiki/Server_Name_Indication) requests sent as part of TLS handshakes.

## How to use it?

The SNI tracer will show which pods are making which SNI requests. To start it,
we can run:

```bash
$ kubectl gadget trace sni
NODE             NAMESPACE        POD              NAME
```

To generate some output for this example, let's create a demo pod in *another terminal*:

```bash
$ kubectl run -it ubuntu --image ubuntu:latest -- /bin/bash
root@ubuntu:/# apt update && apt install -y wget && wget wikimedia.org
(...)
HTTP request sent, awaiting response... 301 Moved Permanently
Location: https://www.wikimedia.org/ [following]
(...)
root@ubuntu:/# wget www.github.com
(...)
HTTP request sent, awaiting response... 301 Moved Permanently
Location: https://github.com/ [following]
(...)
```

Go back to *the first terminal* and see:

```
NODE               NAMESPACE          POD                PID        TID        COMM      NAME
minikube           default            ubuntu             1123615    1123615    wget      wikimedia.org
minikube           default            ubuntu             1123615    1123615    wget      www.wikimedia.org
minikube           default            ubuntu             1123670    1123670    wget      www.github.com
minikube           default            ubuntu             1123670    1123670    wget      github.com
```

We can see that each time our `wget` client connected to a different
server, our tracer caught the Server Name Indication requested.

## Use JSON output

This gadget supports JSON output, for this simply use `-o json`, and
trigger the output as before:

```bash
$ kubectl gadget trace sni -o json
{"node":"minikube","namespace":"default","pod":"ubuntu","type":"normal","pid":1129812,"tid":1129812,"comm":"wget","mountnsid":4026534328,"name":"wikimedia.org"}
{"node":"minikube","namespace":"default","pod":"ubuntu","type":"normal","pid":1129812,"tid":1129812,"comm":"wget","mountnsid":4026534328,"name":"www.wikimedia.org"}

```

## Clean everything

Congratulations! You reached the end of this guide!
You can now delete the pod you created:

```bash
$ kubectl delete pod ubuntu
pod "ubuntu" deleted
```
