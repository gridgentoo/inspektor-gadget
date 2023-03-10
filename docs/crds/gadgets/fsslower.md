---
# Code generated by 'make generate-documentation'. DO NOT EDIT.
title: Gadget fsslower
---

fsslower shows open, read, write and fsync operations slower than a threshold

The following parameters are supported:
- filesystem: Which filesystem to trace [btrfs, ext4, nfs, xfs]
- minlatency: Min latency to trace, in ms. (default 10)

### Example CR

```yaml
apiVersion: gadget.kinvolk.io/v1alpha1
kind: Trace
metadata:
  name: fsslower
  namespace: gadget
spec:
  node: ubuntu-hirsute
  gadget: fsslower
  runMode: Manual
  outputMode: Stream
  filter:
    namespace: default
```

### Operations


#### start

Start fsslower gadget

```bash
$ kubectl annotate -n gadget trace/fsslower \
    gadget.kinvolk.io/operation=start
```
#### stop

Stop fsslower gadget

```bash
$ kubectl annotate -n gadget trace/fsslower \
    gadget.kinvolk.io/operation=stop
```

### Output Modes

* Stream
