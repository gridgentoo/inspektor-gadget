# Example with the runcfanotify package

This example uses the runcfanotify package
("github.com/kinvolk/inspektor-gadget/pkg/runcfanotify") in order to be execute
custom OCI hooks.

This uses a DaemonSet: each pod will only monitor containers locally.

To deploy the DaemonSet:
```
$ make deploy
```

This will run `runc-hook -output add,remove -prestart /hooks/prestart.sh` and
the prestart hook will print the OCI state.

Start a new pod:
```
$ kubectl run -ti --rm --image busybox shell1 -- sh
```

Notice the logs:
```
$ kubectl logs -n runc-hook runc-hook-c9nsf
Container added: e7d7dd301bdd9ef0213a59e730eb28807100eb00fc5a945c44039e1ec260b753 pid 37478
{"ociVersion":"1.0.2-dev","id":"e7d7dd301bdd9ef0213a59e730eb28807100eb00fc5a945c44039e1ec260b753","status":"created","pid":37478,"bundle":""}
Container added: d2732b0ddc91f00fd787f7692cf261fc1fac898565bbec33497226e1d13a6afe pid 37559
{"ociVersion":"1.0.2-dev","id":"d2732b0ddc91f00fd787f7692cf261fc1fac898565bbec33497226e1d13a6afe","status":"created","pid":37559,"bundle":""}
```

There are two containers because Kubernetes starts a "pause" container along with the requested container.
