# Example with the container-collection package

This example uses the container-collection package
("github.com/kinvolk/inspektor-gadget/pkg/container-collection") in order to be
notified when a new container is started and to attach the OCI config.json as a
Kubernetes event.

This uses a DaemonSet: each pod will only monitor containers locally.

To deploy the DaemonSet:
```
$ make deploy
```

Start a new pod:
```
$ kubectl run -ti --rm --image busybox shell1 -- sh
```

Notice the new event:
```
$ kubectl get events
LAST SEEN   TYPE      REASON                    OBJECT          MESSAGE
6m          Normal    NewContainerConfig        pod/shell1      {"ociVersion":"1.0.2-dev","process":{"terminal":true,"user":{"uid":0,
```

This can also be seen with the following command:
```
$ kubectl describe pod shell1
Name:         shell1
Namespace:    default
...
Events:
  Type    Reason              Age   From               Message
  ----    ------              ----  ----               -------
  Normal  Scheduled           20s   default-scheduler  Successfully assigned default/shell1 to minikube
  Normal  Pulling             19s   kubelet            Pulling image "busybox"
  Normal  Pulled              16s   kubelet            Successfully pulled image "busybox" in 3.006760389s
  Normal  Created             16s   kubelet            Created container shell1
  Normal  NewContainerConfig  16s   RuncHook           {"ociVersion":"1.0.2-dev","process":{"terminal":true,"user":{"uid":0,
```
