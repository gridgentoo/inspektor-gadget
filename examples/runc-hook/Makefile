CONTAINER_REPO ?= docker.io/kinvolk/gadget
IMAGE_TAG ?= $(shell ../../tools/image-tag branch)

runc-hook: main.go
	go build -o runc-hook main.go

runc-hook-static: main.go
	go build -o runc-hook-static -ldflags '-w -extldflags "-static"' main.go

test1:
	sudo ./runc-hook -output "add,remove,config"

test2:
	sudo ./runc-hook -prestart 'cat > /tmp/hooks.log'

build-container:
	DOCKER_BUILDKIT=1 docker build -t $(CONTAINER_REPO)-runc-hook:$(IMAGE_TAG) -f Dockerfile ../..

deploy:
	sed "s|image: .*:latest|image: $(CONTAINER_REPO)-runc-hook:$(IMAGE_TAG)|" deploy.yaml | kubectl apply -f -

undeploy:
	kubectl delete -f deploy.yaml

clean:
	rm -f runc-hook runc-hook-static
