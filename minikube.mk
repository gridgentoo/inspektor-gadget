
MINIKUBE_VERSION ?= v1.27.0
KUBERNETES_VERSION ?= v1.24.6
MINIKUBE_DRIVER ?= docker

PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
MINIKUBE_BIN ?= $(PROJECT_DIR)/bin/minikube

CONTAINER_RUNTIME ?= docker

# make does not allow implicit rules (with '%') to be phony so let's use
# the 'phony_explicit' dependency to make implicit rules inherit the phony
# attribute
.PHONY: phony_explicit
phony_explicit:

# minikube

MINIKUBE = $(MINIKUBE_BIN)/minikube-$(MINIKUBE_VERSION)
.PHONY: minikube
minikube:
	mkdir -p $(MINIKUBE_BIN)
	test -e $(MINIKUBE_BIN)/minikube-$(MINIKUBE_VERSION) || \
	(cd $(MINIKUBE_BIN) && curl -Lo ./minikube-$(MINIKUBE_VERSION) https://github.com/kubernetes/minikube/releases/download/$(MINIKUBE_VERSION)/minikube-linux-$(shell go env GOHOSTARCH))
	chmod +x $(MINIKUBE_BIN)/minikube-$(MINIKUBE_VERSION)

# clean

.PHONY: minikube-clean
minikube-clean:
	$(MINIKUBE) delete -p minikube-docker
	$(MINIKUBE) delete -p minikube-containerd
	$(MINIKUBE) delete -p minikube-cri-o
	rm -rf $(MINIKUBE_BIN)

# setup

MINIKUBE_SETUP_TARGETS = \
	minikube-setup-docker \
	minikube-setup-containerd \
	minikube-setup-cri-o

.PHONY: minikube-setup-all
minikube-setup-all: $(MINIKUBE_SETUP_TARGETS) minikube-setup

minikube-setup: minikube-setup-$(CONTAINER_RUNTIME)

.PHONY: phony_explicit
minikube-setup-%: minikube
	$(MINIKUBE) status -p minikube-$* -f {{.APIServer}} >/dev/null || \
	$(MINIKUBE) start -p minikube-$* --driver=$(MINIKUBE_DRIVER) --kubernetes-version=$(KUBERNETES_VERSION) --container-runtime=$* --wait=all
	$(MINIKUBE) profile minikube-$*

