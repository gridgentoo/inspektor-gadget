# make does not allow implicit rules (with '%') to be phony so let's use
# the 'phony_explicit' dependency to make implicit rules inherit the phony
# attribute
.PHONY: phony_explicit
phony_explicit:

# build

build:
	make -C $(shell pwd)/../../.. local-gadget

# test

# INTEGRATION_TESTS_PARAMS can be used to pass additional parameters locally e.g
# INTEGRATION_TESTS_PARAMS="-test.run TestFilterByContainerName" make -C integration/local-gadget/docker test
.PHONY: test
test: build
	cp ../../../local-gadget-linux-amd64 local-gadget
	go test -c -o ./local-gadget-docker-integration.test ./...
	sudo ./local-gadget-docker-integration.test -test.v -integration $${INTEGRATION_TESTS_PARAMS}
	rm -f ./local-gadget-docker-integration.test ./local-gadget