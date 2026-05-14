.PHONY: test build image kind-up policyctl-check

test:
	go test ./...

build:
	go build -o bin/policygate ./cmd/webhook
	go build -o bin/policyctl ./cmd/policyctl

image:
	docker build -t policygate:local .

kind-up:
	./hack/kind-up.sh

policyctl-check:
	go run ./cmd/policyctl check -f examples/bad-pod.yaml -p policies/
