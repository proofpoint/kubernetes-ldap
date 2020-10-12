NS ?= proofpoint
VERSION ?= latest

REPO = kubernetes-ldap
NAME = kubernetes-ldap
INSTANCE = default

.PHONY: build push shell run start stop rm release

default: fmt vet test build

build:
	CGO_ENABLED=0 GOOS=linux go build -mod=vendor --ldflags "-s -w" -o bin/kubernetes-ldap .

docker:
	docker build -t $(NS)/$(REPO):$(VERSION) .

push:
	docker push $(NS)/$(REPO):$(VERSION)

rm:
	docker rm $(NAME)-$(INSTANCE)

release: docker
	make push -e VERSION=$(VERSION)

test:
	go test ./... -cover

fmt:
	go fmt ./...

vet:
	go vet ./...


