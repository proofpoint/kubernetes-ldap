NS ?= proofpoint
VERSION ?= latest

REPO = kubernetes-ldap
NAME = kubernetes-ldap
INSTANCE = default

.PHONY: build push shell run start stop rm release vendor

default: fmt vet test build

build: vendor
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin/kubernetes-ldap .

docker:
	docker build -t $(NS)/$(REPO):$(VERSION) .

push:
	docker push $(NS)/$(REPO):$(VERSION)

rm:
	docker rm $(NAME)-$(INSTANCE)

release: build
	make push -e VERSION=$(VERSION)

test:
	go test ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

vendor:
	go get -u github.com/golang/dep/cmd/dep
	dep ensure

