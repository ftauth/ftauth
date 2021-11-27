Version := 0.0.1
GitCommit := $(shell git rev-parse HEAD)
BuildDate := $(shell date -u)
LDFLAGS := "-X 'main.Version=$(Version)' -X 'main.GitCommit=$(GitCommit)' -X 'main.BuildDate=$(BuildDate)'"

COVERFILE := coverage.txt
GOARCH ?= amd64

.PHONY: test
test: clean server-test

.PHONY: server-test
server-test:
	go test -v -coverprofile=$(COVERFILE) ./...

.PHONY: server
server: clean
	mkdir -p bin
	GOOS=linux CGO_ENABLED=0 GOARCH=$(GOARCH) go build -ldflags $(LDFLAGS) -o bin/ftauth ./cmd/server

	# GOOS=darwin CGO_ENABLED=0 go build -ldflags $(LDFLAGS) -o bin/ftauth-macos ./cmd/server
	# GOOS=windows CGO_ENABLED=0 go build -ldflags $(LDFLAGS) -o bin/ftauth.exe ./cmd/server

.PHONY: docker
docker:
	docker build -t ftauth/ftauth:dev .

.PHONY: clean
clean:
	rm -rf bin/ $(COVERFILE)
