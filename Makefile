Version := 0.0.1
GitCommit := $(shell git rev-parse HEAD)
BuildDate := $(shell date -u)
LDFLAGS := "-X 'main.Version=$(Version)' -X 'main.GitCommit=$(GitCommit)' -X 'main.BuildDate=$(BuildDate)'"

COVERFILE := coverage.txt

.PHONY: test
test: clean server-test admin-test # landing-test

.PHONY: server-test
server-test:
	go test -v -coverprofile=$(COVERFILE) ./...

.PHONY: server
server: clean
	mkdir -p bin
	GOOS=linux go build -ldflags $(LDFLAGS) -o bin/ftauth ./cmd/server
	GOOS=darwin go build -ldflags $(LDFLAGS) -o bin/ftauth-macos ./cmd/server
	GOOS=windows go build -ldflags $(LDFLAGS) -o bin/ftauth.exe ./cmd/server

.PHONY: landing-static
landing-static: clean
	cd web/landing; \
	dart pub get; \
	dart tool/grind.dart

.PHONY: landing-test
landing-test:
	cd web/landing; \
	dart pub get; \
	dart tool/grind.dart test

.PHONY: landing
landing: landing-static
	mkdir -p bin
	GOOS=linux go build -o bin/landing ./cmd/landing

.PHONY: admin-static
admin-static: clean
	cd web/admin; \
	flutter pub get; \
	flutter build web;

.PHONY: admin-test
admin-test:
	cd web/admin; \
	flutter pub get; \
	flutter test

.PHONY: clean
clean:
	rm -rf bin/ $(COVERFILE) web/admin/build/ web/landing/build/