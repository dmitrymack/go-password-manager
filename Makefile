PKG        := github.com/dmitrymack/go-password-manager
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE       ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w \
	-X $(PKG)/internal/buildinfo.Version=$(VERSION) \
	-X $(PKG)/internal/buildinfo.Date=$(DATE) \
	-X $(PKG)/internal/buildinfo.Commit=$(COMMIT)
BIN        := bin
# Client targets: the specification requires Windows, Linux and macOS.
PLATFORMS  := linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64
# Generated code is excluded from the coverage figure.
COVER_SKIP := \.pb\.go

.PHONY: build server client client-all test cover lint certs up down clean

build: server client

server:
	go build -ldflags "$(LDFLAGS)" -o $(BIN)/gophkeeper-server ./cmd/server

client:
	go build -ldflags "$(LDFLAGS)" -o $(BIN)/gophkeeper ./cmd/client

# CGO is off so cross-compiling needs no C toolchain for the target OS.
client-all:
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" \
			-o $(BIN)/gophkeeper-$$os-$$arch$$ext ./cmd/client || exit 1; \
	done

test:
	go test -race ./...

cover:
	go test -race -coverprofile=coverage.out.tmp ./...
	grep -vE '$(COVER_SKIP)' coverage.out.tmp > coverage.out && rm coverage.out.tmp
	go tool cover -func=coverage.out | tail -1

lint:
	golangci-lint run ./...

# Development certificates: a local CA plus a server certificate it signs,
# valid for localhost and 127.0.0.1. The client trusts certs/ca.crt.
certs:
	mkdir -p certs
	openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
		-keyout certs/ca.key -out certs/ca.crt -subj "/CN=GophKeeper Dev CA"
	openssl req -newkey rsa:4096 -sha256 -nodes \
		-keyout certs/server.key -out certs/server.csr -subj "/CN=localhost"
	printf "subjectAltName=DNS:localhost,DNS:server,IP:127.0.0.1" > certs/san.ext
	openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key \
		-CAcreateserial -days 365 -sha256 -extfile certs/san.ext -out certs/server.crt
	rm certs/server.csr certs/san.ext

up:
	docker compose up --build -d

down:
	docker compose down

clean:
	rm -rf $(BIN) coverage.out
