FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X github.com/dmitrymack/go-password-manager/internal/buildinfo.Version=${VERSION}" \
    -o /out/gophkeeper-server ./cmd/server

FROM alpine:3.22
RUN adduser -D -H gophkeeper
USER gophkeeper
COPY --from=build /out/gophkeeper-server /usr/local/bin/gophkeeper-server
EXPOSE 3200
ENTRYPOINT ["gophkeeper-server"]
