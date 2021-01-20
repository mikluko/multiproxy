FROM golang:1.15-alpine3.12 AS download

RUN apk add --no-cache git gcc musl-dev

WORKDIR /usr/local/src/github.com/akabos/multiproxy
COPY go.mod go.sum ./
RUN go mod download

FROM golang:1.15-alpine3.12 AS build

WORKDIR /usr/local/src/github.com/akabos/multiproxy

COPY --from=download /go/pkg/mod /go/pkg/mod
COPY ./ ./

RUN go build -o /usr/local/bin/multiproxy github.com/akabos/multiproxy/cmd/multiproxy

FROM alpine:3.12

RUN apk add --no-cache dumb-init ca-certificates

COPY --from=build /usr/local/bin/multiproxy /usr/local/bin/

ENTRYPOINT ["/usr/bin/dumb-init"]

CMD ["multiproxy", "-listen", "0.0.0.0:8080"]
