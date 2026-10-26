FROM golang:1.27-alpine3.24 AS download

RUN apk add --no-cache git gcc musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

FROM golang:1.27-alpine3.24 AS build

WORKDIR /src

COPY --from=download /go/pkg/mod /go/pkg/mod
COPY ./ ./

RUN go build -o /usr/local/bin/multiproxy ./cmd/multiproxy

FROM alpine:3.24

RUN apk add --no-cache dumb-init ca-certificates

COPY --from=build /usr/local/bin/multiproxy /usr/local/bin/

ENTRYPOINT ["/usr/bin/dumb-init"]

CMD ["multiproxy", "-listen", "0.0.0.0:8080"]
