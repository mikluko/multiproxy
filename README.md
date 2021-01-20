# multiproxy

[![Go Reference](https://pkg.go.dev/badge/github.com/akabos/multiproxy.svg)](https://pkg.go.dev/github.com/akabos/multiproxy)
[![Go Report Card](https://goreportcard.com/badge/github.com/akabos/multiproxy)](https://goreportcard.com/report/github.com/akabos/multiproxy)
[![Go Cover](https://gocover.io/_badge/github.com/akabos/multiproxy)](https://gocover.io/github.com/akabos/multiproxy)
[![License](https://img.shields.io/github/license/akabos/multiproxy.svg)](https://github.com/akabos/multiproxy/blob/develop/LICENSE)

Extensible and performant HTTP roxy implemented in Go.

## Requirements

* Go v1.15 (not tested, but should work with >1.11)

## Installation

    go install -u github.com/akabos/multiproxy/cmd 

## Usage

    multiproxy 

Running [pre-built docker image](https://hub.docker.com/r/akabos/multiproxy):

    docker run -rm -p 8080:8080 akabos/multiproxy

## Proxy headers

According to [RFC 2616](https://tools.ietf.org/html/rfc2616#section-14.45), the Via general-header field MUST be used by 
gateways and proxies to indicate the intermediate protocols and recipients between the user agent and the server on 
requests, and between the origin server and the client on responses. By default, multiproxy obeys that requirement and
adds an aforementioned header to each request, including those intercepted from `CONNECT` sessions. It also appends 
client IP to `X-Forwarded-For` header which is not defined by any RFC but is [well known](https://en.wikipedia.org/wiki/X-Forwarded-For).  

If that is not what you want, you have to explicitly disable that behaviour:

    multiproxy -novia -noxforwardedfor

## Goals

* performance
* extensibility
* RFC compliance

## Non-goals

* GUI
* transparent HTTPS proxying capabilities

## TODO

* Examples
* Better test coverage
