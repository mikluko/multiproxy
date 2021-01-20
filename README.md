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

Making a request over the proxy:

    curl -x http://127.0.0.1:8080 http://example.com

## HTTPS

The proxy has two methods for handling `CONNECT` request. The default one is _tunneling_ which is cryptographically 
consistent and used by default for all `CONNECT` requests. The downside of that handler is that proxy have to operate at
TCP level and have no control over requests or responses passing through the proxy. 

The other one is Man-in-the-Middle or MITM handler which basically implements 
[Man-in-the-Middle attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack). With this handler the proxy have 
full control over requests and responses. The downside is that client software have to be explicitly instructed to 
abandon attempts to verify server certificates.

Running the server in MITM mode:

    mutiproxy -mitm '*'

Making a request over the proxy in MITM mode:

    curl -k -x http://127.0.0.1:8080 https://example.com

It is possible to run proxy in the mixed mode. E.g. handling some domains with MITM and others with tunneling:

    mutiproxy -mitm '.example.com,example.net' -tunnel '*'

In the example above `example.com`, all it's subdomains and `example.net` would be served by MITM and all the other 
hostnames with tunneling. 

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
