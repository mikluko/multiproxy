# multiproxy

`multiproxy` is an extensible and performant HTTP proxy implemented in Go.

[![Go Reference](https://pkg.go.dev/badge/sarak.sh/mikluko/multiproxy.svg)](https://pkg.go.dev/sarak.sh/mikluko/multiproxy)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://forge.sarak.sh/mikluko/multiproxy/src/branch/main/LICENSE)

## Requirements

* Go 1.26 or later

## Installation

    go install sarak.sh/mikluko/multiproxy/cmd/multiproxy@latest

## Usage

    multiproxy 

Making a request over the proxy:

    curl -x http://127.0.0.1:8080 http://example.com

## HTTPS

The proxy has two methods for handling `CONNECT` request. The default one is _tunneling_ which is cryptographically 
consistent and used by default for all `CONNECT` requests. The downside of that handler is that proxy have to operate at
TCP level and have no control over requests or responses passing through the proxy. 

The other one is Man-in-the-Middle or MITM handler which basically implements 
[Man-in-the-Middle attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack). With this handler the proxy have 
full control over requests and responses. The downside is that a client has to trust the proxy's CA, or skip
certificate verification.

Running the server in MITM mode:

    multiproxy -mitm '*'

Making a request over the proxy in MITM mode, without verifying the certificate:

    curl -k -x http://127.0.0.1:8080 https://example.com

### A persistent CA

Without `-ca-cert` and `-ca-key` the CA is generated in memory and changes on every start. With them, it is read
from the two PEM files, and created there when neither exists:

    multiproxy -mitm '*' -ca-cert ca.pem -ca-key ca-key.pem

`-ca-name` and `-ca-org` set the subject of a CA created that way. `ca.pem` is what a client trusts:

    curl --cacert ca.pem -x http://127.0.0.1:8080 https://example.com

`-print-ca` prints the CA certificate in use and exits.

MITM certificates use RSA 2048 keys and are valid for 30 days. `-leaf-key ecdsa` switches to ECDSA P-256 keys,
and `-leaf-validity` sets another validity.

It is possible to run proxy in the mixed mode. E.g. handling some domains with MITM and others with tunneling:

    mutiproxy -mitm '.example.com,example.net' -tunnel '*'

In the example above `example.com`, all it's subdomains and `example.net` would be served by MITM and all the other 
hostnames with tunneling. 

## SOCKS5

`-socks` opens a SOCKS5 listener beside the HTTP one. Each SOCKS connection is routed by the same `-mitm` and
`-tunnel` rules as a `CONNECT` request, and refused where they refuse one:

    multiproxy -mitm '.example.com' -tunnel '*' -socks 127.0.0.1:1080

    curl --socks5-hostname 127.0.0.1:1080 https://example.net

Only the `CONNECT` command is supported, without authentication.

## Proxy headers

According to [RFC 2616](https://tools.ietf.org/html/rfc2616#section-14.45), the Via general-header field MUST be used by 
gateways and proxies to indicate the intermediate protocols and recipients between the user agent and the server on 
requests, and between the origin server and the client on responses. By default, multiproxy obeys that requirement and
adds an aforementioned header to each request, including those intercepted from `CONNECT` sessions. It also appends 
client IP to `X-Forwarded-For` header which is not defined by any RFC but is [well known](https://en.wikipedia.org/wiki/X-Forwarded-For).  

If that is not what you want, you have to explicitly disable that behaviour:

    multiproxy -novia -noxforwardedfor

## Rewriting headers

`-set-header HOST=Name: value` sets a header, replacing any value the client sent, and `-del-header HOST=Name`
strips one. `HOST` is a pattern as in `-mitm`, or `*` for every host. Both flags repeat, and every matching rule
applies in the order given:

    multiproxy -mitm api.example.com -set-header 'api.example.com=Authorization: Bearer secret' -del-header '*=Cookie'

The rules reach plain-HTTP requests and requests intercepted by MITM. A tunnelled connection is opaque to the
proxy and passes unchanged.

## Library use

The packages under `pkg/` compose into a proxy of your own. `MITMHandler.Handler` serves every request intercepted
from a `CONNECT` session, so any middleware wrapped around it sees and can change those requests. This proxy
replaces the `Authorization` header on requests to `api.example.com`, plain or intercepted:

```go
rewrite := headers.Rewrite(headers.Rule{
	Host: "api.example.com",
	Set:  http.Header{"Authorization": {"Bearer " + os.Getenv("API_TOKEN")}},
})

r := &router.Router{
	Default: rewrite(&handlers.HTTPHandler{}),
}
r.HandleConnectHost("api.example.com", &handlers.MITMHandler{
	Handler: rewrite(&handlers.HTTPHandler{}),
})

_ = http.ListenAndServe("127.0.0.1:8080", r)
```

## Goals

* performance
* extensibility
* RFC compliance

## Non-goals

* GUI
* transparent HTTPS proxying capabilities

## TODO

* Examples

## Releasing

`CHANGELOG.md` decides releases. Work lands on `main` through pull requests from feature branches.
To release, a pull request renames `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` and opens a fresh
`## [Unreleased]` above it. Merging it tags `vX.Y.Z` and publishes the release with that entry as
its notes.
