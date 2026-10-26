# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/2.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `headers.Rule.SetFunc` computes headers per request; an error answers the request with 502 Bad Gateway instead of forwarding it.

### Fixed

- Responses to intercepted requests stream to the client instead of reaching it only once complete.
- Every request pipelined on an intercepted connection is answered, where requests after the first could be lost.
- A client that starts its TLS handshake before reading the `CONNECT` response is intercepted instead of stalling.

## [0.4.0] - 2026-10-26

### Added

- `-leaf-key` selects RSA or ECDSA P-256 keys for MITM certificates, and `SelfSignedCA.KeyAlgorithm` does the same in the library.
- `-leaf-validity` and `SelfSignedCA.Validity` set how long MITM certificates stay valid.
- `-ca-cert` and `-ca-key` read the CA from PEM files, and create both when neither exists.
- `-ca-name` and `-ca-org` set the subject of a generated CA.
- `-print-ca` prints the CA certificate as PEM and exits.
- `issuer.RootTemplate`, `issuer.NewRoot`, `issuer.LoadOrCreate` and `issuer.WriteFiles` create, read and write a CA.
- `-set-header` and `-del-header` set and strip headers on plain-HTTP and MITM requests to matching hosts.
- The `headers` middleware package rewrites request headers per host pattern.
- `router.MatchHost` matches a hostname against a host pattern.
- `-socks` opens a SOCKS5 listener routed by the same `-mitm` and `-tunnel` rules as `CONNECT` requests.
- The `socks5` package serves SOCKS5 connections as `CONNECT` requests to an `http.Handler`.
- Traces, metrics and logs are exported through the OpenTelemetry SDK, configured by the standard `OTEL_*` environment variables and exporting over OTLP to localhost by default.
- Log records written while a request is traced carry `trace_id` and `span_id`, and `log.TraceHandler` adds them to any `slog.Handler`.
- The command stops on SIGINT and SIGTERM, flushing telemetry before it exits.

### Changed

- **Breaking:** the module path is `sarak.sh/mikluko/multiproxy`; imports of `github.com/akabos/multiproxy` change to it.
- **Breaking:** building requires Go 1.26 or later.
- **Breaking:** `router.Router` answers a plain-HTTP request with 403 unless a host pattern matches its host or `Connect` is set, so `-mitm` and `-tunnel` restrict plain HTTP as well as `CONNECT`.
- **Breaking:** the `log` middleware package is built on `log/slog`: `log.Middleware` takes an access and a server `*slog.Logger`, and the helpers take `slog` key-value arguments instead of `zap.Field`.
- Logs are written by `log/slog`: JSON records carry `time` instead of `ts`, and server records carry upper-case levels.
- With telemetry enabled, an upstream request carries the proxy's span in its `traceparent` header in place of the client's.

### Removed

- The Docker image is no longer published.
- **Breaking:** `log.DefaultAccessLogEncoderConfig`, `log.DefaultServerLogEncoderConfig` and `log.Fatal`; the zap dependency is gone.

### Fixed

- MITM certificates name the requested hostname as a subject alternative name, so Go clients accept them.
- MITM certificate keys honour `SelfSignedCA.BitSize`, which defaults to 2048 bits instead of 1024.
- MITM certificates are valid for 30 days by default instead of 10 years, and are issued again once expired.
- MITM certificates carry random serial numbers instead of all sharing serial 1.
- A generated CA is signed with SHA-256 instead of SHA-1, and carries a random serial number.

## [0.3.1] - 2021-04-29

### Removed

- An unused field of `HTTPHandler`.

## [0.3.0] - 2021-04-29

### Added

- `HTTPHandler.NoXForwardedFor` skips adding the `X-Forwarded-For` header.

### Removed

- **Breaking:** the `xforwardedfor` middleware; set `HTTPHandler.NoXForwardedFor` instead.

## [0.2.3] - 2021-02-19

### Fixed

- A failed `CONNECT` request is logged with its status code.

## [0.2.2] - 2021-02-19

### Changed

- Access and server logs are written as JSON, with lowercase levels and the logger name under `logger`.

## [0.2.1] - 2021-02-18

### Fixed

- A nil pointer dereference in the tunnel handler.

## [0.2.0] - 2021-01-25

### Changed

- `HTTPHandler` proxies through the standard library's `httputil.ReverseProxy`.

## [0.1.2] - 2021-01-21

### Added

- `log.UID` and `log.Sequence` return a request's unique ID and sequence number.

## [0.1.1] - 2021-01-21

### Added

- `log.StatusCode` and `log.ContentLength` return a response's status code and content length.

## [0.1.0] - 2021-01-20

Initial release.

### Added

- HTTP, tunneling and MITM proxy handlers, a request router, and logging middleware.

[Unreleased]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.4.0...HEAD
[0.4.0]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.3.1...v0.4.0
[0.3.1]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.3.0...v0.3.1
[0.3.0]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.2.3...v0.3.0
[0.2.3]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.2.2...v0.2.3
[0.2.2]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.2.1...v0.2.2
[0.2.1]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.2.0...v0.2.1
[0.2.0]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.1.2...v0.2.0
[0.1.2]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.1.1...v0.1.2
[0.1.1]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.1.0...v0.1.1
[0.1.0]: https://forge.sarak.sh/mikluko/multiproxy/releases/tag/v0.1.0
