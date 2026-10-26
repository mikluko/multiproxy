# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/2.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `-leaf-key` selects RSA or ECDSA P-256 keys for MITM certificates, and `SelfSignedCA.KeyAlgorithm` does the same in the library.
- `-leaf-validity` and `SelfSignedCA.Validity` set how long MITM certificates stay valid.

### Changed

- **Breaking:** the module path is `sarak.sh/mikluko/multiproxy`; imports of `github.com/akabos/multiproxy` change to it.
- **Breaking:** building requires Go 1.26 or later.
- **Breaking:** `router.Router` answers a plain-HTTP request with 403 unless a host pattern matches its host or `Connect` is set, so `-mitm` and `-tunnel` restrict plain HTTP as well as `CONNECT`.

### Removed

- The Docker image is no longer published.

### Fixed

- MITM certificates name the requested hostname as a subject alternative name, so Go clients accept them.
- MITM certificate keys honour `SelfSignedCA.BitSize`, which defaults to 2048 bits instead of 1024.
- MITM certificates are valid for 30 days by default instead of 10 years, and are issued again once expired.
- MITM certificates carry random serial numbers instead of all sharing serial 1.

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

[Unreleased]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.3.1...HEAD
[0.3.1]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.3.0...v0.3.1
[0.3.0]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.2.3...v0.3.0
[0.2.3]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.2.2...v0.2.3
[0.2.2]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.2.1...v0.2.2
[0.2.1]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.2.0...v0.2.1
[0.2.0]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.1.2...v0.2.0
[0.1.2]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.1.1...v0.1.2
[0.1.1]: https://forge.sarak.sh/mikluko/multiproxy/compare/v0.1.0...v0.1.1
[0.1.0]: https://forge.sarak.sh/mikluko/multiproxy/releases/tag/v0.1.0
