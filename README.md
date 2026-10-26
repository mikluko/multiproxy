# multiproxy

multiproxy is an HTTP proxy that decides, host by host, whether to tunnel an HTTPS connection or to intercept it.
Plain-HTTP, `CONNECT` and SOCKS5 clients all follow the same host rules, and requests the proxy can see, plain or
intercepted, can have their headers rewritten. It exports traces, metrics and logs through OpenTelemetry. Its Go
packages compose into a proxy of your own.

[![Go Reference](https://pkg.go.dev/badge/sarak.sh/mikluko/multiproxy.svg)](https://pkg.go.dev/sarak.sh/mikluko/multiproxy)

## Quick start

1. Install multiproxy. It needs Go 1.26 or later:

   ```
   go install sarak.sh/mikluko/multiproxy/cmd/multiproxy@latest
   ```

1. Start it. With no flags it listens on `127.0.0.1:8080` and tunnels every HTTPS connection:

   ```
   multiproxy
   ```

1. Send a request through it:

   ```
   curl -x http://127.0.0.1:8080 https://example.com
   ```

Each request writes one JSON access record to the proxy's stdout.

## Documentation

How-to guides:

- [How to intercept HTTPS with a trusted CA](docs/how-to/intercept-https.md)
- [How to serve SOCKS5 clients](docs/how-to/serve-socks5.md)
- [How to rewrite request headers](docs/how-to/rewrite-headers.md)
- [How to send telemetry to a collector](docs/how-to/send-telemetry.md)
- [How to cut a release](docs/how-to/cut-a-release.md), for maintainers

Reference:

- [Command-line reference](docs/reference/command-line.md): flags, host patterns, logs, environment and exit status
- [Package documentation](https://pkg.go.dev/sarak.sh/mikluko/multiproxy) for the Go packages
- [Changelog](CHANGELOG.md)

Explanation:

- [About tunnelling and MITM](docs/explanation/tunnelling-and-mitm.md)
- [About proxy headers](docs/explanation/proxy-headers.md)

## License

multiproxy is released under the [MIT License](LICENSE).
