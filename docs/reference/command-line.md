# Command-line reference

## Synopsis

```
multiproxy [<flag> ...]
```

With neither `-mitm` nor `-tunnel`, multiproxy tunnels `CONNECT` requests to every host, as `-tunnel '*'` does.

## Flags

Table: flags of the `multiproxy` command.

| Flag | Default | Description |
|---|---|---|
| `-listen <address>` | `127.0.0.1:8080` | Address of the HTTP proxy listener. |
| `-socks <address>` | none | Address of a SOCKS5 listener. No SOCKS listener is opened without it. |
| `-mitm <patterns>` | none | Comma-separated [host patterns](#host-patterns) whose `CONNECT` sessions are intercepted. |
| `-tunnel <patterns>` | none | Comma-separated host patterns whose `CONNECT` sessions are tunnelled. |
| `-ca-cert <file>` | none | PEM file of the CA certificate that signs intercepted hosts' certificates. Requires `-ca-key`. |
| `-ca-key <file>` | none | PEM file of the CA private key. Requires `-ca-cert`. |
| `-ca-name <name>` | `root.example.org` | Common name of a CA that multiproxy creates. |
| `-ca-org <name>` | `Multiproxy Root Org` | Organization of a CA that multiproxy creates. |
| `-print-ca` | off | Prints the CA certificate as PEM to stdout and exits. |
| `-leaf-key <algorithm>` | `rsa` | Key algorithm of leaf certificates: `rsa` for RSA 2048, `ecdsa` for ECDSA P-256. |
| `-leaf-validity <duration>` | `720h0m0s` | Validity of leaf certificates, as a Go duration such as `168h`. |
| `-upstream-ca <file>` | none | PEM file of CA certificates trusted for upstream servers, beside the system roots. Excludes `-upstream-insecure`. |
| `-upstream-insecure` | off | Accepts any upstream server certificate. Excludes `-upstream-ca`. |
| `-set-header <host>=<name>: <value>` | none | Sets a header on requests to matching hosts. Repeatable. |
| `-del-header <host>=<name>` | none | Strips a header from requests to matching hosts. Repeatable. |
| `-novia` | off | Leaves out the `Via` header. |
| `-noxforwardedfor` | off | Leaves out the `X-Forwarded-For` header, and strips one the client sent. |
| `-noaccesslog` | off | Writes no access records. |
| `-h` | | Prints the flags and exits. |

## Host patterns

`-mitm`, `-tunnel`, `-set-header` and `-del-header` take host patterns. A pattern matches the target host without
its port.

Table: host pattern forms.

| Pattern | Matches |
|---|---|
| `example.com` | `example.com` only |
| `.example.com` | `example.com` and every subdomain of it |
| `192.0.2.1` | that IP address only |
| `*` | every host |

`-mitm` patterns are tried before `-tunnel` patterns, each in the order given, and the first match decides. `*` in
`-mitm` or `-tunnel` is a fallback for hosts no other pattern matches; it may appear in only one of the two.

A request to a host that no pattern and no fallback matches is refused: a `CONNECT` request with
`405 Method Not Allowed`, a plain-HTTP request with `403 Forbidden`, and a SOCKS connection with reply code 2.

`-set-header` and `-del-header` apply every matching rule, in the order given.

## CA files

`-ca-cert` and `-ca-key` must name both files or neither. Where neither file exists, multiproxy creates a CA there:
an RSA 2048 key written as PKCS #8 with mode `0600`, and a certificate valid for 10 years. A certificate that is not
a CA is refused. Without the flags, multiproxy creates a CA in memory on every start.

## Upstream connections

For an intercepted request, multiproxy connects to the real server over TLS and verifies its certificate against the
system roots, and also against `-upstream-ca` where given. A certificate that does not verify answers the client with
`502 Bad Gateway`. `-upstream-insecure` turns verification off.

Connecting to a tunnel target times out after 5 seconds.

## Request headers

By default multiproxy adds two headers to each plain-HTTP and intercepted request:

- `Via`, with `1.1` and the host name of the machine multiproxy runs on, appended to any value the client sent.
- `X-Forwarded-For`, with the client's IP address appended.

With telemetry enabled, the upstream request also carries the proxy's span in `traceparent`.

## Logs

Access records go to stdout, one JSON object per request, written when the request completes:

Table: access record fields.

| Field | Description |
|---|---|
| `time` | When the request completed, RFC 3339 with nanoseconds. |
| `seq`, `uid` | Sequence number and UUID of the request. |
| `parent-seq`, `parent-uuid` | Sequence number and UUID of the `CONNECT` session an intercepted request came through. |
| `client` | Client address. |
| `method` | Request method. |
| `server` | Target host and port, for `CONNECT`. |
| `url` | Target URL, for other methods. |
| `status` | Response status code. |
| `content-length` | Bytes sent to the client. |
| `logger` | `access.http`, `access.tunnel`, `access.mitm`, or `access.mitm.http` for an intercepted request. |
| `duration`, `duration-human` | Time taken, in nanoseconds and rounded to milliseconds. |
| `trace_id`, `span_id` | The request's trace and span, while it is traced. |

Server records go to stderr as JSON objects with `time`, `level`, `msg` and `logger`, and `trace_id` and `span_id`
while a request is traced.

## Environment

multiproxy reads the
[OpenTelemetry SDK environment variables](https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/).
With none set, it exports traces, metrics and logs over OTLP to localhost. `OTEL_SDK_DISABLED=true` turns telemetry
off. Export failures are logged at warn level where an `OTEL_EXPORTER_OTLP_*ENDPOINT` variable is set, and at debug
level otherwise.

## Exit status

Table: exit status of the `multiproxy` command.

| Status | Meaning |
|---|---|
| 0 | `-h`, `-print-ca`, or a stop on SIGINT or SIGTERM. |
| 1 | A failure after the flags parsed, such as an unreadable CA or an address in use. |
| 2 | A flag that does not parse. |

## SOCKS5 reply codes

Table: SOCKS5 reply codes multiproxy sends, from RFC 1928.

| Code | Meaning | When |
|---|---|---|
| 0 | succeeded | The connection is tunnelled or intercepted. |
| 1 | general failure | Any other failure. |
| 2 | connection not allowed by ruleset | No host pattern admits the target. |
| 4 | host unreachable | The target refused the connection or did not resolve. |
| 6 | TTL expired | Connecting to the target took longer than 5 seconds. |
| 7 | command not supported | A command other than `CONNECT`. |
| 8 | address type not supported | An address type other than IPv4, IPv6 or a domain name. |

A client that offers no method without authentication gets method `0xFF` and the connection closes.
