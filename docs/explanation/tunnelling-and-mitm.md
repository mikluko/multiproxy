# About tunnelling and MITM

An HTTPS client asks a proxy for a connection with a `CONNECT` request, and from then on speaks TLS to the target.
multiproxy answers that request in one of two ways, chosen per target host, and the choice trades visibility
against integrity.

## Tunnelling

A tunnel connects the client to the target and copies bytes both ways. The TLS session runs end to end, so the
client verifies the real server's certificate and nothing in between can read or change the traffic, multiproxy
included. That is the default, and the right answer wherever the proxy has no business looking inside: it costs
nothing in trust and breaks no client.

The price is that the proxy sees only a host, a port and a byte count. It cannot log a URL, rewrite a header or
refuse one path while allowing another.

## MITM

MITM, or man-in-the-middle, ends the client's TLS session at the proxy. multiproxy issues a leaf certificate
for the requested host on the spot, signed by its proxy CA, reads the requests inside, serves each through its HTTP
handler, and opens a TLS connection of its own to the real server. Everything the proxy does to plain HTTP, it can
now do to HTTPS: log the URL, rewrite headers, attach a trace.

This works only because the client trusts multiproxy's CA, and that trust is the cost. Whoever holds the CA key can
impersonate any host to every client that trusts it, which is why the key file is written readable by its owner
alone, and why a CA kept on disk deserves the care of any other credential. Clients that pin certificates, or ship
their own trust store, refuse an intercepted connection however the CA is installed.

MITM also replaces the client's view of the server with the proxy's. The client sees multiproxy's
certificate and never the real server's, so the client's own verification of the server is gone. multiproxy verifies
the real server's certificate in its place, against the system roots, and answers `502 Bad Gateway` where it does
not verify. The client can no longer tell which roots that was, or see the server's certificate for itself, and
`-upstream-insecure` drops the check altogether: then a forged upstream is indistinguishable from the real one.

## One set of rules

A client can reach multiproxy three ways: a plain-HTTP request, a `CONNECT` request, or a SOCKS5 connection. All
three are routed by the same host patterns, and a host no pattern admits is refused on every path.

That symmetry is deliberate. If plain HTTP or SOCKS bypassed the rules that govern `CONNECT`, a client denied a
host over one path could reach it over another, and the rules would describe intent rather than behaviour. multiproxy
serves a SOCKS connection by handing it to the same router as an in-process `CONNECT` request, so there is no second
copy of the rules to drift.

## What multiproxy does not do

multiproxy is an explicit proxy: a client has to be configured to use it. Transparent interception, where traffic is
redirected to the proxy without the client knowing, is out of scope, and so is any user interface beyond the command
line and the Go packages.

## Related pages

- [How to intercept HTTPS with a trusted CA](../how-to/intercept-https.md)
- [Host patterns](../reference/command-line.md#host-patterns)
