# multiproxy

An explicit forward proxy that decides, per target host, whether to tunnel a client's connection, intercept it, or
refuse it.

## Requests and routing

**Client**:
A program configured to send its traffic through multiproxy.
_Avoid_: user agent, downstream

**Entry point**:
One of the three ways a client reaches multiproxy: a plain request, a CONNECT request, or a SOCKS connection.
_Avoid_: front end, front door, listener

**Plain request**:
An HTTP request a client sends to multiproxy naming a full target URL, forwarded as HTTP.
_Avoid_: forward request, proxy request

**CONNECT request**:
A client's request for a connection to a target, through which it then speaks to the target directly.
_Avoid_: tunnel request

**SOCKS connection**:
A client's request, in the SOCKS5 protocol, for a connection to a target; routed exactly as a CONNECT request.

**Target**:
The host and port a client asks to reach.
_Avoid_: destination, origin

**Upstream**:
The server multiproxy connects to on a client's behalf, at the target.
_Avoid_: origin server, backend, remote

**Host pattern**:
A rule matching target hosts: one host, a domain with its subdomains, an IP address, or every host.
_Avoid_: host rule, domain filter

**Fallback**:
The handling for targets no host pattern matches, set by the pattern `*`.
_Avoid_: default route, catch-all

**Refusal**:
multiproxy's answer to a request for a target that no host pattern and no fallback admits.
_Avoid_: block, deny, rejection

## Tunnelling and MITM

**Tunnel**:
Handling of a CONNECT request in which multiproxy copies bytes between client and upstream without reading them.
_Avoid_: passthrough, splice, pipe

**MITM**:
Handling of a CONNECT request in which multiproxy ends the client's TLS session, reads the requests inside, and
forwards each to the upstream over a TLS connection of its own.
_Avoid_: interception mode, SSL bumping, TLS inspection, decryption

**Intercepted request**:
An HTTP request read from inside a MITM session.
_Avoid_: sub-request, inner request

**Accept**:
The moment multiproxy tells a client that its CONNECT request or SOCKS connection is established.
_Avoid_: hijack, connect reply

**Proxy CA**:
The certificate authority whose key signs leaf certificates, and which clients trust so that MITM goes unnoticed.
_Avoid_: root, MITM CA, issuer CA

**Leaf certificate**:
The certificate multiproxy presents to a client for an intercepted host, signed by the proxy CA.
_Avoid_: MITM certificate, issued certificate, host certificate

**Upstream verification**:
multiproxy's check that an upstream's certificate is trusted, standing in for the check the client can no longer
make under MITM.
_Avoid_: upstream validation

## Headers and records

**Proxy headers**:
`Via` and `X-Forwarded-For`, which multiproxy adds to plain and intercepted requests to make itself visible.

**Header rule**:
A rule that sets or strips a request header for targets matching a host pattern.
_Avoid_: header rewrite rule, header override

**Access record**:
The one log record multiproxy writes for each request when it completes.
_Avoid_: access log line, request log

**Server record**:
A log record about multiproxy's own operation, apart from access records.
_Avoid_: error log, application log
