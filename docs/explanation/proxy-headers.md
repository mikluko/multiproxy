# About proxy headers

A proxy in the path of a request is invisible to the server unless it says so. multiproxy says so by default, with
two headers, and `-novia` and `-noxforwardedfor` let it stay quiet.

## Via

[RFC 9110](https://www.rfc-editor.org/rfc/rfc9110#section-7.6.3) requires a proxy to send a `Via` header in each
message it forwards. It lists the intermediaries a request passed through, which lets a server or an operator see
the chain and lets proxies detect a request that loops back to them. multiproxy follows the requirement by default,
for intercepted requests as well as plain ones.

## X-Forwarded-For

`X-Forwarded-For` carries the address of the client a request came from. No RFC defines it, but it is
[widely understood](https://en.wikipedia.org/wiki/X-Forwarded-For) by servers and load balancers. The standardized
successor, the `Forwarded` header of [RFC 7239](https://www.rfc-editor.org/rfc/rfc7239), carries the same
information; multiproxy sends the older header because more software reads it.

## When to turn them off

Both headers tell the server something about the client and the proxy. Where that is unwanted, for example when the
proxy should not reveal the network behind it, `-novia` and `-noxforwardedfor` leave them out. `-noxforwardedfor`
also strips an `X-Forwarded-For` the client sent, so an address it supplied cannot pass through as if multiproxy had
vouched for it.

## Related pages

- [Request headers](../reference/command-line.md#request-headers)
- [How to rewrite request headers](../how-to/rewrite-headers.md)
