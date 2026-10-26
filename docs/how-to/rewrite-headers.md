# How to rewrite request headers

This guide shows you how to set, replace and strip headers on requests passing through multiproxy, per target
host.

The rules reach plain-HTTP requests and HTTPS requests multiproxy intercepts. A tunnelled connection is opaque to the
proxy, so to rewrite headers on HTTPS, intercept that host first, as shown in
[How to intercept HTTPS with a trusted CA](intercept-https.md).

## On the command line

- To set a header, replacing any value the client sent, add `-set-header '<host>=<name>: <value>'`.
- To strip a header, add `-del-header '<host>=<name>'`.

`<host>` is a [host pattern](../reference/command-line.md#host-patterns), or `*` for every host. Both flags repeat,
and every matching rule applies in the order given. This replaces the credentials on requests to an API and strips
cookies everywhere:

```
multiproxy -mitm api.example.com -ca-cert ca.pem -ca-key ca-key.pem \
  -set-header 'api.example.com=Authorization: Bearer <token>' \
  -del-header '*=Cookie'
```

## In a Go program

Wrap the handlers in `headers.Rewrite`. `MITMHandler.Handler` serves every request intercepted from a `CONNECT`
session, so a middleware around it sees those requests:

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

Any other middleware plugs in the same way.

### Compute a header per request

For a value that changes, such as a short-lived token or a credential chosen by the request path, give the rule a
`SetFunc` instead of `Set`. It runs for each matching request, after `Delete` and `Set`:

```go
rewrite := headers.Rewrite(headers.Rule{
	Host:   "api.example.com",
	Delete: []string{"Authorization"},
	SetFunc: func(rq *http.Request) (http.Header, error) {
		tok, err := tokens.Get(rq.Context(), ownerFromPath(rq.URL.Path))
		if err != nil {
			return nil, err
		}
		return http.Header{"Authorization": {"Bearer " + tok}}, nil
	},
})
```

`tokens.Get` and `ownerFromPath` stand for your own code. Pass `rq.Context()` to anything slow, so the work stops
when the client goes away, and cache inside the function: multiproxy calls it on every matching request. When the
function returns an error, multiproxy answers `502 Bad Gateway` and does not forward the request.

## What's next

- [Package documentation](https://pkg.go.dev/sarak.sh/mikluko/multiproxy) describes the `headers`, `handlers` and
  `router` packages.
