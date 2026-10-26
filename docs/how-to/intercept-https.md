# How to intercept HTTPS with a trusted CA

This guide shows you how to run multiproxy so that it intercepts HTTPS to chosen hosts, with a CA your clients
trust, and tunnels everything else.

## Before you begin

- Install multiproxy, as shown in the [README](../../README.md#quick-start).
- Choose a directory to keep the CA in. The CA key signs certificates for every host you intercept, so keep it
  private.

## Intercept some hosts and tunnel the rest

1. Start the proxy with the hosts to intercept in `-mitm`, a fallback in `-tunnel`, and the CA files:

   ```
   multiproxy -mitm '.example.com' -tunnel '*' -ca-cert <dir>/ca.pem -ca-key <dir>/ca-key.pem
   ```

   `<dir>` is the directory you chose. The first start creates both files there; later starts read them, so the
   CA stays the same across restarts.

1. Make your client trust `<dir>/ca.pem`. For `curl`:

   ```
   curl --cacert <dir>/ca.pem -x http://127.0.0.1:8080 https://www.example.com
   ```

   For a client that reads the system trust store, add `ca.pem` to that store.

To name the CA something other than the default, add `-ca-name` and `-ca-org` on the first start. They have no
effect once the files exist.

## Export the CA certificate

To hand the certificate to someone else without giving them the files, print it:

```
multiproxy -print-ca -ca-cert <dir>/ca.pem -ca-key <dir>/ca-key.pem > multiproxy-ca.pem
```

## Change the certificates multiproxy issues

The certificates multiproxy issues for intercepted hosts use RSA 2048 keys and are valid for 30 days.

- To use ECDSA P-256 keys, which are cheaper to generate per host, add `-leaf-key ecdsa`.
- To change the validity, add `-leaf-validity` with a duration, for example `-leaf-validity 168h`.

## What's next

- [Command-line reference](../reference/command-line.md) lists every flag and the host pattern syntax.
- [About tunnelling and MITM](../explanation/tunnelling-and-mitm.md) covers what interception costs and when to
  avoid it.
