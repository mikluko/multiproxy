# How to serve SOCKS5 clients

This guide shows you how to open a SOCKS5 listener beside the HTTP one, for clients that only speak SOCKS.

1. Start multiproxy with `-socks` and the address to listen on:

   ```
   multiproxy -mitm '.example.com' -tunnel '*' -socks 127.0.0.1:1080
   ```

1. Point the client at the SOCKS listener. For `curl`:

   ```
   curl --socks5-hostname 127.0.0.1:1080 https://example.net
   ```

A SOCKS connection follows the same `-mitm` and `-tunnel` rules as a `CONNECT` request. A host those rules refuse
is refused over SOCKS too, and `curl` reports a SOCKS handshake failure.

The listener accepts the `CONNECT` command without authentication. It offers no way to authenticate clients, so bind
it to an address that only trusted clients reach.

## What's next

- [Command-line reference](../reference/command-line.md#socks5-reply-codes) lists the SOCKS reply codes.
- [About tunnelling and MITM](../explanation/tunnelling-and-mitm.md#one-set-of-rules) covers why SOCKS shares the
  HTTP rules.
