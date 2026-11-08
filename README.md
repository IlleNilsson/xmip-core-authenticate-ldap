# xmip-core-authenticate-ldap

Authenticate by LDAP: proves a username and password by a simple bind at the directory, RFC 4511 inside TLS. A technology of [xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

A simple bind carries the password as it is, so the bind travels only inside
TLS, the estate's own (`xmip-core-library-tls`): StartTLS on the directory's
ordinary port by default (RFC 4511 section 4.14), or LDAPS, TLS from the first
byte, with `over_ldaps`. The directory's certificate must reach the operating
system's trust store, or the one handed over with `trusting`. A directory that
refuses StartTLS is refused, and no bind is sent in the clear.

`in_the_clear` binds without TLS, and only to a directory on this machine: the
endpoint must name `localhost` or a loopback address before anything is
connected, and the peer connected to must be a loopback address before
anything is sent.

The directory is connected to through `net::connect`, the estate's one TCP
connect: every address its name resolves to, inside the timeout.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
