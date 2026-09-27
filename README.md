# xmip-core-authenticate-ldap

Authenticate by LDAP: proves a username and password by a simple bind at the directory, RFC 4511 over TCP. A technology of [xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

The directory is connected to through `net::connect`, the estate's one TCP connect: every address its name resolves to, inside the timeout; until 2026-09-27 this crate wrote the loop itself.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
