# ocular

Small helper for Cisco AnyConnect-style SSO (SAMLv2 / Azure AD) when using
`openconnect`.

Flow:

1. Perform the AnyConnect XML auth handshake
2. Open a real Chrome/Chromium window for you to complete SSO/MFA
3. Extract the SSO cookie and run `openconnect --cookie-on-stdin`

## Requirements

- `openconnect`
- Chrome/Chromium (or `--chrome-path`)
- `sudo`/`doas` (or run as root)

## Usage

Interactive:

```sh
ocular
```

Non-interactive:

```sh
ocular --server vpn.example.com/group -- --base-mtu=1370
ocular --server vpn.example.com/group --authenticate json
```

The session cookie is cached in `~/.ocular/config.toml` to avoid reauth.

## License

GPL-3.0-only (see `LICENSE`).
