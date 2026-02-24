# ocular

Friendly CLI-based SSO bridge for `openconnect` (Cisco AnyConnect-style login).

## Requirements

- `openconnect`
- Chrome/Chromium (or `--chrome-path`)

## Install

Running

```sh
cargo install --path .
```

installs the binary to `~/.cargo/bin/ocular` which is on your `PATH` by default.

## Usage

```sh
# Interactive
ocular

# Connect (non-interactive)
ocular --server vpn.example.com/group -- --base-mtu=1370

# Authenticate only
ocular --server vpn.example.com/group --authenticate shell
ocular --server vpn.example.com/group --authenticate json
```

## Important behavior

- Session auth is cached in `~/.ocular/config.toml` and reused until server rejection/expiry.
- Browser profile data is persisted in `~/.ocular/browser-profiles/` so IdP/browser cookies survive relaunch.
- Extra args after `--` are passed directly to `openconnect`.

## License

AGPL-3.0-only (`LICENSE`).
