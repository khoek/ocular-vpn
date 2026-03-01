# ocular-vpn

Minimal CLI SSO helper for `openconnect` (Cisco AnyConnect-style login).

## Requirements
- `openconnect`
- Chrome/Chromium (or `--chrome-path`)

## Install
```sh
cargo install ocular-vpn
```

## Usage
```sh
ocular
ocular --server vpn.example.com/group -- --base-mtu=1370
ocular --server vpn.example.com/group --authenticate shell
ocular --server vpn.example.com/group --authenticate json
```

## License
AGPL-3.0-only (`LICENSE`).
