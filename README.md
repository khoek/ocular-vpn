# ocular-vpn

Minimal CLI SSO helper for `openconnect` (Cisco AnyConnect-style login).

## Requirements
- Chrome/Chromium (or `--chrome-path`)
- Native build prerequisites for `openconnect-core` / `openconnect-sys` (see crate docs)

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
