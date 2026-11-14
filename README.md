# Sigill

Sigill (Swedish for *seal*, as in a wax seal on a letter) is a self-hosted email service for
transactional and broadcast mail, with its own MTA. It is written in Rust and stores everything
in a single SQLite file.

> **Status:** milestones M0–M5 are implemented. What is left before production is listed
> as unticked items in [PLAN.md](PLAN.md): setting up the Hetzner server, a manual inbox check
> and the restore drill on a real host. Vaka alert rules come later.

## What it does

- HTTP API for apps to send templated transactional mail, plus broadcast announcements
- Its own outbound MTA: MX lookup, SMTP over TLS, DKIM signing (RSA and Ed25519),
  per-domain throttling and retries
- Bounce and complaint handling with an automatic suppression list
- Small broadcast feature: contacts, consent records and one-click unsubscribe (RFC 8058)
- Delivery events sent back to your apps by signed webhooks

## What it is not

- Not a mailbox server: no IMAP/POP, and the only inbound mail is bounces and complaint reports
- Not multi-tenant: it is built to serve your own apps from your own servers and IPs
- Not a marketing-automation tool

## Stack

- Rust on Tokio, with `axum` for the HTTP API
- SQLite via `sqlx`, backed up continuously with Litestream
- Stalwart's mail crates: `mail-auth`, `mail-builder`, `mail-parser`, `smtp-proto`
- One binary, `sigill serve`, runs the API, delivery workers and bounce listener in one process

## Quick start (local)

```sh
docker compose up -d                       # Mailpit on :1025 / http://localhost:8025
cp deploy/sigill.example.toml sigill.toml  # set delivery.mode = "smarthost", local paths
export SIGILL_MASTER_KEY=$(head -c 48 /dev/urandom | base64)
cargo run -- dkim-keygen
cargo run -- app create --name myapp       # prints the API key
cargo run -- serve
```

Then `PUT /v1/templates/{key}` and `POST /v1/messages` with `Authorization: Bearer <key>`.
Operations are described in [docs/runbook.md](docs/runbook.md).

## Requirements for running it

Running your own MTA means a host that allows outbound port 25, dedicated IPv4 addresses with
reverse DNS (PTR) you control, and correct SPF, DKIM and DMARC records for your sending domains.
See the deliverability section of [PLAN.md](PLAN.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
