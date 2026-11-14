# CLAUDE.md

Sigill is a self-hosted email service for transactional and broadcast mail with its own MTA,
written in Rust with SQLite. It serves the owner's own apps (single tenant).

## Start here

- `PLAN.md` is the source of truth: scope, architecture, crates, data model, component specs,
  milestones and open decisions. Read it before starting work.
- Work milestone by milestone (M0 → M5). Finish and verify one milestone before starting the next,
  and tick its checkboxes in `PLAN.md` in the same change.
- If an implementation needs to deviate from `PLAN.md`, update the plan in the same change and say
  why in the commit message.
- Items under "Open decisions" in `PLAN.md` are not yours to settle silently: ask before choosing,
  and record the decision in `PLAN.md`.

## Commands

Once the workspace exists (M0):

- `cargo check --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` in the inner loop
- `cargo nextest run --workspace` for tests (`cargo test --doc` for doc tests)
- `cargo fmt --all` before committing
- `SQLX_OFFLINE=true` for builds; run `cargo sqlx prepare --workspace` after changing queries and
  commit `.sqlx/`
- `docker compose up` starts Mailpit for local end-to-end sends

## Rules

- Fast builds are a requirement: follow the build-speed rules in `PLAN.md`. Don't add a dependency
  without a reason, keep `default-features = false` where possible, and keep heavy crates out of
  crates that don't need them.
- Check a crate's current version and API (Context7 or docs.rs) before using it; don't rely on memory.
- Tests must not touch real mail servers or the internet. Use the in-repo fake SMTP server and a
  temp-file SQLite database per test.
- Never log or send recipient addresses, subjects or message bodies to Vaka. Use ids and
  recipient domains instead.
- Secrets (DKIM keys, API key pepper, webhook secrets, `VAKA_KEY`) come from env vars or files,
  never from the repo or the database in plain text.
- Every code change that changes behaviour comes with tests.

## License

Dual licensed MIT OR Apache-2.0. New crates set `license = "MIT OR Apache-2.0"` in `Cargo.toml`.
