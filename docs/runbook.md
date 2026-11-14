# Sigill runbook

Operational procedures for one Sigill host. Commands assume the systemd layout in
`deploy/` (`/etc/sigill/sigill.toml`, data in `/var/lib/sigill`).

## First install

1. Check the provider checklist in `PLAN.md`: outbound 25 open, PTR editable, dedicated IPv4s.
2. Install the binary to `/usr/local/bin/sigill`, Litestream to `/usr/local/bin/litestream`,
   and create the `sigill` user: `useradd --system --home /var/lib/sigill sigill`.
3. Copy `deploy/sigill.example.toml` to `/etc/sigill/sigill.toml` and fill in domains, IPs and
   host names. Generate secrets (mode 0600, owned by `sigill`):
   `head -c 48 /dev/urandom | base64 > /etc/sigill/master.key` and an admin password file.
   Back up the master key offline: losing it invalidates every API key, VERP address,
   unsubscribe link and webhook secret.
4. `sigill dkim-keygen` writes keys to `dkim_key_dir` and prints the DKIM TXT records.
5. Publish DNS (the admin DNS page lists every record): PTR for each IP matching its
   `helo_hostname`, SPF on the bounce domain, both DKIM records, DMARC with `p=none` and
   `rua=mailto:dmarc@<bounce domain>`, and an MX for the bounce domain pointing at
   `bounce.hostname`.
6. `sigill dns-check` until it reports no failures.
7. Install `deploy/litestream.yml` and the units, then
   `systemctl enable --now litestream sigill`.
8. `sigill app create --name <app> --webhook-url <url>` for each calling app; store the key.
9. Register `fbl@<bounce domain>` with Yahoo CFL and Microsoft JMRP/SNDS, and add the domains
   to Google Postmaster Tools.
10. Send a test to Gmail and Outlook accounts and confirm `dkim=pass spf=pass dmarc=pass` in
    the headers.

## IP warm-up

New IPs have no reputation. Per IP, per day:

| Day | Transactional | Broadcast |
| --- | --- | --- |
| 1–2 | 200 | 0 |
| 3–4 | 500 | 0 |
| 5–7 | 1 000 | 200 |
| 8–10 | 2 500 | 500 |
| 11–14 | 5 000 | 1 000 |
| then | double weekly while bounces stay under 2% and complaints under 0.1% | same |

Hold `broadcast.max_per_hour` low (for example 100) during warm-up and raise it in steps.
Send to the most engaged recipients first. If Gmail or Microsoft start deferring (see the
queue page: domains in backoff), stay at the current volume until deferrals stop.

## Moving DMARC to enforcement

Watch the admin DMARC page for two weeks. When every failing source is either fixed or not
yours, move `p=none` → `p=quarantine` (`pct=25`, then `100`) → `p=reject`.

## DKIM key rotation

1. Add a new selector: set `dkim_selector = "s2027"` for the domain in a copy of the config
   and run `sigill dkim-keygen --domain <domain>` against it; keys for the old selector stay.
2. Publish the new DKIM TXT records and wait for `sigill dns-check` to pass (allow for TTL).
3. Switch the live config to the new selector and restart: `systemctl restart sigill`.
4. Keep the old DNS records for at least a week (mail in flight and forwarded mail is still
   verified against them), then remove them and delete the old key files.

## Master key rotation

Rotating the master key changes every derived secret. Plan it: issue new API keys
(`sigill app rotate-key --id <id>`) and new webhook secrets (`sigill app set-webhook`) for
every app at the same time, and expect old unsubscribe links and in-flight VERP bounces to
stop matching. Only rotate when the key may have leaked.

## Blocklist response

1. Check the IP on Spamhaus, Barracuda and Microsoft SNDS. Look at the queue page for
   domains in backoff and at recent bounces (`last_response` mentions the list).
2. Stop the cause: pause broadcasts (cancel scheduled ones), and check recent complaint and
   bounce rates. A compromised app key shows up as unusual volume from one app: rotate it.
3. Fix what triggered the listing (purchased list, broken signup form, missing double opt-in).
4. Request delisting through each list's form. Microsoft: the sender support form; Gmail has
   no delisting, only Postmaster Tools reputation, which recovers with clean volume.
5. Resume slowly, as in warm-up.

## Alerts

Health checks run every 15 minutes and log an error (which becomes a Vaka issue) when the
queue backlog, the hourly bounce rate or one domain's deferrals cross the `[alerts]`
thresholds. Vaka alert rules on the `sigill` project turn new and regressed issues into
notifications.

- **Queue backlog:** check the queue page. Many deferred rows for one domain means that
  domain throttles us: lower its `max_per_minute` (`domain_throttle` table) and wait. Rows
  stuck in `queued` with nothing sending means the dispatcher is down: check
  `journalctl -u sigill`.
- **Bounce rate:** find the source (one app or one broadcast) via message search; a bad list
  import is the usual cause. Hard bounces are suppressed automatically.
- **Defer spike:** read `last_response` on recent deferrals for that domain; it names the
  reason (rate limit, reputation, greylisting).

## Backup and restore

Litestream replicates the database continuously. To restore onto a fresh host:

1. Install as in "First install" steps 2–3, including the same master key and DKIM keys
   (they are not in the database; keep them in your secrets store).
2. `litestream restore -config /etc/litestream.yml -o /var/lib/sigill/sigill.db /var/lib/sigill/sigill.db`
3. `chown sigill: /var/lib/sigill/sigill.db`, then `systemctl start litestream sigill`.
   Deliveries left in `sending` are put back in the queue on start.
4. Move the sending IPs to the new host, or update PTR, SPF and the bounce MX for new IPs and
   run `sigill dns-check`.

Practice it: `scripts/restore-drill.sh` runs the whole cycle against a local file replica and
checks that the restored database is intact and complete.

## Logs and debugging

- Logs are JSON on stdout (`journalctl -u sigill -o cat`); `SIGILL_LOG=info,sigill_mta=debug`
  turns on detail for one crate.
- Logs and Vaka never contain recipient addresses, subjects or bodies; search by message id,
  delivery id or recipient domain. The admin UI shows the addresses.
- `sigill vaka-test` sends a test event to check error reporting.
