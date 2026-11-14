-- Sigill initial schema. Ids are UUIDv7 text, timestamps are unix milliseconds,
-- JSON lives in TEXT columns.

CREATE TABLE apps (
    id              TEXT PRIMARY KEY NOT NULL,
    name            TEXT NOT NULL UNIQUE,
    api_key_hash    TEXT NOT NULL,
    webhook_url     TEXT,
    default_stream  TEXT NOT NULL DEFAULT 'transactional'
                    CHECK (default_stream IN ('transactional', 'broadcast')),
    created_at      INTEGER NOT NULL
) STRICT;

-- Sending domains, mirrored from the config file at startup. DKIM private keys stay in
-- files on disk; only the public keys are recorded here.
CREATE TABLE sending_domains (
    domain              TEXT PRIMARY KEY NOT NULL,
    stream              TEXT NOT NULL CHECK (stream IN ('transactional', 'broadcast')),
    dkim_selector       TEXT NOT NULL,
    dkim_public_keys    TEXT NOT NULL DEFAULT '{}',
    return_path_domain  TEXT NOT NULL,
    verified_at         INTEGER
) STRICT;

CREATE TABLE ip_pools (
    name            TEXT PRIMARY KEY NOT NULL CHECK (name IN ('transactional', 'broadcast')),
    ips             TEXT NOT NULL DEFAULT '[]',
    helo_hostname   TEXT NOT NULL
) STRICT;

CREATE TABLE templates (
    app_id      TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    key         TEXT NOT NULL,
    version     INTEGER NOT NULL,
    subject_tpl TEXT NOT NULL,
    html_tpl    TEXT NOT NULL,
    text_tpl    TEXT NOT NULL,
    mjml_src    TEXT,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (app_id, key, version)
) STRICT;

CREATE TABLE broadcasts (
    id              TEXT PRIMARY KEY NOT NULL,
    app_id          TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    template_key    TEXT NOT NULL,
    template_version INTEGER,
    list            TEXT NOT NULL,
    from_addr       TEXT,
    variables       TEXT NOT NULL DEFAULT '{}',
    segment_query   TEXT NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'draft'
                    CHECK (status IN ('draft', 'scheduled', 'sending', 'finished', 'cancelled')),
    scheduled_at    INTEGER,
    started_at      INTEGER,
    finished_at     INTEGER,
    audience_count  INTEGER NOT NULL DEFAULT 0,
    sent_count      INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL
) STRICT;

CREATE TABLE messages (
    id                  TEXT PRIMARY KEY NOT NULL,
    app_id              TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    idempotency_key     TEXT,
    stream              TEXT NOT NULL CHECK (stream IN ('transactional', 'broadcast')),
    template_key        TEXT NOT NULL,
    template_version    INTEGER NOT NULL,
    from_addr           TEXT NOT NULL,
    subject             TEXT NOT NULL,
    rendered_mime       BLOB,
    broadcast_id        TEXT REFERENCES broadcasts(id) ON DELETE SET NULL,
    created_at          INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX messages_idempotency ON messages(app_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX messages_created ON messages(created_at);
CREATE INDEX messages_broadcast ON messages(broadcast_id) WHERE broadcast_id IS NOT NULL;

CREATE TABLE deliveries (
    id              TEXT PRIMARY KEY NOT NULL,
    message_id      TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    stream          TEXT NOT NULL CHECK (stream IN ('transactional', 'broadcast')),
    rcpt            TEXT NOT NULL,
    rcpt_domain     TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'sending', 'sent', 'deferred', 'bounced', 'failed', 'suppressed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    last_smtp_code  INTEGER,
    last_response   TEXT,
    priority        INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
) STRICT;

CREATE INDEX deliveries_queue ON deliveries(status, next_attempt_at, priority);
CREATE INDEX deliveries_message ON deliveries(message_id);
CREATE INDEX deliveries_rcpt ON deliveries(rcpt);

CREATE TABLE delivery_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_id TEXT NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL
                CHECK (kind IN ('queued', 'sent', 'deferred', 'bounced', 'complained', 'failed', 'suppressed', 'unsubscribed')),
    detail      TEXT,
    at          INTEGER NOT NULL
) STRICT;

CREATE INDEX delivery_events_delivery ON delivery_events(delivery_id);
CREATE INDEX delivery_events_at ON delivery_events(at);

CREATE TABLE suppressions (
    address             TEXT NOT NULL,
    scope               TEXT NOT NULL CHECK (scope IN ('all', 'broadcast')),
    reason              TEXT NOT NULL
                        CHECK (reason IN ('hard_bounce', 'soft_bounce', 'complaint', 'unsubscribe', 'manual')),
    source_delivery_id  TEXT,
    created_at          INTEGER NOT NULL,
    PRIMARY KEY (address, scope)
) STRICT;

CREATE INDEX suppressions_address ON suppressions(address);

-- Soft bounces counted per address; 5 in 30 days suppresses the address.
CREATE TABLE soft_bounces (
    address     TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    at          INTEGER NOT NULL
) STRICT;

CREATE INDEX soft_bounces_address ON soft_bounces(address, at);

CREATE TABLE contacts (
    id          TEXT PRIMARY KEY NOT NULL,
    app_id      TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    name        TEXT,
    attributes  TEXT NOT NULL DEFAULT '{}',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    UNIQUE (app_id, email)
) STRICT;

CREATE TABLE consents (
    contact_id  TEXT NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    list        TEXT NOT NULL,
    granted_at  INTEGER NOT NULL,
    source      TEXT NOT NULL,
    revoked_at  INTEGER,
    PRIMARY KEY (contact_id, list)
) STRICT;

CREATE INDEX consents_list ON consents(list, revoked_at);

CREATE TABLE domain_throttle (
    rcpt_domain     TEXT PRIMARY KEY NOT NULL,
    max_conns       INTEGER NOT NULL,
    max_per_minute  INTEGER NOT NULL,
    backoff_until   INTEGER
) STRICT;

-- Conservative defaults for the big mailbox providers.
INSERT INTO domain_throttle (rcpt_domain, max_conns, max_per_minute) VALUES
    ('gmail.com', 5, 120),
    ('googlemail.com', 5, 120),
    ('outlook.com', 3, 60),
    ('hotmail.com', 3, 60),
    ('live.com', 3, 60),
    ('msn.com', 3, 60),
    ('yahoo.com', 3, 60),
    ('ymail.com', 3, 60),
    ('aol.com', 3, 60);

CREATE TABLE webhook_outbox (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id          TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    payload         TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    last_error      TEXT,
    created_at      INTEGER NOT NULL
) STRICT;

CREATE INDEX webhook_outbox_due ON webhook_outbox(next_attempt_at);

CREATE TABLE dmarc_reports (
    id              TEXT PRIMARY KEY NOT NULL,
    org_name        TEXT NOT NULL,
    report_id       TEXT NOT NULL,
    domain          TEXT NOT NULL,
    date_begin      INTEGER NOT NULL,
    date_end        INTEGER NOT NULL,
    policy          TEXT NOT NULL,
    total_count     INTEGER NOT NULL,
    fail_count      INTEGER NOT NULL,
    received_at     INTEGER NOT NULL,
    UNIQUE (org_name, report_id)
) STRICT;

CREATE TABLE dmarc_records (
    report_id       TEXT NOT NULL REFERENCES dmarc_reports(id) ON DELETE CASCADE,
    source_ip       TEXT NOT NULL,
    count           INTEGER NOT NULL,
    disposition     TEXT NOT NULL,
    dkim_result     TEXT NOT NULL,
    spf_result      TEXT NOT NULL,
    header_from     TEXT NOT NULL
) STRICT;

CREATE INDEX dmarc_records_report ON dmarc_records(report_id);
