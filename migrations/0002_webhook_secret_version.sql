-- Each app's webhook signing secret is derived from the master key, the app id and this
-- version, so one app's secret can be rotated without changing the master key.
ALTER TABLE apps ADD COLUMN webhook_secret_version INTEGER NOT NULL DEFAULT 0;
