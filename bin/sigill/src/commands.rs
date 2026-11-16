//! One-shot CLI commands.

use anyhow::{Context, bail};
use clap::ArgMatches;
use sigill_core::secrets::Secrets;
use sigill_core::{Config, Stream};
use sigill_store::Store;

pub fn dkim_keygen(config: &Config, only: Option<&str>) -> anyhow::Result<()> {
    let domains: Vec<_> =
        config.domains.iter().filter(|d| only.is_none_or(|o| d.name.eq_ignore_ascii_case(o))).collect();
    if domains.is_empty() {
        bail!("no matching sending domain in the config ([[domains]] entries)");
    }
    for d in domains {
        let records = sigill_render::dkim::generate_keys(d).with_context(|| {
            format!("generating keys for {} (existing keys are never overwritten)", d.name)
        })?;
        println!("# {} (keys in {})", d.name, d.dkim_key_dir.display());
        for (selector, txt) in records {
            println!("{selector}._domainkey.{} IN TXT \"{}\"", d.name, txt);
        }
    }
    Ok(())
}

async fn open(config: &Config) -> anyhow::Result<Store> {
    Store::open(&config.database.path, 1).await.context("opening database")
}

fn secrets(config: &Config) -> anyhow::Result<Secrets> {
    Secrets::load(config.secrets.master_key_file.as_deref()).context("loading master key")
}

pub async fn app(config: &Config, m: &ArgMatches) -> anyhow::Result<()> {
    let store = open(config).await?;
    let secrets = secrets(config)?;
    let pepper = secrets.api_key_pepper();
    match m.subcommand() {
        Some(("create", m)) => {
            let name = m.get_one::<String>("name").expect("required");
            let stream: Stream = m.get_one::<String>("stream").expect("default").parse()?;
            let id = sigill_core::new_id();
            let (key, hash) = sigill_api::auth::generate_key(&id, &pepper);
            let webhook = m.get_one::<String>("webhook-url").map(String::as_str);
            if let Some(url) = webhook {
                check_webhook_url(url)?;
            }
            store.create_app(&id, name, &hash, webhook, stream).await?;
            println!("app id:          {id}");
            println!("API key:         {key}");
            println!("webhook secret:  {}", secrets.webhook_secret(&id, 0));
            println!("\nThe API key is shown only once; store it in your app's secrets.");
        }
        Some(("list", _)) => {
            for a in store.list_apps().await? {
                println!(
                    "{}  {}  stream={}  webhook={}",
                    a.id,
                    a.name,
                    a.default_stream,
                    a.webhook_url.as_deref().unwrap_or("-")
                );
            }
        }
        Some(("rotate-key", m)) => {
            let id = m.get_one::<String>("id").expect("required");
            let (key, hash) = sigill_api::auth::generate_key(id, &pepper);
            store.set_app_key_hash(id, &hash).await?;
            println!("new API key: {key}\nThe old key stops working at once.");
        }
        Some(("set-webhook", m)) => {
            let id = m.get_one::<String>("id").expect("required");
            let url = if m.get_flag("clear") { None } else { m.get_one::<String>("url").map(String::as_str) };
            if url.is_none() && !m.get_flag("clear") {
                bail!("give --url or --clear");
            }
            if let Some(url) = url {
                check_webhook_url(url)?;
            }
            store.set_app_webhook(id, url).await?;
            let app = store.get_app(id).await?.context("no such app")?;
            println!(
                "webhook updated; signing secret: {}",
                secrets.webhook_secret(id, app.webhook_secret_version)
            );
        }
        Some(("rotate-webhook-secret", m)) => {
            let id = m.get_one::<String>("id").expect("required");
            let version = store.bump_webhook_secret_version(id).await?;
            println!("new webhook signing secret: {}", secrets.webhook_secret(id, version));
            println!("Events are signed with it from now on; update the receiving app.");
        }
        _ => unreachable!("subcommand required"),
    }
    store.close().await;
    Ok(())
}

fn check_webhook_url(url: &str) -> anyhow::Result<()> {
    if !sigill_webhook::webhook_url_allowed(url) {
        bail!(
            "webhook URLs must be https (events carry recipient addresses); http is only allowed to localhost"
        );
    }
    Ok(())
}

pub async fn dns_check(config: &Config) -> anyhow::Result<()> {
    use sigill_mta::dnscheck::{self, ExpectedDkim, Status};
    let signers = sigill_render::Signers::load(&config.domains)
        .context("loading DKIM keys (run `sigill dkim-keygen` first)")?;
    let expected: Vec<ExpectedDkim> = config
        .domains
        .iter()
        .filter_map(|d| {
            let keys = signers.get(&d.name)?;
            Some(ExpectedDkim { domain: d.name.to_ascii_lowercase(), records: keys.dns_records.clone() })
        })
        .collect();
    let resolver = sigill_mta::dns::HickoryResolver::from_system().context("DNS resolver")?;
    let checks = dnscheck::run(config, &expected, &resolver).await;
    for c in &checks {
        println!("{c}");
    }
    // Record domains whose checks all pass, for the admin DNS view.
    if let Ok(store) = open(config).await {
        for d in &config.domains {
            let rp = d.return_path_domain.to_ascii_lowercase();
            let name = d.name.to_ascii_lowercase();
            let mine = checks.iter().filter(|c| c.name.contains(&name) || c.name == rp);
            let ok = mine.clone().count() > 0 && mine.clone().all(|c| c.status != Status::Fail);
            store.mark_domain_verified(&name, ok.then(sigill_core::now_ms)).await?;
        }
        store.close().await;
    }
    let failed = checks.iter().filter(|c| c.status == Status::Fail).count();
    let warned = checks.iter().filter(|c| c.status == Status::Warn).count();
    println!("\n{} checks: {} failed, {} warnings", checks.len(), failed, warned);
    if failed > 0 {
        bail!("{failed} DNS checks failed");
    }
    Ok(())
}
