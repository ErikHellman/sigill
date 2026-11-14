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
            store.create_app(&id, name, &hash, webhook, stream).await?;
            println!("app id:          {id}");
            println!("API key:         {key}");
            println!("webhook secret:  {}", secrets.webhook_secret(&id));
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
            println!("new API key: {key}\n(restart `sigill serve` to drop cached old keys)");
        }
        Some(("set-webhook", m)) => {
            let id = m.get_one::<String>("id").expect("required");
            let url = if m.get_flag("clear") { None } else { m.get_one::<String>("url").map(String::as_str) };
            if url.is_none() && !m.get_flag("clear") {
                bail!("give --url or --clear");
            }
            store.set_app_webhook(id, url).await?;
            println!("webhook updated; signing secret: {}", secrets.webhook_secret(id));
        }
        _ => unreachable!("subcommand required"),
    }
    store.close().await;
    Ok(())
}
