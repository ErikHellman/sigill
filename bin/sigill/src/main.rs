//! `sigill`: one binary for the API, delivery workers and bounce listener.

mod commands;
mod serve;
mod telemetry;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Arg, ArgAction, ArgMatches, Command};
use sigill_core::Config;

fn cli() -> Command {
    Command::new("sigill")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Self-hosted transactional and broadcast email service")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .global(true)
                .env("SIGILL_CONFIG")
                .default_value("sigill.toml")
                .help("Path to the TOML config file"),
        )
        .subcommand_required(true)
        .subcommand(Command::new("serve").about("Run the API, delivery workers and bounce listener"))
        .subcommand(Command::new("migrate").about("Apply database migrations"))
        .subcommand(
            Command::new("dkim-keygen")
                .about("Generate DKIM keys (RSA-2048 and Ed25519) for configured domains and print the DNS records")
                .arg(Arg::new("domain").long("domain").help("Only this sending domain")),
        )
        .subcommand(
            Command::new("app")
                .about("Manage calling apps and API keys")
                .subcommand_required(true)
                .subcommand(
                    Command::new("create")
                        .about("Create an app and print its API key and webhook secret")
                        .arg(Arg::new("name").long("name").required(true))
                        .arg(Arg::new("webhook-url").long("webhook-url"))
                        .arg(
                            Arg::new("stream")
                                .long("stream")
                                .default_value("transactional")
                                .value_parser(["transactional", "broadcast"]),
                        ),
                )
                .subcommand(Command::new("list").about("List apps"))
                .subcommand(
                    Command::new("rotate-key")
                        .about("Issue a new API key (the old one stops working)")
                        .arg(Arg::new("id").long("id").required(true)),
                )
                .subcommand(
                    Command::new("set-webhook")
                        .about("Set or clear an app's webhook URL")
                        .arg(Arg::new("id").long("id").required(true))
                        .arg(Arg::new("url").long("url"))
                        .arg(Arg::new("clear").long("clear").action(ArgAction::SetTrue)),
                ),
        )
        .subcommand(Command::new("vaka-test").about("Send a test event to Vaka to verify error reporting"))
}

fn load_config(m: &ArgMatches) -> anyhow::Result<Config> {
    let path = PathBuf::from(m.get_one::<String>("config").expect("has default"));
    let path = path.exists().then_some(path);
    Config::load(path.as_deref()).context("loading configuration")
}

fn main() -> anyhow::Result<()> {
    let _vaka = telemetry::init_vaka();
    telemetry::init_tracing();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let matches = cli().get_matches();
    if let Some(("vaka-test", _)) = matches.subcommand() {
        vaka_sdk::capture_message("sigill vaka install test", vaka_sdk::Level::Info);
        let flushed = vaka_sdk::flush(std::time::Duration::from_secs(10));
        println!(
            "test event {} (set VAKA_DEBUG=1 to see send errors)",
            if flushed { "flushed" } else { "not flushed: is VAKA_KEY set?" }
        );
        return Ok(());
    }
    let config = load_config(&matches)?;
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let result = rt.block_on(async {
        match matches.subcommand() {
            Some(("serve", _)) => serve::serve(config).await,
            Some(("migrate", _)) => {
                sigill_store::Store::migrate(&config.database.path).await?;
                println!("migrations applied to {}", config.database.path.display());
                Ok(())
            }
            Some(("dkim-keygen", m)) => {
                commands::dkim_keygen(&config, m.get_one::<String>("domain").map(String::as_str))
            }
            Some(("app", m)) => commands::app(&config, m).await,
            _ => unreachable!("subcommand required"),
        }
    });
    if let Err(e) = &result {
        tracing::error!(error = %format!("{e:#}"), "sigill exited with an error");
    }
    result
}
