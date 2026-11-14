//! `sigill`: one binary for the API, delivery workers and bounce listener.

mod telemetry;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Arg, ArgMatches, Command};
use sigill_core::Config;
use sigill_store::Store;
use tokio_util::sync::CancellationToken;

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
            Some(("serve", _)) => serve(config).await,
            Some(("migrate", _)) => {
                Store::migrate(&config.database.path).await?;
                println!("migrations applied to {}", config.database.path.display());
                Ok(())
            }
            _ => unreachable!("subcommand required"),
        }
    });
    if let Err(e) = &result {
        tracing::error!(error = %format!("{e:#}"), "sigill exited with an error");
    }
    result
}

async fn serve(config: Config) -> anyhow::Result<()> {
    let config = Arc::new(config);
    let store = Store::open(&config.database.path, config.database.read_connections)
        .await
        .context("opening database")?;
    let shutdown = CancellationToken::new();
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            wait_for_signal().await;
            tracing::info!("shutdown requested");
            shutdown.cancel();
        });
    }
    let state = sigill_api::AppState { store: store.clone(), config: config.clone() };
    sigill_api::serve(state, shutdown.clone()).await?;
    store.close().await;
    Ok(())
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
