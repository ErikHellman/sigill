//! `sigill serve`: API, dispatcher and background jobs in one process.

use std::sync::Arc;

use anyhow::Context;
use sigill_core::secrets::Secrets;
use sigill_core::{Config, Stream};
use sigill_mta::dns::HickoryResolver;
use sigill_mta::mta_sts::HttpsFetcher;
use sigill_mta::{Dispatcher, Mta};
use sigill_render::Signers;
use sigill_store::Store;
use sigill_store::setup::SendingDomain;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

pub async fn serve(config: Config) -> anyhow::Result<()> {
    let config = Arc::new(config);
    let secrets = Secrets::load(config.secrets.master_key_file.as_deref()).context("loading master key")?;
    let signers =
        Signers::load(&config.domains).context("loading DKIM keys (run `sigill dkim-keygen` first)")?;
    let store = Store::open(&config.database.path, config.database.read_connections)
        .await
        .context("opening database")?;
    sync_setup(&store, &config, &signers).await?;

    let shutdown = CancellationToken::new();
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            wait_for_signal().await;
            tracing::info!("shutdown requested");
            shutdown.cancel();
        });
    }

    let wake = Arc::new(Notify::new());
    let resolver = Arc::new(HickoryResolver::from_system().context("DNS resolver")?);
    let fetcher = Arc::new(HttpsFetcher::new().context("HTTP client")?);
    let mta = Arc::new(Mta::new(store.clone(), config.clone(), resolver, fetcher, secrets.verp_key()));
    let webhooks = sigill_webhook::WebhookWorker::new(store.clone(), secrets.clone(), &config.webhooks)
        .context("webhook HTTP client")?;
    let bounce = if config.bounce.enabled {
        let tls = match (&config.bounce.tls_cert, &config.bounce.tls_key) {
            (Some(cert), Some(key)) => Some(sigill_bounce::load_tls(cert, key).context("bounce TLS")?),
            _ => None,
        };
        let listener = tokio::net::TcpListener::bind(config.bounce.listen)
            .await
            .with_context(|| format!("binding bounce listener on {}", config.bounce.listen))?;
        let settings = sigill_bounce::Settings::new(&config.bounce, config.bounce_domains());
        let processor = sigill_bounce::Processor::new(store.clone(), secrets.verp_key());
        Some((sigill_bounce::Listener::new(settings, processor, secrets.verp_key(), tls), listener))
    } else {
        None
    };
    let state = sigill_api::AppState::new(store.clone(), config.clone(), secrets, signers, wake.clone());

    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(Dispatcher::new(mta, wake).run(shutdown.clone()));
    tasks.spawn(webhooks.run(shutdown.clone()));
    tasks.spawn(crate::jobs::maintenance(store.clone(), config.clone(), shutdown.clone()));
    tasks.spawn(sigill_api::BroadcastScheduler::new(state.clone()).run(shutdown.clone()));
    if let Some((bounce, listener)) = bounce {
        tasks.spawn(bounce.run(listener, shutdown.clone()));
    }
    {
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            if let Err(e) = sigill_api::serve(state, shutdown.clone()).await {
                tracing::error!(error = %e, "HTTP API failed");
                shutdown.cancel();
            }
        });
    }
    while let Some(r) = tasks.join_next().await {
        if let Err(e) = r {
            tracing::error!(error = %e, "task panicked");
            shutdown.cancel();
        }
    }
    store.close().await;
    tracing::info!("stopped");
    Ok(())
}

async fn sync_setup(store: &Store, config: &Config, signers: &Signers) -> anyhow::Result<()> {
    let domains: Vec<SendingDomain> = config
        .domains
        .iter()
        .map(|d| SendingDomain {
            domain: d.name.to_ascii_lowercase(),
            stream: d.stream.to_string(),
            dkim_selector: d.dkim_selector.clone(),
            dkim_public_keys: signers
                .get(&d.name)
                .map(|k| serde_json::to_string(&k.dns_records).expect("strings serialise"))
                .unwrap_or_else(|| "[]".into()),
            return_path_domain: d.return_path_domain.clone(),
            verified_at: None,
        })
        .collect();
    store.sync_sending_domains(&domains).await?;
    for s in Stream::ALL {
        let c = config.streams.get(*s);
        let ips: Vec<String> = c.ips.iter().map(ToString::to_string).collect();
        store.sync_ip_pool(s.as_str(), &ips, &c.helo_hostname).await?;
    }
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
