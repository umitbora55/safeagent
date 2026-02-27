#![allow(dead_code)]

use tokio::signal;
use tokio::sync::broadcast;
use tracing::info;

/// Graceful shutdown handler.
/// Listens for SIGTERM/SIGINT and notifies all components.
pub struct ShutdownSignal {
    tx: broadcast::Sender<()>,
}

impl ShutdownSignal {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1);
        Self { tx }
    }

    /// Get a receiver that will be notified on shutdown
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.tx.subscribe()
    }

    /// Wait for shutdown signal, then notify all subscribers
    pub async fn wait_for_shutdown(&self) {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                info!("📴 Received Ctrl+C, initiating graceful shutdown...");
            }
            _ = terminate => {
                info!("📴 Received SIGTERM, initiating graceful shutdown...");
            }
        }

        let _ = self.tx.send(());
        info!("📴 Shutdown signal sent to all components");
    }
}

/// Run cleanup tasks before exit
pub async fn cleanup(data_dir: &std::path::Path) {
    info!("🧹 Running cleanup tasks...");

    // Flush any pending writes
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Save shutdown timestamp
    let shutdown_file = data_dir.join("last_shutdown");
    let timestamp = chrono::Utc::now().to_rfc3339();
    let _ = std::fs::write(&shutdown_file, &timestamp);

    info!("✅ Cleanup complete. SafeAgent stopped at {}", timestamp);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_subscribe() {
        let signal = ShutdownSignal::new();
        let mut rx = signal.subscribe();

        // Send shutdown
        let _ = signal.tx.send(());

        // Receiver gets it
        assert!(rx.recv().await.is_ok());
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let signal = ShutdownSignal::new();
        let mut rx1 = signal.subscribe();
        let mut rx2 = signal.subscribe();

        let _ = signal.tx.send(());

        assert!(rx1.recv().await.is_ok());
        assert!(rx2.recv().await.is_ok());
    }

    #[tokio::test]
    async fn test_cleanup() {
        let dir = std::env::temp_dir().join(format!(
            "safeagent_shutdown_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        cleanup(&dir).await;

        assert!(dir.join("last_shutdown").exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
