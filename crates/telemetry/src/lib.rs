//! OpenTelemetry Telemetry (G4 Security Feature)
//!
//! Provides:
//! - OTLP trace export
//! - Configurable endpoint
//! - Graceful shutdown
//! - Integration with tracing crate

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    runtime,
    trace::{RandomIdGenerator, Sampler, TracerProvider},
    Resource,
};
use std::time::Duration;
use thiserror::Error;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Default OTLP endpoint.
const DEFAULT_OTLP_ENDPOINT: &str = "http://localhost:4317";

/// Default service name.
const DEFAULT_SERVICE_NAME: &str = "safeagent";

/// Telemetry configuration errors.
#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("Failed to initialize OTLP exporter: {0}")]
    ExporterInit(String),

    #[error("Failed to initialize tracer provider: {0}")]
    TracerInit(String),

    #[error("Failed to initialize subscriber: {0}")]
    SubscriberInit(String),
}

/// Telemetry configuration.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// OTLP endpoint (default: http://localhost:4317)
    pub endpoint: String,

    /// Service name for traces
    pub service_name: String,

    /// Service version
    pub service_version: String,

    /// Environment (e.g., "production", "staging", "development")
    pub environment: String,

    /// Sample ratio (0.0 to 1.0)
    pub sample_ratio: f64,

    /// Export timeout in seconds
    pub timeout_secs: u64,

    /// Whether to also log to console
    pub console_logging: bool,

    /// Log filter (e.g., "info", "safeagent=debug")
    pub log_filter: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_OTLP_ENDPOINT.to_string(),
            service_name: DEFAULT_SERVICE_NAME.to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            environment: "development".to_string(),
            sample_ratio: 1.0,
            timeout_secs: 10,
            console_logging: true,
            log_filter: "info".to_string(),
        }
    }
}

impl TelemetryConfig {
    /// Create config for production (lower sample ratio, no console logging).
    pub fn production() -> Self {
        Self {
            sample_ratio: 0.1, // Sample 10% of traces
            console_logging: false,
            environment: "production".to_string(),
            ..Default::default()
        }
    }

    /// Create config for testing (full sampling, console logging).
    pub fn testing() -> Self {
        Self {
            sample_ratio: 1.0,
            console_logging: true,
            environment: "testing".to_string(),
            log_filter: "debug".to_string(),
            ..Default::default()
        }
    }

    /// Set the OTLP endpoint.
    pub fn with_endpoint(mut self, endpoint: &str) -> Self {
        self.endpoint = endpoint.to_string();
        self
    }

    /// Set the service name.
    pub fn with_service_name(mut self, name: &str) -> Self {
        self.service_name = name.to_string();
        self
    }

    /// Set the environment.
    pub fn with_environment(mut self, env: &str) -> Self {
        self.environment = env.to_string();
        self
    }

    /// Set the sample ratio.
    pub fn with_sample_ratio(mut self, ratio: f64) -> Self {
        self.sample_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    /// Enable or disable console logging.
    pub fn with_console_logging(mut self, enabled: bool) -> Self {
        self.console_logging = enabled;
        self
    }

    /// Set the log filter.
    pub fn with_log_filter(mut self, filter: &str) -> Self {
        self.log_filter = filter.to_string();
        self
    }
}

/// Handle for the telemetry system.
///
/// Drop this handle to gracefully shutdown telemetry.
pub struct TelemetryHandle {
    tracer_provider: TracerProvider,
}

impl TelemetryHandle {
    /// Shutdown telemetry and flush any pending spans.
    pub fn shutdown(self) {
        info!("Shutting down telemetry...");
        if let Err(e) = self.tracer_provider.shutdown() {
            tracing::error!("Failed to shutdown tracer provider: {:?}", e);
        }
    }
}

/// Initialize OpenTelemetry with OTLP export.
///
/// This sets up:
/// - OTLP gRPC exporter
/// - Tracer provider with configured sampling
/// - Tracing subscriber integration
///
/// Returns a handle that should be kept alive for the duration of the application.
/// When dropped, it will flush pending spans.
pub fn init_telemetry(config: TelemetryConfig) -> Result<TelemetryHandle, TelemetryError> {
    // Create resource with service metadata
    let resource = Resource::new([
        KeyValue::new("service.name", config.service_name.clone()),
        KeyValue::new("service.version", config.service_version.clone()),
        KeyValue::new("deployment.environment", config.environment.clone()),
    ]);

    // Create OTLP exporter
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&config.endpoint)
        .with_timeout(Duration::from_secs(config.timeout_secs))
        .build()
        .map_err(|e| TelemetryError::ExporterInit(e.to_string()))?;

    // Create tracer provider
    let sampler = if config.sample_ratio >= 1.0 {
        Sampler::AlwaysOn
    } else if config.sample_ratio <= 0.0 {
        Sampler::AlwaysOff
    } else {
        Sampler::TraceIdRatioBased(config.sample_ratio)
    };

    let tracer_provider = TracerProvider::builder()
        .with_batch_exporter(exporter, runtime::Tokio)
        .with_sampler(sampler)
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource)
        .build();

    // Create OpenTelemetry layer for tracing
    let tracer = tracer_provider.tracer(config.service_name.clone());
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    // Create env filter
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_filter));

    // Build subscriber
    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(otel_layer);

    if config.console_logging {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_thread_ids(true);
        subscriber
            .with(fmt_layer)
            .try_init()
            .map_err(|e| TelemetryError::SubscriberInit(e.to_string()))?;
    } else {
        subscriber
            .try_init()
            .map_err(|e| TelemetryError::SubscriberInit(e.to_string()))?;
    }

    info!(
        service = %config.service_name,
        endpoint = %config.endpoint,
        environment = %config.environment,
        "OpenTelemetry initialized"
    );

    Ok(TelemetryHandle { tracer_provider })
}

/// Initialize telemetry with default configuration.
///
/// Useful for quick setup in development.
pub fn init_default_telemetry() -> Result<TelemetryHandle, TelemetryError> {
    init_telemetry(TelemetryConfig::default())
}

/// Check if an OTLP collector is reachable at the given endpoint.
///
/// This is a simple connectivity check that doesn't require authentication.
pub async fn check_otlp_connectivity(endpoint: &str) -> bool {
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    // Parse endpoint to get host:port
    let addr = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .unwrap_or(endpoint);

    // Try to connect with a timeout
    matches!(
        timeout(Duration::from_secs(5), TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

/// Span helper for creating traced operations.
#[macro_export]
macro_rules! traced_operation {
    ($name:expr, $($field:tt)*) => {
        tracing::info_span!($name, $($field)*)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests don't actually connect to an OTLP collector,
    // they test the configuration and initialization logic.

    #[test]
    fn test_default_config() {
        let config = TelemetryConfig::default();
        assert_eq!(config.endpoint, DEFAULT_OTLP_ENDPOINT);
        assert_eq!(config.service_name, DEFAULT_SERVICE_NAME);
        assert_eq!(config.sample_ratio, 1.0);
        assert!(config.console_logging);
    }

    #[test]
    fn test_production_config() {
        let config = TelemetryConfig::production();
        assert_eq!(config.sample_ratio, 0.1);
        assert!(!config.console_logging);
        assert_eq!(config.environment, "production");
    }

    #[test]
    fn test_testing_config() {
        let config = TelemetryConfig::testing();
        assert_eq!(config.sample_ratio, 1.0);
        assert!(config.console_logging);
        assert_eq!(config.environment, "testing");
        assert_eq!(config.log_filter, "debug");
    }

    #[test]
    fn test_config_builder() {
        let config = TelemetryConfig::default()
            .with_endpoint("http://otel-collector:4317")
            .with_service_name("my-service")
            .with_environment("staging")
            .with_sample_ratio(0.5)
            .with_console_logging(false)
            .with_log_filter("warn");

        assert_eq!(config.endpoint, "http://otel-collector:4317");
        assert_eq!(config.service_name, "my-service");
        assert_eq!(config.environment, "staging");
        assert_eq!(config.sample_ratio, 0.5);
        assert!(!config.console_logging);
        assert_eq!(config.log_filter, "warn");
    }

    #[test]
    fn test_sample_ratio_clamping() {
        let config = TelemetryConfig::default().with_sample_ratio(1.5);
        assert_eq!(config.sample_ratio, 1.0);

        let config = TelemetryConfig::default().with_sample_ratio(-0.5);
        assert_eq!(config.sample_ratio, 0.0);
    }

    #[tokio::test]
    async fn test_connectivity_check_unreachable() {
        // Test with a non-existent endpoint
        let result = check_otlp_connectivity("localhost:19999").await;
        assert!(!result);
    }

    // Integration test that requires a running OTLP collector
    // This test is ignored by default since it requires external infrastructure
    #[tokio::test]
    #[ignore = "Requires running OTLP collector"]
    async fn test_init_telemetry_with_collector() {
        let config = TelemetryConfig::testing().with_endpoint("http://localhost:4317");

        let handle = init_telemetry(config);
        assert!(handle.is_ok());

        // Create some spans
        {
            let _span = tracing::info_span!("test_operation").entered();
            tracing::info!("Test event");
        }

        // Shutdown gracefully
        // Avoid blocking on tracer provider drop in CI smoke tests.
        if let Ok(handle) = handle {
            std::mem::forget(handle);
        }
    }

    // Deterministic smoke test for CI/local verify gate.
    #[tokio::test]
    #[ignore = "Requires running OTLP collector"]
    async fn otel_smoke_test() {
        let endpoint = "http://localhost:4317";
        assert!(
            check_otlp_connectivity(endpoint).await,
            "OTLP collector not reachable at {}",
            endpoint
        );
    }

    // Smoke test that verifies the config can be created and is valid
    #[test]
    fn smoke_test_config_creation() {
        let configs = vec![
            TelemetryConfig::default(),
            TelemetryConfig::production(),
            TelemetryConfig::testing(),
            TelemetryConfig::default()
                .with_endpoint("http://custom:4317")
                .with_service_name("custom-service")
                .with_environment("custom-env")
                .with_sample_ratio(0.25)
                .with_console_logging(false)
                .with_log_filter("debug"),
        ];

        for config in configs {
            assert!(!config.endpoint.is_empty());
            assert!(!config.service_name.is_empty());
            assert!(!config.environment.is_empty());
            assert!(config.sample_ratio >= 0.0 && config.sample_ratio <= 1.0);
            assert!(!config.log_filter.is_empty());
        }
    }
}
