//! W18: Platform Marketplace GA
//!
//! SafeAgent marketplace v2: plugin/connector registry, partner API,
//! white-label SDK configuration, usage-based pricing billing engine,
//! and GA release hardening metrics.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{info, warn};
use uuid::Uuid;

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum MarketplaceError {
    #[error("plugin '{0}' not found in marketplace")]
    PluginNotFound(String),
    #[error("publisher '{0}' not authorized")]
    UnauthorizedPublisher(String),
    #[error("billing account '{0}' not found")]
    AccountNotFound(String),
    #[error("insufficient credits: required {required}, available {available}")]
    InsufficientCredits { required: f64, available: f64 },
    #[error("plugin '{0}' failed security scan: {1}")]
    SecurityScanFailed(String, String),
}

// ── Plugin / Connector ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginCategory {
    LlmConnector,
    ToolBridge,
    SecurityPolicy,
    Compliance,
    Observability,
    DataConnector,
    WorkflowAutomation,
    Custom,
}

impl PluginCategory {
    pub fn label(&self) -> &'static str {
        match self {
            PluginCategory::LlmConnector => "llm-connector",
            PluginCategory::ToolBridge => "tool-bridge",
            PluginCategory::SecurityPolicy => "security-policy",
            PluginCategory::Compliance => "compliance",
            PluginCategory::Observability => "observability",
            PluginCategory::DataConnector => "data-connector",
            PluginCategory::WorkflowAutomation => "workflow-automation",
            PluginCategory::Custom => "custom",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublishStatus {
    Draft,
    PendingReview,
    Published,
    Deprecated,
    Suspended,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplacePlugin {
    pub plugin_id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub publisher_id: String,
    pub category: PluginCategory,
    pub status: PublishStatus,
    pub pricing: PricingModel,
    pub manifest_url: String,
    pub source_hash: String,
    pub security_scan_passed: bool,
    pub downloads: u64,
    pub rating: f32, // 0.0 - 5.0
    pub published_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub tags: Vec<String>,
    pub capabilities: Vec<String>,
}

impl MarketplacePlugin {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        version: impl Into<String>,
        publisher_id: impl Into<String>,
        category: PluginCategory,
    ) -> Self {
        let now = Utc::now();
        Self {
            plugin_id: Uuid::new_v4().to_string(),
            name: name.into(),
            description: description.into(),
            version: version.into(),
            publisher_id: publisher_id.into(),
            category,
            status: PublishStatus::Draft,
            pricing: PricingModel::Free,
            manifest_url: String::new(),
            source_hash: String::new(),
            security_scan_passed: false,
            downloads: 0,
            rating: 0.0,
            published_at: now,
            updated_at: now,
            tags: vec![],
            capabilities: vec![],
        }
    }

    pub fn is_available(&self) -> bool {
        self.status == PublishStatus::Published && self.security_scan_passed
    }
}

// ── Pricing Models ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PricingModel {
    Free,
    /// Fixed price per month in USD cents
    Subscription { monthly_usd_cents: u64 },
    /// Per API call price in micro-USD (1 = $0.000001)
    PayPerUse { per_call_micro_usd: u64 },
    /// Tiered: (calls_included, overage_per_call_micro_usd)
    Tiered {
        monthly_usd_cents: u64,
        included_calls: u64,
        overage_micro_usd: u64,
    },
    /// Enterprise license negotiated separately
    Enterprise,
}

// ── Publisher ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Publisher {
    pub publisher_id: String,
    pub name: String,
    pub contact_email: String,
    pub verified: bool,
    pub partner_tier: PartnerTier,
    pub registered_at: DateTime<Utc>,
    pub published_plugins: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PartnerTier {
    Community,
    Silver,
    Gold,
    Platinum,
}

impl Publisher {
    pub fn new(
        name: impl Into<String>,
        email: impl Into<String>,
        tier: PartnerTier,
    ) -> Self {
        Self {
            publisher_id: Uuid::new_v4().to_string(),
            name: name.into(),
            contact_email: email.into(),
            verified: false,
            partner_tier: tier,
            registered_at: Utc::now(),
            published_plugins: vec![],
        }
    }

    pub fn verify(mut self) -> Self {
        self.verified = true;
        self
    }
}

// ── Marketplace Registry ─────────────────────────────────────────────────────

pub struct MarketplaceRegistry {
    plugins: DashMap<String, MarketplacePlugin>,
    publishers: DashMap<String, Publisher>,
    /// tag -> Vec<plugin_id>
    tag_index: DashMap<String, Vec<String>>,
    /// category label -> Vec<plugin_id>
    category_index: DashMap<String, Vec<String>>,
}

impl MarketplaceRegistry {
    pub fn new() -> Self {
        Self {
            plugins: DashMap::new(),
            publishers: DashMap::new(),
            tag_index: DashMap::new(),
            category_index: DashMap::new(),
        }
    }

    pub fn register_publisher(&self, publisher: Publisher) -> String {
        let id = publisher.publisher_id.clone();
        info!("Marketplace: registered publisher '{}'", publisher.name);
        self.publishers.insert(id.clone(), publisher);
        id
    }

    pub fn submit_plugin(
        &self,
        mut plugin: MarketplacePlugin,
    ) -> Result<String, MarketplaceError> {
        // Verify publisher exists and is verified
        let publisher = self
            .publishers
            .get(&plugin.publisher_id)
            .ok_or_else(|| MarketplaceError::UnauthorizedPublisher(plugin.publisher_id.clone()))?;

        if !publisher.verified {
            return Err(MarketplaceError::UnauthorizedPublisher(format!(
                "publisher '{}' not verified",
                publisher.name
            )));
        }

        plugin.status = PublishStatus::PendingReview;
        let id = plugin.plugin_id.clone();

        // Index by tags
        for tag in &plugin.tags {
            self.tag_index
                .entry(tag.clone())
                .or_default()
                .push(id.clone());
        }
        // Index by category
        self.category_index
            .entry(plugin.category.label().to_string())
            .or_default()
            .push(id.clone());

        self.plugins.insert(id.clone(), plugin);
        Ok(id)
    }

    /// Simulate security scan approval.
    pub fn approve_security_scan(&self, plugin_id: &str) -> Result<(), MarketplaceError> {
        let mut entry = self
            .plugins
            .get_mut(plugin_id)
            .ok_or_else(|| MarketplaceError::PluginNotFound(plugin_id.to_string()))?;
        entry.security_scan_passed = true;
        entry.status = PublishStatus::Published;
        Ok(())
    }

    pub fn get_plugin(&self, plugin_id: &str) -> Option<MarketplacePlugin> {
        self.plugins.get(plugin_id).map(|e| e.clone())
    }

    pub fn search_by_category(&self, category: &str) -> Vec<MarketplacePlugin> {
        self.category_index
            .get(category)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.plugins.get(id).map(|p| p.clone()))
                    .filter(|p| p.is_available())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn search_by_tag(&self, tag: &str) -> Vec<MarketplacePlugin> {
        self.tag_index
            .get(tag)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.plugins.get(id).map(|p| p.clone()))
                    .filter(|p| p.is_available())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn install(
        &self,
        plugin_id: &str,
        user_id: &str,
        billing: &BillingEngine,
    ) -> Result<InstallReceipt, MarketplaceError> {
        let mut plugin = self
            .plugins
            .get_mut(plugin_id)
            .ok_or_else(|| MarketplaceError::PluginNotFound(plugin_id.to_string()))?;

        if !plugin.is_available() {
            return Err(MarketplaceError::PluginNotFound(format!(
                "plugin '{}' is not available (status: {:?})",
                plugin_id, plugin.status
            )));
        }

        // Charge if not free
        let amount = match &plugin.pricing {
            PricingModel::Free => 0.0,
            PricingModel::PayPerUse { per_call_micro_usd } => *per_call_micro_usd as f64 / 1_000_000.0,
            PricingModel::Subscription { monthly_usd_cents } => *monthly_usd_cents as f64 / 100.0,
            PricingModel::Tiered { monthly_usd_cents, .. } => *monthly_usd_cents as f64 / 100.0,
            PricingModel::Enterprise => 0.0,
        };

        if amount > 0.0 {
            billing.charge(user_id, amount, &format!("install:{}", plugin_id))?;
        }

        plugin.downloads += 1;

        Ok(InstallReceipt {
            receipt_id: Uuid::new_v4().to_string(),
            plugin_id: plugin_id.to_string(),
            user_id: user_id.to_string(),
            amount_charged_usd: amount,
            installed_at: Utc::now(),
        })
    }

    pub fn published_count(&self) -> usize {
        self.plugins
            .iter()
            .filter(|e| e.status == PublishStatus::Published)
            .count()
    }
}

impl Default for MarketplaceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallReceipt {
    pub receipt_id: String,
    pub plugin_id: String,
    pub user_id: String,
    pub amount_charged_usd: f64,
    pub installed_at: DateTime<Utc>,
}

// ── Billing Engine ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingAccount {
    pub account_id: String,
    pub user_id: String,
    pub balance_usd: f64,
    pub total_spent_usd: f64,
    pub created_at: DateTime<Utc>,
}

impl BillingAccount {
    pub fn new(user_id: impl Into<String>, initial_balance: f64) -> Self {
        Self {
            account_id: Uuid::new_v4().to_string(),
            user_id: user_id.into(),
            balance_usd: initial_balance,
            total_spent_usd: 0.0,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    pub record_id: String,
    pub user_id: String,
    pub plugin_id: String,
    pub description: String,
    pub amount_usd: f64,
    pub recorded_at: DateTime<Utc>,
}

pub struct BillingEngine {
    accounts: DashMap<String, BillingAccount>,
    usage_records: DashMap<String, Vec<UsageRecord>>,
}

impl BillingEngine {
    pub fn new() -> Self {
        Self {
            accounts: DashMap::new(),
            usage_records: DashMap::new(),
        }
    }

    pub fn create_account(&self, account: BillingAccount) -> String {
        let id = account.user_id.clone();
        self.accounts.insert(id.clone(), account);
        id
    }

    pub fn charge(
        &self,
        user_id: &str,
        amount_usd: f64,
        description: &str,
    ) -> Result<UsageRecord, MarketplaceError> {
        let mut account = self
            .accounts
            .get_mut(user_id)
            .ok_or_else(|| MarketplaceError::AccountNotFound(user_id.to_string()))?;

        if account.balance_usd < amount_usd {
            return Err(MarketplaceError::InsufficientCredits {
                required: amount_usd,
                available: account.balance_usd,
            });
        }

        account.balance_usd -= amount_usd;
        account.total_spent_usd += amount_usd;

        let record = UsageRecord {
            record_id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            plugin_id: description.to_string(),
            description: description.to_string(),
            amount_usd,
            recorded_at: Utc::now(),
        };

        self.usage_records
            .entry(user_id.to_string())
            .or_default()
            .push(record.clone());

        Ok(record)
    }

    pub fn balance(&self, user_id: &str) -> Option<f64> {
        self.accounts.get(user_id).map(|a| a.balance_usd)
    }

    pub fn usage_records(&self, user_id: &str) -> Vec<UsageRecord> {
        self.usage_records
            .get(user_id)
            .map(|v| v.clone())
            .unwrap_or_default()
    }
}

impl Default for BillingEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── White-Label SDK ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhiteLabelConfig {
    pub brand_name: String,
    pub logo_url: String,
    pub primary_color: String,
    pub api_base_url: String,
    pub features_enabled: Vec<String>,
    pub custom_domain: Option<String>,
    pub partner_id: String,
}

impl WhiteLabelConfig {
    pub fn new(
        brand_name: impl Into<String>,
        partner_id: impl Into<String>,
        api_base_url: impl Into<String>,
    ) -> Self {
        Self {
            brand_name: brand_name.into(),
            logo_url: String::new(),
            primary_color: "#2563EB".into(), // default blue
            api_base_url: api_base_url.into(),
            features_enabled: vec![
                "policy-engine".into(),
                "audit-log".into(),
                "guardrails".into(),
            ],
            custom_domain: None,
            partner_id: partner_id.into(),
        }
    }

    pub fn with_custom_domain(mut self, domain: impl Into<String>) -> Self {
        self.custom_domain = Some(domain.into());
        self
    }

    pub fn to_sdk_config_json(&self) -> serde_json::Value {
        serde_json::json!({
            "brandName": self.brand_name,
            "logoUrl": self.logo_url,
            "primaryColor": self.primary_color,
            "apiBaseUrl": self.api_base_url,
            "customDomain": self.custom_domain,
            "features": self.features_enabled,
            "partnerId": self.partner_id,
        })
    }
}

// ── GA Release Metrics ────────────────────────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GaReleaseMetrics {
    pub total_plugins: u64,
    pub verified_publishers: u64,
    pub total_installs: u64,
    pub monthly_active_users: u64,
    pub uptime_99_9_compliant: bool,
    pub security_incidents_30d: u32,
    pub mean_plugin_rating: f64,
    pub partner_integrations: u64,
}

impl GaReleaseMetrics {
    pub fn is_ga_ready(&self) -> bool {
        self.total_plugins >= 10
            && self.verified_publishers >= 3
            && self.uptime_99_9_compliant
            && self.security_incidents_30d == 0
            && self.mean_plugin_rating >= 4.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> MarketplaceRegistry {
        MarketplaceRegistry::new()
    }

    fn make_billing() -> BillingEngine {
        BillingEngine::new()
    }

    fn make_verified_publisher() -> Publisher {
        Publisher::new("AcmeCorp", "acme@corp.io", PartnerTier::Gold).verify()
    }

    fn make_plugin(publisher_id: &str) -> MarketplacePlugin {
        let mut p = MarketplacePlugin::new(
            "awesome-llm-connector",
            "Connects to GPT-4 with safety wrappers",
            "1.0.0",
            publisher_id,
            PluginCategory::LlmConnector,
        );
        p.tags = vec!["llm".into(), "gpt4".into()];
        p
    }

    // ── Publisher Registration ────────────────────────────────────────────────

    #[test]
    fn publisher_registered_successfully() {
        let registry = make_registry();
        let pub1 = make_verified_publisher();
        let id = registry.register_publisher(pub1);
        assert!(!id.is_empty());
    }

    #[test]
    fn unverified_publisher_cannot_submit() {
        let registry = make_registry();
        let unverified = Publisher::new("BadActor", "x@x.io", PartnerTier::Community);
        let pub_id = registry.register_publisher(unverified);
        let plugin = make_plugin(&pub_id);
        let result = registry.submit_plugin(plugin);
        assert!(result.is_err());
    }

    // ── Plugin Lifecycle ─────────────────────────────────────────────────────

    #[test]
    fn plugin_submitted_pending_review() {
        let registry = make_registry();
        let publisher = make_verified_publisher();
        let pub_id = registry.register_publisher(publisher);
        let plugin = make_plugin(&pub_id);
        let plugin_id = registry.submit_plugin(plugin).unwrap();
        let retrieved = registry.get_plugin(&plugin_id).unwrap();
        assert_eq!(retrieved.status, PublishStatus::PendingReview);
    }

    #[test]
    fn plugin_approved_becomes_available() {
        let registry = make_registry();
        let publisher = make_verified_publisher();
        let pub_id = registry.register_publisher(publisher);
        let plugin = make_plugin(&pub_id);
        let plugin_id = registry.submit_plugin(plugin).unwrap();
        registry.approve_security_scan(&plugin_id).unwrap();
        let retrieved = registry.get_plugin(&plugin_id).unwrap();
        assert!(retrieved.is_available());
    }

    #[test]
    fn plugin_not_available_before_scan() {
        let registry = make_registry();
        let publisher = make_verified_publisher();
        let pub_id = registry.register_publisher(publisher);
        let plugin = make_plugin(&pub_id);
        let plugin_id = registry.submit_plugin(plugin).unwrap();
        let retrieved = registry.get_plugin(&plugin_id).unwrap();
        assert!(!retrieved.is_available());
    }

    // ── Search ───────────────────────────────────────────────────────────────

    #[test]
    fn search_by_category_returns_published() {
        let registry = make_registry();
        let publisher = make_verified_publisher();
        let pub_id = registry.register_publisher(publisher);
        let plugin = make_plugin(&pub_id);
        let plugin_id = registry.submit_plugin(plugin).unwrap();
        registry.approve_security_scan(&plugin_id).unwrap();

        let results = registry.search_by_category("llm-connector");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_by_tag_returns_published() {
        let registry = make_registry();
        let publisher = make_verified_publisher();
        let pub_id = registry.register_publisher(publisher);
        let plugin = make_plugin(&pub_id);
        let plugin_id = registry.submit_plugin(plugin).unwrap();
        registry.approve_security_scan(&plugin_id).unwrap();

        let results = registry.search_by_tag("llm");
        assert!(!results.is_empty());
    }

    // ── Billing Engine ────────────────────────────────────────────────────────

    #[test]
    fn charge_deducts_balance() {
        let billing = make_billing();
        billing.create_account(BillingAccount::new("user-1", 100.0));
        billing.charge("user-1", 9.99, "subscription").unwrap();
        let balance = billing.balance("user-1").unwrap();
        assert!((balance - 90.01).abs() < 0.001);
    }

    #[test]
    fn insufficient_balance_fails() {
        let billing = make_billing();
        billing.create_account(BillingAccount::new("poor-user", 5.0));
        let result = billing.charge("poor-user", 50.0, "big-purchase");
        assert!(result.is_err());
    }

    #[test]
    fn free_plugin_install_no_charge() {
        let registry = make_registry();
        let billing = make_billing();
        billing.create_account(BillingAccount::new("user-x", 0.0)); // zero balance

        let publisher = make_verified_publisher();
        let pub_id = registry.register_publisher(publisher);
        let plugin = make_plugin(&pub_id); // defaults to Free pricing
        let plugin_id = registry.submit_plugin(plugin).unwrap();
        registry.approve_security_scan(&plugin_id).unwrap();

        let receipt = registry.install(&plugin_id, "user-x", &billing).unwrap();
        assert_eq!(receipt.amount_charged_usd, 0.0);
    }

    #[test]
    fn install_increments_download_count() {
        let registry = make_registry();
        let billing = make_billing();
        billing.create_account(BillingAccount::new("user-dl", 100.0));

        let publisher = make_verified_publisher();
        let pub_id = registry.register_publisher(publisher);
        let plugin = make_plugin(&pub_id);
        let plugin_id = registry.submit_plugin(plugin).unwrap();
        registry.approve_security_scan(&plugin_id).unwrap();

        registry.install(&plugin_id, "user-dl", &billing).unwrap();
        let p = registry.get_plugin(&plugin_id).unwrap();
        assert_eq!(p.downloads, 1);
    }

    // ── White-Label SDK ──────────────────────────────────────────────────────

    #[test]
    fn white_label_sdk_config_json() {
        let config = WhiteLabelConfig::new(
            "EnterpriseSafe",
            "partner-acme",
            "https://api.enterprise.safe",
        )
        .with_custom_domain("safe.enterprise.com");
        let json = config.to_sdk_config_json();
        assert_eq!(json["brandName"], "EnterpriseSafe");
        assert_eq!(json["customDomain"], "safe.enterprise.com");
    }

    // ── GA Release Metrics ────────────────────────────────────────────────────

    #[test]
    fn ga_ready_when_all_criteria_met() {
        let metrics = GaReleaseMetrics {
            total_plugins: 25,
            verified_publishers: 5,
            total_installs: 1000,
            monthly_active_users: 500,
            uptime_99_9_compliant: true,
            security_incidents_30d: 0,
            mean_plugin_rating: 4.5,
            partner_integrations: 10,
        };
        assert!(metrics.is_ga_ready());
    }

    #[test]
    fn ga_not_ready_with_incidents() {
        let metrics = GaReleaseMetrics {
            total_plugins: 25,
            verified_publishers: 5,
            uptime_99_9_compliant: true,
            security_incidents_30d: 2,
            mean_plugin_rating: 4.5,
            ..Default::default()
        };
        assert!(!metrics.is_ga_ready());
    }

    #[test]
    fn ga_not_ready_low_rating() {
        let metrics = GaReleaseMetrics {
            total_plugins: 25,
            verified_publishers: 5,
            uptime_99_9_compliant: true,
            security_incidents_30d: 0,
            mean_plugin_rating: 3.2,
            ..Default::default()
        };
        assert!(!metrics.is_ga_ready());
    }
}
