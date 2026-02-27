//! W17: Multi-Cloud Deployment Engine
//!
//! Helm chart generation, edge/IoT deployment manifests,
//! multi-region policy sync, serverless gateway configuration,
//! and air-gapped deployment mode.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::info;
use uuid::Uuid;

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum DeployError {
    #[error("deployment target '{0}' not found")]
    TargetNotFound(String),
    #[error("incompatible deployment mode: {0}")]
    IncompatibleMode(String),
    #[error("manifest generation failed: {0}")]
    ManifestError(String),
    #[error("policy sync conflict in region '{0}': {1}")]
    SyncConflict(String, String),
}

// ── Deployment Target ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
    OnPrem,
    Edge,
    AirGapped,
}

impl CloudProvider {
    pub fn label(&self) -> &'static str {
        match self {
            CloudProvider::Aws => "aws",
            CloudProvider::Azure => "azure",
            CloudProvider::Gcp => "gcp",
            CloudProvider::OnPrem => "on-prem",
            CloudProvider::Edge => "edge",
            CloudProvider::AirGapped => "air-gapped",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentTarget {
    pub target_id: String,
    pub name: String,
    pub provider: CloudProvider,
    pub region: String,
    pub kubernetes_version: Option<String>,
    pub is_primary: bool,
    pub tags: HashMap<String, String>,
}

impl DeploymentTarget {
    pub fn new(
        name: impl Into<String>,
        provider: CloudProvider,
        region: impl Into<String>,
    ) -> Self {
        Self {
            target_id: Uuid::new_v4().to_string(),
            name: name.into(),
            provider,
            region: region.into(),
            kubernetes_version: None,
            is_primary: false,
            tags: HashMap::new(),
        }
    }

    pub fn as_primary(mut self) -> Self {
        self.is_primary = true;
        self
    }

    pub fn with_k8s_version(mut self, version: impl Into<String>) -> Self {
        self.kubernetes_version = Some(version.into());
        self
    }
}

// ── Helm Chart Generator ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelmValues {
    pub replicas: u32,
    pub image_repository: String,
    pub image_tag: String,
    pub service_type: String,
    pub service_port: u16,
    pub resources: ResourceRequirements,
    pub env_vars: HashMap<String, String>,
    pub extra_values: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub cpu_request: String,
    pub cpu_limit: String,
    pub memory_request: String,
    pub memory_limit: String,
}

impl Default for ResourceRequirements {
    fn default() -> Self {
        Self {
            cpu_request: "100m".into(),
            cpu_limit: "500m".into(),
            memory_request: "128Mi".into(),
            memory_limit: "512Mi".into(),
        }
    }
}

impl Default for HelmValues {
    fn default() -> Self {
        Self {
            replicas: 1,
            image_repository: "ghcr.io/safeagent/gateway".into(),
            image_tag: "latest".into(),
            service_type: "ClusterIP".into(),
            service_port: 8080,
            resources: ResourceRequirements::default(),
            env_vars: HashMap::new(),
            extra_values: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelmChart {
    pub chart_name: String,
    pub chart_version: String,
    pub app_version: String,
    pub values_yaml: String,
    pub deployment_yaml: String,
    pub service_yaml: String,
    pub configmap_yaml: String,
    pub generated_at: DateTime<Utc>,
}

pub struct HelmChartGenerator;

impl HelmChartGenerator {
    pub fn generate(
        chart_name: &str,
        app_version: &str,
        values: &HelmValues,
        target: &DeploymentTarget,
    ) -> HelmChart {
        let values_yaml = Self::render_values(values);
        let deployment_yaml = Self::render_deployment(chart_name, app_version, values, target);
        let service_yaml = Self::render_service(chart_name, values);
        let configmap_yaml = Self::render_configmap(chart_name, values);

        HelmChart {
            chart_name: chart_name.to_string(),
            chart_version: "0.1.0".into(),
            app_version: app_version.to_string(),
            values_yaml,
            deployment_yaml,
            service_yaml,
            configmap_yaml,
            generated_at: Utc::now(),
        }
    }

    fn render_values(v: &HelmValues) -> String {
        let mut yaml = format!(
            "replicaCount: {}\n\
             image:\n  repository: {}\n  tag: \"{}\"\n  pullPolicy: IfNotPresent\n\
             service:\n  type: {}\n  port: {}\n\
             resources:\n  requests:\n    cpu: {}\n    memory: {}\n  limits:\n    cpu: {}\n    memory: {}\n",
            v.replicas,
            v.image_repository, v.image_tag,
            v.service_type, v.service_port,
            v.resources.cpu_request, v.resources.memory_request,
            v.resources.cpu_limit, v.resources.memory_limit,
        );
        if !v.env_vars.is_empty() {
            yaml.push_str("env:\n");
            for (k, val) in &v.env_vars {
                yaml.push_str(&format!("  {}: \"{}\"\n", k, val));
            }
        }
        yaml
    }

    fn render_deployment(
        name: &str,
        app_version: &str,
        v: &HelmValues,
        target: &DeploymentTarget,
    ) -> String {
        format!(
            "apiVersion: apps/v1\n\
             kind: Deployment\n\
             metadata:\n  name: {name}\n  labels:\n    app: {name}\n    version: \"{app_version}\"\n    cloud: \"{provider}\"\n\
             spec:\n  replicas: {replicas}\n  selector:\n    matchLabels:\n      app: {name}\n  template:\n    metadata:\n      labels:\n        app: {name}\n    spec:\n      containers:\n      - name: {name}\n        image: {repo}:{tag}\n        ports:\n        - containerPort: {port}\n",
            name = name,
            app_version = app_version,
            provider = target.provider.label(),
            replicas = v.replicas,
            repo = v.image_repository,
            tag = v.image_tag,
            port = v.service_port,
        )
    }

    fn render_service(name: &str, v: &HelmValues) -> String {
        format!(
            "apiVersion: v1\n\
             kind: Service\n\
             metadata:\n  name: {name}\n\
             spec:\n  type: {svc_type}\n  ports:\n  - port: {port}\n    targetPort: {port}\n  selector:\n    app: {name}\n",
            name = name,
            svc_type = v.service_type,
            port = v.service_port,
        )
    }

    fn render_configmap(name: &str, v: &HelmValues) -> String {
        let mut data = String::new();
        for (k, val) in &v.env_vars {
            data.push_str(&format!("  {}: \"{}\"\n", k, val));
        }
        format!(
            "apiVersion: v1\n\
             kind: ConfigMap\n\
             metadata:\n  name: {name}-config\n\
             data:\n{data}",
            name = name,
            data = data,
        )
    }
}

// ── Edge / IoT Deployment ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeDeploymentSpec {
    pub device_id: String,
    pub arch: EdgeArch,
    pub memory_limit_mb: u32,
    pub cpu_limit_millicores: u32,
    pub offline_capable: bool,
    pub sync_interval_seconds: u32,
    pub policy_bundle_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeArch {
    Amd64,
    Arm64,
    Armv7,
    Riscv64,
}

impl EdgeArch {
    pub fn label(&self) -> &'static str {
        match self {
            EdgeArch::Amd64 => "amd64",
            EdgeArch::Arm64 => "arm64",
            EdgeArch::Armv7 => "armv7",
            EdgeArch::Riscv64 => "riscv64",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeManifest {
    pub device_id: String,
    pub manifest_yaml: String,
    pub generated_at: DateTime<Utc>,
}

pub struct EdgeManifestGenerator;

impl EdgeManifestGenerator {
    pub fn generate(spec: &EdgeDeploymentSpec, image_tag: &str) -> EdgeManifest {
        let manifest = format!(
            "# SafeAgent Edge Manifest — device: {device_id}\n\
             apiVersion: v1\n\
             kind: EdgeDeployment\n\
             metadata:\n  deviceId: {device_id}\n  arch: {arch}\n\
             spec:\n\
               image: ghcr.io/safeagent/edge:{tag}\n\
               resources:\n\
                 memory: {mem}Mi\n\
                 cpu: {cpu}m\n\
               offline: {offline}\n\
               syncIntervalSeconds: {sync}\n\
               policyBundlePath: {policy_path}\n",
            device_id = spec.device_id,
            arch = spec.arch.label(),
            tag = image_tag,
            mem = spec.memory_limit_mb,
            cpu = spec.cpu_limit_millicores,
            offline = spec.offline_capable,
            sync = spec.sync_interval_seconds,
            policy_path = spec.policy_bundle_path,
        );
        EdgeManifest {
            device_id: spec.device_id.clone(),
            manifest_yaml: manifest,
            generated_at: Utc::now(),
        }
    }
}

// ── Multi-Region Policy Sync ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundle {
    pub bundle_id: String,
    pub version: u64,
    pub policies: Vec<String>,
    pub checksum: String,
    pub created_at: DateTime<Utc>,
}

impl PolicyBundle {
    pub fn new(policies: Vec<String>) -> Self {
        let checksum = format!("{:x}", policies.len() * 31 + policies.iter().map(|p| p.len()).sum::<usize>());
        Self {
            bundle_id: Uuid::new_v4().to_string(),
            version: 1,
            policies,
            checksum,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionSyncState {
    pub region: String,
    pub current_bundle_version: u64,
    pub last_synced: DateTime<Utc>,
    pub sync_status: SyncStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncStatus {
    InSync,
    Pending,
    Failed { error: String },
    Drifted { delta_versions: u64 },
}

pub struct MultiRegionPolicySync {
    primary_bundle: PolicyBundle,
    regions: dashmap::DashMap<String, RegionSyncState>,
}

impl MultiRegionPolicySync {
    pub fn new(primary: PolicyBundle) -> Self {
        Self {
            primary_bundle: primary,
            regions: dashmap::DashMap::new(),
        }
    }

    pub fn register_region(&self, region: impl Into<String>) {
        let r = region.into();
        self.regions.insert(
            r.clone(),
            RegionSyncState {
                region: r,
                current_bundle_version: 0,
                last_synced: Utc::now(),
                sync_status: SyncStatus::Pending,
            },
        );
    }

    /// Simulate syncing a region to the current primary bundle version.
    pub fn sync_region(&self, region: &str) -> Result<(), DeployError> {
        let mut entry = self
            .regions
            .get_mut(region)
            .ok_or_else(|| DeployError::TargetNotFound(region.to_string()))?;

        info!("PolicySync: syncing region '{}' to v{}", region, self.primary_bundle.version);
        entry.current_bundle_version = self.primary_bundle.version;
        entry.last_synced = Utc::now();
        entry.sync_status = SyncStatus::InSync;
        Ok(())
    }

    pub fn drift_report(&self) -> Vec<RegionSyncState> {
        self.regions
            .iter()
            .filter(|e| e.sync_status != SyncStatus::InSync)
            .map(|e| e.clone())
            .collect()
    }

    pub fn in_sync_count(&self) -> usize {
        self.regions
            .iter()
            .filter(|e| e.sync_status == SyncStatus::InSync)
            .count()
    }

    pub fn total_regions(&self) -> usize {
        self.regions.len()
    }
}

// ── Air-Gapped Mode ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirGappedBundle {
    pub bundle_id: String,
    pub includes_models: Vec<String>,
    pub includes_policies: Vec<String>,
    pub offline_cache_size_mb: u64,
    pub created_at: DateTime<Utc>,
    pub sha256_manifest: String,
}

impl AirGappedBundle {
    pub fn new(models: Vec<String>, policies: Vec<String>) -> Self {
        let size: u64 = models.len() as u64 * 2000 + policies.len() as u64 * 1;
        let manifest_hash = format!(
            "{:016x}",
            models.len() as u64 * 0x1a2b3c4d + policies.len() as u64 * 0x5e6f7a8b
        );
        Self {
            bundle_id: Uuid::new_v4().to_string(),
            includes_models: models,
            includes_policies: policies,
            offline_cache_size_mb: size,
            created_at: Utc::now(),
            sha256_manifest: manifest_hash,
        }
    }

    pub fn is_self_contained(&self) -> bool {
        !self.includes_models.is_empty() && !self.includes_policies.is_empty()
    }
}

// ── Serverless Gateway Config ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerlessGatewayConfig {
    pub function_name: String,
    pub runtime: String,
    pub memory_mb: u32,
    pub timeout_seconds: u32,
    pub env_vars: HashMap<String, String>,
    pub triggers: Vec<ServerlessTrigger>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerlessTrigger {
    HttpApi { path: String, method: String },
    Queue { queue_name: String },
    Schedule { cron_expression: String },
    EventBridge { event_pattern: String },
}

impl ServerlessGatewayConfig {
    pub fn new(function_name: impl Into<String>) -> Self {
        Self {
            function_name: function_name.into(),
            runtime: "provided.al2023".into(), // custom runtime for Rust
            memory_mb: 512,
            timeout_seconds: 30,
            env_vars: HashMap::new(),
            triggers: vec![],
        }
    }

    pub fn with_http_trigger(mut self, path: impl Into<String>, method: impl Into<String>) -> Self {
        self.triggers.push(ServerlessTrigger::HttpApi {
            path: path.into(),
            method: method.into(),
        });
        self
    }

    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.insert(key.into(), value.into());
        self
    }

    pub fn to_sam_template(&self) -> String {
        let triggers: String = self
            .triggers
            .iter()
            .filter_map(|t| {
                if let ServerlessTrigger::HttpApi { path, method } = t {
                    Some(format!(
                        "      HttpApi:\n        Type: HttpApi\n        Properties:\n          Path: {}\n          Method: {}\n",
                        path, method
                    ))
                } else {
                    None
                }
            })
            .collect();

        format!(
            "AWSTemplateFormatVersion: '2010-09-09'\nTransform: AWS::Serverless-2016-10-31\nResources:\n  {}:\n    Type: AWS::Serverless::Function\n    Properties:\n      Runtime: {}\n      MemorySize: {}\n      Timeout: {}\n    Events:\n{}",
            self.function_name,
            self.runtime,
            self.memory_mb,
            self.timeout_seconds,
            triggers,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helm Chart ───────────────────────────────────────────────────────────

    #[test]
    fn helm_chart_generated_with_deployment() {
        let values = HelmValues::default();
        let target = DeploymentTarget::new("prod-aws", CloudProvider::Aws, "us-east-1");
        let chart = HelmChartGenerator::generate("safeagent-gateway", "0.1.0", &values, &target);
        assert!(chart.deployment_yaml.contains("safeagent-gateway"));
        assert!(chart.deployment_yaml.contains("aws"));
        assert!(chart.service_yaml.contains("ClusterIP"));
    }

    #[test]
    fn helm_values_yaml_contains_image() {
        let mut values = HelmValues::default();
        values.image_tag = "v1.2.3".into();
        let target = DeploymentTarget::new("staging", CloudProvider::Gcp, "eu-west-1");
        let chart = HelmChartGenerator::generate("my-chart", "1.0", &values, &target);
        assert!(chart.values_yaml.contains("v1.2.3"));
    }

    #[test]
    fn helm_configmap_includes_env_vars() {
        let mut values = HelmValues::default();
        values.env_vars.insert("LOG_LEVEL".into(), "debug".into());
        let target = DeploymentTarget::new("dev", CloudProvider::OnPrem, "dc-1");
        let chart = HelmChartGenerator::generate("safeagent", "0.1.0", &values, &target);
        assert!(chart.configmap_yaml.contains("LOG_LEVEL"));
    }

    // ── Edge Deployment ──────────────────────────────────────────────────────

    #[test]
    fn edge_manifest_contains_arch() {
        let spec = EdgeDeploymentSpec {
            device_id: "rpi-001".into(),
            arch: EdgeArch::Arm64,
            memory_limit_mb: 256,
            cpu_limit_millicores: 500,
            offline_capable: true,
            sync_interval_seconds: 300,
            policy_bundle_path: "/opt/safeagent/policies".into(),
        };
        let manifest = EdgeManifestGenerator::generate(&spec, "v0.1.0");
        assert!(manifest.manifest_yaml.contains("arm64"));
        assert!(manifest.manifest_yaml.contains("offline: true"));
        assert!(manifest.manifest_yaml.contains("rpi-001"));
    }

    #[test]
    fn edge_manifest_sets_device_id() {
        let spec = EdgeDeploymentSpec {
            device_id: "edge-dev-42".into(),
            arch: EdgeArch::Amd64,
            memory_limit_mb: 512,
            cpu_limit_millicores: 1000,
            offline_capable: false,
            sync_interval_seconds: 60,
            policy_bundle_path: "/policies".into(),
        };
        let manifest = EdgeManifestGenerator::generate(&spec, "latest");
        assert_eq!(manifest.device_id, "edge-dev-42");
    }

    // ── Policy Sync ──────────────────────────────────────────────────────────

    #[test]
    fn policy_sync_region_in_sync_after_sync() {
        let bundle = PolicyBundle::new(vec!["permit(principal, action, resource);".into()]);
        let sync = MultiRegionPolicySync::new(bundle);
        sync.register_region("us-east-1");
        sync.register_region("eu-west-1");

        sync.sync_region("us-east-1").unwrap();

        assert_eq!(sync.in_sync_count(), 1);
        assert_eq!(sync.drift_report().len(), 1); // eu-west-1 still pending
    }

    #[test]
    fn all_regions_synced() {
        let bundle = PolicyBundle::new(vec!["forbid(principal, action, resource);".into()]);
        let sync = MultiRegionPolicySync::new(bundle);
        sync.register_region("ap-southeast-1");
        sync.register_region("us-west-2");

        sync.sync_region("ap-southeast-1").unwrap();
        sync.sync_region("us-west-2").unwrap();

        assert_eq!(sync.in_sync_count(), 2);
        assert!(sync.drift_report().is_empty());
    }

    #[test]
    fn sync_unknown_region_fails() {
        let bundle = PolicyBundle::new(vec![]);
        let sync = MultiRegionPolicySync::new(bundle);
        let result = sync.sync_region("unknown-region");
        assert!(result.is_err());
    }

    // ── Air-Gapped ───────────────────────────────────────────────────────────

    #[test]
    fn air_gapped_bundle_self_contained() {
        let bundle = AirGappedBundle::new(
            vec!["gpt4-mini".into()],
            vec!["policy-001".into(), "policy-002".into()],
        );
        assert!(bundle.is_self_contained());
        assert!(bundle.offline_cache_size_mb > 0);
    }

    #[test]
    fn air_gapped_bundle_not_self_contained_without_models() {
        let bundle = AirGappedBundle::new(vec![], vec!["policy-001".into()]);
        assert!(!bundle.is_self_contained());
    }

    // ── Serverless Config ────────────────────────────────────────────────────

    #[test]
    fn serverless_sam_template_generated() {
        let config = ServerlessGatewayConfig::new("safeagent-fn")
            .with_http_trigger("/v1/authorize", "POST")
            .with_env("RUST_LOG", "info");
        let template = config.to_sam_template();
        assert!(template.contains("safeagent-fn"));
        assert!(template.contains("POST"));
        assert!(template.contains("/v1/authorize"));
    }

    #[test]
    fn deployment_target_primary_flag() {
        let target = DeploymentTarget::new("prod", CloudProvider::Aws, "us-east-1").as_primary();
        assert!(target.is_primary);
    }

    #[test]
    fn cloud_provider_labels() {
        assert_eq!(CloudProvider::Aws.label(), "aws");
        assert_eq!(CloudProvider::AirGapped.label(), "air-gapped");
        assert_eq!(CloudProvider::Edge.label(), "edge");
    }
}
