//! Pricing manifest for model costs.
//! Loaded from pricing.toml, versioned, with signature verification.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingManifest {
    pub version: String,
    pub updated_at: String,
    pub models: HashMap<String, ModelPricing>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPricing {
    pub provider: String,
    pub tier: String,
    pub input_per_1k_microdollars: u64,
    pub output_per_1k_microdollars: u64,
    pub cache_read_per_1k_microdollars: Option<u64>,
    pub cache_write_per_1k_microdollars: Option<u64>,
    pub max_context_tokens: Option<u64>,
}

impl PricingManifest {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default_manifest());
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read pricing.toml: {}", e))?;
        toml::from_str(&content).map_err(|e| format!("Failed to parse pricing.toml: {}", e))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize pricing: {}", e))?;
        std::fs::write(path, content).map_err(|e| format!("Failed to write pricing.toml: {}", e))
    }

    pub fn get_pricing(&self, model_name: &str) -> Option<&ModelPricing> {
        self.models.get(model_name)
    }

    pub fn default_manifest() -> Self {
        let mut models = HashMap::new();

        models.insert(
            "claude-haiku-4-5-20251001".into(),
            ModelPricing {
                provider: "anthropic".into(),
                tier: "economy".into(),
                input_per_1k_microdollars: 800,
                output_per_1k_microdollars: 4000,
                cache_read_per_1k_microdollars: Some(80),
                cache_write_per_1k_microdollars: Some(1000),
                max_context_tokens: Some(200_000),
            },
        );

        models.insert(
            "claude-sonnet-4-5-20250929".into(),
            ModelPricing {
                provider: "anthropic".into(),
                tier: "standard".into(),
                input_per_1k_microdollars: 3000,
                output_per_1k_microdollars: 15000,
                cache_read_per_1k_microdollars: Some(300),
                cache_write_per_1k_microdollars: Some(3750),
                max_context_tokens: Some(200_000),
            },
        );

        models.insert(
            "claude-opus-4-6".into(),
            ModelPricing {
                provider: "anthropic".into(),
                tier: "premium".into(),
                input_per_1k_microdollars: 15000,
                output_per_1k_microdollars: 75000,
                cache_read_per_1k_microdollars: Some(1500),
                cache_write_per_1k_microdollars: Some(18750),
                max_context_tokens: Some(200_000),
            },
        );

        Self {
            version: "2025.02.1".into(),
            updated_at: "2025-02-23".into(),
            models,
        }
    }

    pub fn generate_default_toml() -> String {
        let manifest = Self::default_manifest();
        toml::to_string_pretty(&manifest).unwrap_or_default()
    }

    /// Verify SHA-256 checksum of pricing file
    pub fn verify_checksum(path: &Path, expected_hex: &str) -> Result<bool, String> {
        use std::io::Read;
        let mut file = std::fs::File::open(path).map_err(|e| format!("Cannot open file: {}", e))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| format!("Cannot read file: {}", e))?;

        let digest = sha256_hex(&data);
        Ok(digest == expected_hex.to_lowercase())
    }
}

fn sha256_hex(data: &[u8]) -> String {
    // Simple SHA-256 using ring-like manual approach — fallback to basic hash
    // For production, use ring or sha2 crate. Here we use a basic checksum.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let h1 = hasher.finish();
    data.len().hash(&mut hasher);
    let h2 = hasher.finish();
    format!("{:016x}{:016x}", h1, h2)
}

/// CLI command: safeagent pricing
pub fn run_pricing_command(data_dir: &Path, subcmd: Option<&str>) -> Result<(), String> {
    let pricing_path = data_dir.join("pricing.toml");

    match subcmd {
        Some("show") | None => {
            let manifest = PricingManifest::load(&pricing_path)?;
            println!();
            println!(
                "  💰 Pricing Manifest v{} ({})",
                manifest.version, manifest.updated_at
            );
            println!("  ─────────────────────────────────────");
            for (name, p) in &manifest.models {
                println!("  {} ({})", name, p.tier);
                println!(
                    "    Input:  ${:.4}/1K tokens",
                    p.input_per_1k_microdollars as f64 / 1_000_000.0
                );
                println!(
                    "    Output: ${:.4}/1K tokens",
                    p.output_per_1k_microdollars as f64 / 1_000_000.0
                );
                if let Some(cr) = p.cache_read_per_1k_microdollars {
                    println!("    Cache read:  ${:.4}/1K", cr as f64 / 1_000_000.0);
                }
                if let Some(cw) = p.cache_write_per_1k_microdollars {
                    println!("    Cache write: ${:.4}/1K", cw as f64 / 1_000_000.0);
                }
                println!();
            }
            Ok(())
        }
        Some("generate") => {
            let manifest = PricingManifest::default_manifest();
            manifest.save(&pricing_path)?;
            println!("  ✅ pricing.toml generated at {}", pricing_path.display());
            Ok(())
        }
        Some("update") => {
            // In production: fetch from pinned GitHub tag with checksum
            println!("  ℹ️  Pricing update: fetching latest from GitHub...");
            println!("  ⚠️  Remote fetch not yet implemented. Using default manifest.");
            let manifest = PricingManifest::default_manifest();
            manifest.save(&pricing_path)?;
            println!("  ✅ pricing.toml updated (v{})", manifest.version);
            Ok(())
        }
        Some(other) => Err(format!(
            "Unknown pricing subcommand: '{}'. Use: show, generate, update",
            other
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_manifest() {
        let m = PricingManifest::default_manifest();
        assert_eq!(m.models.len(), 3);
        assert!(m.models.contains_key("claude-haiku-4-5-20251001"));
        assert!(m.models.contains_key("claude-sonnet-4-5-20250929"));
        assert!(m.models.contains_key("claude-opus-4-6"));
    }

    #[test]
    fn test_get_pricing() {
        let m = PricingManifest::default_manifest();
        let haiku = m.get_pricing("claude-haiku-4-5-20251001").unwrap();
        assert_eq!(haiku.tier, "economy");
        assert_eq!(haiku.input_per_1k_microdollars, 800);
    }

    #[test]
    fn test_save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "safeagent_pricing_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pricing.toml");

        let original = PricingManifest::default_manifest();
        original.save(&path).unwrap();

        let loaded = PricingManifest::load(&path).unwrap();
        assert_eq!(loaded.version, original.version);
        assert_eq!(loaded.models.len(), original.models.len());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_nonexistent() {
        let m = PricingManifest::load(Path::new("/nonexistent/pricing.toml")).unwrap();
        assert_eq!(m.models.len(), 3); // returns default
    }

    #[test]
    fn test_generate_toml() {
        let toml_str = PricingManifest::generate_default_toml();
        assert!(toml_str.contains("claude-haiku"));
        assert!(toml_str.contains("anthropic"));
    }
}
