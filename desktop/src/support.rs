use chrono::Utc;
use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, read_to_string, File};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipWriter};

use super::DesktopPaths;

#[derive(Serialize)]
struct SupportBundleFile {
    source: String,
    mode: String,
}

#[derive(Serialize)]
struct SupportBundleIndex {
    generated_at: i64,
    files: Vec<SupportBundleFile>,
    desktop_version: String,
}

fn timestamp_secs() -> i64 {
    Utc::now().timestamp()
}

fn file_sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn redaction_rules() -> Vec<(&'static str, &'static str)> {
    vec![
        (r"sk-ant-[a-zA-Z0-9\-_]{10,}", "sk-ant-****"),
        (r"pa-[a-zA-Z0-9\-_]{10,}", "pa-****"),
        (
            r"\b\d{6,10}:[A-Za-z0-9_\-]{20,}",
            "****:****",
        ),
        (
            r"(?i)(password|pwd|secret|token|apikey|api[_-]?key|access[_-]?key)\s*[:=]\s*[^\\s\\r\\n]+",
            "$1=****",
        ),
    ]
}

pub fn redact_sensitive(value: &str) -> String {
    redaction_rules().into_iter().fold(value.to_string(), |accum, rule| {
        let re = Regex::new(rule.0).ok();
        if let Some(re) = re {
            re.replace_all(&accum, rule.1).to_string()
        } else {
            accum
        }
    })
}

fn read_tail_lines(path: &Path, lines: usize) -> Vec<String> {
    if !path.exists() {
        return vec![String::new()];
    }
    let raw = read_to_string(path).unwrap_or_default();
    raw.lines()
        .rev()
        .take(lines)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(std::borrow::ToOwned::to_owned)
        .collect()
}

fn write_file_to_zip<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    path: &str,
    content: &[u8],
) -> Result<(), String> {
    let options: FileOptions<'_, ()> =
        FileOptions::default().compression_method(CompressionMethod::Stored);
    zip.start_file(path, options)
        .map_err(|e| format!("start file {path}: {e}"))?;
    zip.write_all(content)
        .map_err(|e| format!("zip write {path}: {e}"))
}

pub fn create_support_bundle(
    root: &Path,
    paths: &DesktopPaths,
    status_json: &str,
    versions_json: &str,
) -> Result<PathBuf, String> {
    fs::create_dir_all(root).map_err(|e| format!("create support dir: {e}"))?;
    let generated_at = Utc::now().to_rfc3339();
    let stamp = timestamp_secs();
    let bundle_path = root.join(format!("support_bundle_{stamp}.zip"));

    let mut file = File::create(&bundle_path).map_err(|e| format!("create bundle: {e}"))?;
    let mut writer = ZipWriter::new(&mut file);

    let manifest = SupportBundleIndex {
        generated_at: stamp,
        files: vec![
            SupportBundleFile {
                source: "status_snapshot.json".to_string(),
                mode: "generated".to_string(),
            },
            SupportBundleFile {
                source: "versions_snapshot.json".to_string(),
                mode: "generated".to_string(),
            },
            SupportBundleFile {
                source: "settings.json".to_string(),
                mode: "file".to_string(),
            },
            SupportBundleFile {
                source: "events.cp.log".to_string(),
                mode: "file".to_string(),
            },
            SupportBundleFile {
                source: "events.worker.log".to_string(),
                mode: "file".to_string(),
            },
        ],
        desktop_version: crate::update::current_version().to_string(),
    };

    write_file_to_zip(
        &mut writer,
        "support/manifest.json",
        &serde_json::to_vec_pretty(&manifest).map_err(|e| format!("manifest json: {e}"))?,
    )?;
    write_file_to_zip(
        &mut writer,
        "support/status_snapshot.json",
        status_json.as_bytes(),
    )?;
    write_file_to_zip(
        &mut writer,
        "support/versions_snapshot.json",
        versions_json.as_bytes(),
    )?;

    let settings = if paths.settings.exists() {
        read_to_string(&paths.settings).unwrap_or_else(|_| "{}".to_string())
    } else {
        "{}".to_string()
    };
    write_file_to_zip(
        &mut writer,
        "support/settings.json",
        redact_sensitive(&settings).as_bytes(),
    )?;

    let cp_tail = read_tail_lines(&paths.logs.join("control-plane.out.log"), 300)
        .join("\n");
    let worker_tail = read_tail_lines(&paths.logs.join("worker.out.log"), 300)
        .join("\n");
    write_file_to_zip(
        &mut writer,
        "support/events.cp.log",
        redact_sensitive(&cp_tail).as_bytes(),
    )?;
    write_file_to_zip(
        &mut writer,
        "support/events.worker.log",
        redact_sensitive(&worker_tail).as_bytes(),
    )?;
    write_file_to_zip(
        &mut writer,
        "support/version.txt",
        format!("generated={generated_at}\n").as_bytes(),
    )?;
    write_file_to_zip(
        &mut writer,
        "support/README.txt",
        b"Support bundle generated by SafeAgent Desktop.\nContains status, versions, settings and redacted logs.\n",
    )?;

    writer
        .finish()
        .map_err(|e| format!("finish zip: {e}"))?;
    let _ = file.flush();

    let mut raw = Vec::new();
    let mut bundle_file = File::open(&bundle_path).map_err(|e| format!("open bundle: {e}"))?;
    bundle_file
        .read_to_end(&mut raw)
        .map_err(|e| format!("read bundle: {e}"))?;
    let checksum = file_sha256_hex(&raw);
    let checksum_name = bundle_path.with_extension("zip.sha256");
    std::fs::write(
        &checksum_name,
        format!("{checksum}  {}\n", bundle_path.file_name().and_then(|name| name.to_str()).unwrap_or("support_bundle.zip")),
    )
    .map_err(|e| format!("write checksum: {e}"))?;
    Ok(bundle_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use zip::ZipArchive;

    #[test]
    fn support_bundle_redacts_secrets() {
        let root = env::temp_dir().join("safeagent-support-bundle-test");
        let _ = std::fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("bundle dir");
        let settings = root.join("settings.json");
        fs::write(&settings, r#"{\"token\":\"sk-ant-abcde12345ABCDE\"}"#).expect("write");
        let paths = DesktopPaths {
            root: root.clone(),
            pki: root.join("pki"),
            logs: root.join("logs"),
            secrets: root.join("secrets"),
            marketplace: root.join("marketplace"),
            installed: root.join("installed"),
            settings,
            update_manifest: root.join("update.json"),
            support_bundles: root.join("support_bundles"),
        };
        std::fs::create_dir_all(&paths.logs).expect("logs");
        let status = serde_json::json!({"running":true}).to_string();
        let versions = serde_json::json!({"safeagent_desktop":"0.1.0"}).to_string();
        let bundle_root = root.join("support_bundles");
        let path = create_support_bundle(&bundle_root, &paths, &status, &versions)
            .expect("bundle");
        let file = File::open(&path).expect("bundle open");
        let mut zip = ZipArchive::new(file).expect("zip open");
        let mut found_settings = false;
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i).expect("zip entry");
            if entry.name() == "support/settings.json" {
                found_settings = true;
                let mut body = String::new();
                entry.read_to_string(&mut body).expect("read settings");
                assert!(!body.contains("sk-ant-abcde"));
            }
        }
        assert!(found_settings);
        assert!(path.exists());
        assert!(!path.with_extension("zip.sha256").to_string_lossy().is_empty());
    }
}
