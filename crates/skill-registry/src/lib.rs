use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::{Archive, Builder};

pub const MANIFEST_FILE: &str = "skill.toml";
pub const PAYLOAD_TAR_FILE: &str = "payload.tar.gz";
pub const SIGNATURE_FILE: &str = "signature.sig";
pub const CHECKSUM_FILE: &str = "checksums.json";

const ALLOWED_SIGNATURE_SCHEME: &str = "ed25519";
const FORBIDDEN_PATTERNS: [&str; 5] = ["curl|sh", "wget|sh", "rm -rf", "mkfs", "169.254.169.254"];
const PERMISSION_MARKERS: [&str; 4] = ["setuid", "chmod 777", "chown", "chmod +s"];
const FORBIDDEN_PATH_PREFIXES: [&str; 3] = ["/etc", ".ssh", ".well-known"];

#[derive(Debug)]
pub enum RegistryError {
    Io(io::Error),
    Toml(toml::de::Error),
    Json(serde_json::Error),
    Crypto(String),
    Verify(String),
    Scan(Vec<String>),
    Invalid(String),
}

impl Display for RegistryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io: {err}"),
            Self::Toml(err) => write!(f, "toml: {err}"),
            Self::Json(err) => write!(f, "json: {err}"),
            Self::Crypto(err) => write!(f, "crypto: {err}"),
            Self::Verify(err) => write!(f, "verify: {err}"),
            Self::Scan(reasons) => write!(f, "scan: {}", reasons.join(", ")),
            Self::Invalid(err) => write!(f, "invalid: {err}"),
        }
    }
}

impl From<io::Error> for RegistryError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}
impl From<toml::de::Error> for RegistryError {
    fn from(err: toml::de::Error) -> Self {
        Self::Toml(err)
    }
}
impl From<serde_json::Error> for RegistryError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

pub type Result<T> = std::result::Result<T, RegistryError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkillManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub entrypoint: String,
    pub description: String,
    pub required_scopes: Vec<String>,
    pub publisher_id: String,
    pub signing_key_id: String,
    pub files: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PackageChecksums {
    pub manifest_sha256: String,
    pub payload_sha256: String,
    pub file_hashes: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureEnvelope {
    pub key_id: String,
    pub algorithm: String,
    pub signature: String,
    pub manifest_sha256: String,
    pub payload_sha256: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct VerifiedPublishers {
    pub publishers: BTreeMap<String, Vec<VerifiedPublicKey>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifiedPublicKey {
    pub key_id: String,
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub passed: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResult {
    pub publisher_id: String,
    pub signing_key_id: String,
    pub passed: bool,
}

pub struct PackagingArtifacts {
    pub manifest_sha256: String,
    pub payload_sha256: String,
}

pub fn pack_skill(
    source_dir: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
) -> Result<PackagingArtifacts> {
    let source_dir = source_dir.as_ref();
    let out_dir = out_dir.as_ref();
    if out_dir.exists() {
        fs::remove_dir_all(out_dir)?;
    }
    fs::create_dir_all(out_dir)?;

    let manifest_raw = fs::read_to_string(source_dir.join(MANIFEST_FILE))?;
    let manifest: SkillManifest = toml::from_str(&manifest_raw)?;
    validate_manifest(&manifest)?;

    let payload_path = out_dir.join(PAYLOAD_TAR_FILE);
    write_payload_tar(source_dir, &manifest.files, &payload_path)?;

    let manifest_sha256 = sha256_hex(manifest_raw.as_bytes());
    let payload_bytes = fs::read(&payload_path)?;
    let payload_sha256 = sha256_hex(&payload_bytes);

    let mut file_hashes = BTreeMap::new();
    file_hashes.insert(MANIFEST_FILE.to_string(), manifest_sha256.clone());
    file_hashes.insert(PAYLOAD_TAR_FILE.to_string(), payload_sha256.clone());
    let checksums = PackageChecksums {
        manifest_sha256: manifest_sha256.clone(),
        payload_sha256: payload_sha256.clone(),
        file_hashes,
    };

    fs::write(out_dir.join(MANIFEST_FILE), manifest_raw)?;
    fs::write(
        out_dir.join(CHECKSUM_FILE),
        serde_json::to_vec_pretty(&checksums)?,
    )?;
    Ok(PackagingArtifacts {
        manifest_sha256,
        payload_sha256,
    })
}

pub fn sign_skill(pkg_dir: impl AsRef<Path>, private_key_path: impl AsRef<Path>) -> Result<()> {
    let pkg_dir = pkg_dir.as_ref();
    let manifest = load_manifest(pkg_dir)?;
    let checks = load_checksums(pkg_dir)?;
    validate_package_checksums(pkg_dir, &manifest, &checks)?;

    let private_key = parse_private_key(&fs::read_to_string(private_key_path)?)?;
    let signing_key = SigningKey::from_bytes(private_key.as_slice().try_into().map_err(|_| {
        RegistryError::Invalid("private key should be 32-byte Ed25519 seed".to_string())
    })?);

    let canonical_manifest = canonical_manifest_bytes(&manifest)?;
    let message = signing_message(&canonical_manifest, &checks.payload_sha256);
    let signature = signing_key.sign(&message);

    let envelope = SignatureEnvelope {
        key_id: manifest.signing_key_id,
        algorithm: ALLOWED_SIGNATURE_SCHEME.to_string(),
        signature: hex::encode(signature.to_bytes()),
        manifest_sha256: checks.manifest_sha256,
        payload_sha256: checks.payload_sha256,
    };
    fs::write(
        pkg_dir.join(SIGNATURE_FILE),
        serde_json::to_vec_pretty(&envelope)?,
    )?;
    Ok(())
}

pub fn verify_skill(
    pkg_dir: impl AsRef<Path>,
    verified_file: impl AsRef<Path>,
) -> Result<VerifyResult> {
    let pkg_dir = pkg_dir.as_ref();
    let manifest = load_manifest(pkg_dir)?;
    let checks = load_checksums(pkg_dir)?;
    let signature = load_signature(pkg_dir)?;

    validate_package_checksums(pkg_dir, &manifest, &checks)?;
    if signature.algorithm != ALLOWED_SIGNATURE_SCHEME {
        return Err(RegistryError::Invalid(format!(
            "unsupported signature algorithm {}",
            signature.algorithm
        )));
    }
    if signature.key_id != manifest.signing_key_id {
        return Err(RegistryError::Verify(
            "signature key id does not match manifest signing_key_id".to_string(),
        ));
    }
    if signature.manifest_sha256 != checks.manifest_sha256
        || signature.payload_sha256 != checks.payload_sha256
    {
        return Err(RegistryError::Verify(
            "checksums in manifest signature do not match checks file".to_string(),
        ));
    }

    let publishers = read_verified_publishers(verified_file)?;
    let keys = publishers
        .publishers
        .get(&manifest.publisher_id)
        .ok_or_else(|| RegistryError::Verify("publisher not trusted".to_string()))?;
    let selected = keys
        .iter()
        .find(|key| key.key_id == manifest.signing_key_id)
        .ok_or_else(|| RegistryError::Verify("signing key not trusted".to_string()))?;

    let verifying_key = parse_public_key(&selected.public_key)?;
    let canonical_manifest = canonical_manifest_bytes(&manifest)?;
    let message = signing_message(&canonical_manifest, &checks.payload_sha256);
    let raw_sig = parse_hex_or_base64(&signature.signature)?;
    let parsed_sig = Signature::from_slice(&raw_sig)
        .map_err(|e| RegistryError::Verify(format!("invalid signature bytes: {e}")))?;

    verifying_key
        .verify(&message, &parsed_sig)
        .map_err(|e| RegistryError::Verify(format!("ed25519 verify failed: {e}")))?;

    Ok(VerifyResult {
        publisher_id: manifest.publisher_id,
        signing_key_id: signature.key_id,
        passed: true,
    })
}

pub fn scan_skill(pkg_dir: impl AsRef<Path>) -> Result<ScanResult> {
    let pkg_dir = pkg_dir.as_ref();
    let mut reasons = Vec::new();

    let manifest_raw = fs::read_to_string(pkg_dir.join(MANIFEST_FILE))?;
    let manifest: SkillManifest = toml::from_str(&manifest_raw)?;
    for scope in &manifest.required_scopes {
        if scope.trim() == "*" {
            reasons.push("required_scopes contains wildcard '*'".to_string());
        }
    }
    for file in &manifest.files {
        validate_source_path(file, &mut reasons);
        if file.ends_with('/') {
            reasons.push(format!("manifest file points to a directory: {file}"));
        }
    }
    if manifest
        .files
        .iter()
        .all(|entry| entry != &manifest.entrypoint)
    {
        reasons.push("entrypoint must be included in files list".to_string());
    }

    check_forbidden_content("manifest", &manifest_raw, &mut reasons);

    let payload_path = pkg_dir.join(PAYLOAD_TAR_FILE);
    let payload_file = File::open(&payload_path)?;
    let mut archive = Archive::new(GzDecoder::new(payload_file));
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry
            .path()?
            .to_string_lossy()
            .replace('\\', "/")
            .to_lowercase();
        if path.starts_with('/') {
            reasons.push(format!("payload contains absolute path: {path}"));
        }
        if path.contains("..") {
            reasons.push(format!("payload contains traversal path: {path}"));
        }
        if FORBIDDEN_PATH_PREFIXES
            .iter()
            .any(|prefix| path.contains(prefix))
        {
            reasons.push(format!("payload contains forbidden path token: {path}"));
        }

        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        check_forbidden_content(&path, &String::from_utf8_lossy(&bytes), &mut reasons);
    }

    if reasons.is_empty() {
        Ok(ScanResult {
            passed: true,
            reasons,
        })
    } else {
        Err(RegistryError::Scan(reasons.clone()))
    }
}

pub fn add_verified_publisher(
    store_path: impl AsRef<Path>,
    publisher_id: String,
    key_id: String,
    public_key: String,
) -> Result<()> {
    let store_path = store_path.as_ref();
    if let Some(parent) = store_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut stores = load_or_default_publishers(store_path)?;
    let entry = stores.publishers.entry(publisher_id).or_default();
    if let Some(existing) = entry.iter_mut().find(|x| x.key_id == key_id) {
        existing.public_key = public_key;
    } else {
        entry.push(VerifiedPublicKey { key_id, public_key });
    }
    fs::write(store_path, serde_json::to_vec_pretty(&stores)?)?;
    Ok(())
}

fn validate_manifest(manifest: &SkillManifest) -> Result<()> {
    if manifest.id.trim().is_empty() {
        return Err(RegistryError::Invalid(
            "manifest.id is required".to_string(),
        ));
    }
    if manifest.publisher_id.trim().is_empty() {
        return Err(RegistryError::Invalid(
            "manifest.publisher_id is required".to_string(),
        ));
    }
    if manifest.signing_key_id.trim().is_empty() {
        return Err(RegistryError::Invalid(
            "manifest.signing_key_id is required".to_string(),
        ));
    }
    if manifest.files.is_empty() {
        return Err(RegistryError::Invalid(
            "manifest.files is empty".to_string(),
        ));
    }
    if manifest.required_scopes.is_empty() {
        return Err(RegistryError::Invalid(
            "manifest.required_scopes is empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_source_path(file: &str, reasons: &mut Vec<String>) {
    let normalized = file.to_lowercase();
    if normalized.starts_with('/')
        || normalized.contains("../")
        || normalized.contains("..\\")
        || normalized.contains("..") && normalized == ".."
    {
        reasons.push(format!("invalid manifest path: {file}"));
    }
    if normalized.contains("~/.ssh") || normalized.contains("/etc/") || normalized.contains(" c:\\")
    {
        reasons.push(format!("forbidden manifest path: {file}"));
    }
}

fn write_payload_tar(source_dir: &Path, files: &[String], out: &Path) -> Result<()> {
    let file = File::create(out)?;
    let encoder = GzEncoder::new(file, Compression::default());
    let mut builder = Builder::new(encoder);
    for entry in files {
        let path = Path::new(entry);
        validate_file_path(entry)?;
        let source = source_dir.join(path);
        if !source.exists() {
            return Err(RegistryError::Invalid(format!("missing file: {entry}")));
        }
        if !source.is_file() {
            return Err(RegistryError::Invalid(format!(
                "manifest file must be regular file: {entry}"
            )));
        }
        builder.append_path_with_name(&source, path)?;
    }
    let encoder = builder.into_inner()?;
    let mut wrapped = encoder.finish()?;
    wrapped.flush()?;
    Ok(())
}

pub fn load_manifest(pkg_dir: impl AsRef<Path>) -> Result<SkillManifest> {
    let pkg_dir = pkg_dir.as_ref();
    let manifest_raw = fs::read_to_string(pkg_dir.join(MANIFEST_FILE))?;
    let manifest: SkillManifest = toml::from_str(&manifest_raw)?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

pub fn load_checksums(pkg_dir: impl AsRef<Path>) -> Result<PackageChecksums> {
    let pkg_dir = pkg_dir.as_ref();
    let raw = fs::read_to_string(pkg_dir.join(CHECKSUM_FILE))?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn load_signature(pkg_dir: impl AsRef<Path>) -> Result<SignatureEnvelope> {
    let pkg_dir = pkg_dir.as_ref();
    let raw = fs::read_to_string(pkg_dir.join(SIGNATURE_FILE))?;
    Ok(serde_json::from_str(&raw)?)
}

fn validate_file_path(path: &str) -> Result<()> {
    if Path::new(path).is_absolute() {
        return Err(RegistryError::Invalid(format!(
            "absolute paths are not allowed: {path}"
        )));
    }
    if path.contains("..") {
        return Err(RegistryError::Invalid(format!(
            "relative parent segments are not allowed: {path}"
        )));
    }
    if path.contains(".ssh") || path.starts_with("~") {
        return Err(RegistryError::Invalid(format!(
            "forbidden path token in manifest: {path}"
        )));
    }
    Ok(())
}

fn validate_package_checksums(
    pkg_dir: &Path,
    manifest: &SkillManifest,
    checks: &PackageChecksums,
) -> Result<()> {
    let manifest_raw = fs::read_to_string(pkg_dir.join(MANIFEST_FILE))?;
    let manifest_hash = sha256_hex(manifest_raw.as_bytes());
    if checks.manifest_sha256 != manifest_hash {
        return Err(RegistryError::Verify(
            "manifest checksum mismatch".to_string(),
        ));
    }
    let payload = fs::read(pkg_dir.join(PAYLOAD_TAR_FILE))?;
    let payload_hash = sha256_hex(&payload);
    if checks.payload_sha256 != payload_hash {
        return Err(RegistryError::Verify(
            "payload checksum mismatch".to_string(),
        ));
    }
    if checks
        .file_hashes
        .get(MANIFEST_FILE)
        .is_none_or(|actual| actual != &manifest_hash)
    {
        return Err(RegistryError::Verify(
            "manifest hash map mismatch".to_string(),
        ));
    }
    if checks
        .file_hashes
        .get(PAYLOAD_TAR_FILE)
        .is_none_or(|actual| actual != &payload_hash)
    {
        return Err(RegistryError::Verify(
            "payload hash map mismatch".to_string(),
        ));
    }
    if !manifest
        .files
        .iter()
        .any(|entry| entry == &manifest.entrypoint)
    {
        return Err(RegistryError::Invalid(
            "manifest.entrypoint must be part of files".to_string(),
        ));
    }
    Ok(())
}

fn canonical_manifest_bytes(manifest: &SkillManifest) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(manifest)?)
}

fn signing_message(manifest_bytes: &[u8], payload_sha256: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(manifest_bytes.len() + payload_sha256.len());
    msg.extend_from_slice(manifest_bytes);
    msg.extend_from_slice(payload_sha256.as_bytes());
    msg
}

fn check_forbidden_content(path: &str, text: &str, reasons: &mut Vec<String>) {
    let lowered = text.to_lowercase();
    for pattern in FORBIDDEN_PATTERNS {
        if lowered.contains(pattern) {
            reasons.push(format!("{} contains forbidden pattern '{pattern}'", path));
        }
    }
    for marker in PERMISSION_MARKERS {
        if lowered.contains(marker) {
            reasons.push(format!("{} contains suspicious marker '{}'", path, marker));
        }
    }
}

fn parse_private_key(raw: &str) -> Result<Vec<u8>> {
    parse_hex_or_base64(raw)
}

fn parse_public_key(raw: &str) -> Result<VerifyingKey> {
    let bytes = parse_hex_or_base64(raw)?;
    if bytes.len() != 32 {
        return Err(RegistryError::Invalid(
            "public key must be 32 bytes".to_string(),
        ));
    }
    VerifyingKey::from_bytes(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| RegistryError::Crypto("invalid public key length".to_string()))?,
    )
    .map_err(|e| RegistryError::Crypto(format!("invalid public key: {e}")))
}

fn parse_hex_or_base64(raw: &str) -> Result<Vec<u8>> {
    let trimmed = raw.trim();
    let hex = trimmed.chars().all(|c| c.is_ascii_hexdigit()) && trimmed.len().is_multiple_of(2);
    if hex && trimmed.len() >= 64 {
        let decoded = hex::decode(trimmed)
            .map_err(|e| RegistryError::Invalid(format!("invalid hex key: {e}")))?;
        if decoded.is_empty() {
            return Err(RegistryError::Invalid("empty key".to_string()));
        }
        return Ok(decoded);
    }
    let decoded = STANDARD
        .decode(trimmed.as_bytes())
        .map_err(|e| RegistryError::Invalid(format!("invalid base64 key: {e}")))?;
    if decoded.is_empty() {
        return Err(RegistryError::Invalid("empty key".to_string()));
    }
    Ok(decoded)
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn read_verified_publishers(path: impl AsRef<Path>) -> Result<VerifiedPublishers> {
    if !path.as_ref().exists() {
        return Err(RegistryError::Invalid(format!(
            "missing verified publishers file: {}",
            path.as_ref().display()
        )));
    }
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn load_or_default_publishers(path: impl AsRef<Path>) -> Result<VerifiedPublishers> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(VerifiedPublishers::default());
    }
    read_verified_publishers(path)
}

pub fn package_contains_required_files(pkg_dir: impl AsRef<Path>) -> bool {
    let pkg_dir = pkg_dir.as_ref();
    pkg_dir.join(MANIFEST_FILE).is_file()
        && pkg_dir.join(PAYLOAD_TAR_FILE).is_file()
        && pkg_dir.join(SIGNATURE_FILE).is_file()
        && pkg_dir.join(CHECKSUM_FILE).is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(prefix: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        dir.push(format!("safeagent-skill-registry-{prefix}-{seed}"));
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn write_sample_tree(path: &Path, key_id: &str) {
        let manifest = format!(
            r#"
id = "sample.safeagent.echo"
name = "sample"
version = "0.1.0"
entrypoint = "entry.sh"
description = "sample"
required_scopes = ["skill:echo"]
publisher_id = "sample-publisher"
signing_key_id = "{key_id}"
files = ["entry.sh"]
"#
        );
        fs::write(path.join(MANIFEST_FILE), manifest).expect("write manifest");
        fs::write(path.join("entry.sh"), "#!/bin/sh\necho ok\n").expect("write entry");
    }

    fn make_key_pair(seed: u8) -> (SigningKey, VerifyingKey) {
        let mut private_key = [0u8; 32];
        private_key.fill(seed);
        let signing = SigningKey::from_bytes(&private_key);
        (signing.clone(), signing.verifying_key())
    }

    fn setup_store(path: &Path, key_id: &str, verify_key: &str) -> PathBuf {
        let store = VerifiedPublishers {
            publishers: BTreeMap::from([(
                "sample-publisher".to_string(),
                vec![VerifiedPublicKey {
                    key_id: key_id.to_string(),
                    public_key: verify_key.to_string(),
                }],
            )]),
        };
        let file = path.join("verified.json");
        fs::write(&file, serde_json::to_vec_pretty(&store).unwrap()).expect("write store");
        file
    }

    #[test]
    fn signature_verify_and_tamper_manifest_fails() {
        let src = temp_dir("sig");
        write_sample_tree(&src, "k1");
        let (signing, verifying) = make_key_pair(11);
        let pkg = temp_dir("sig-pkg");
        let _ = pack_skill(&src, &pkg).expect("pack");
        let key_path = src.join("key.txt");
        fs::write(&key_path, hex::encode(signing.to_bytes())).expect("write key");
        sign_skill(&pkg, &key_path).expect("sign");
        let store = setup_store(&src, "k1", &hex::encode(verifying.to_bytes()));
        verify_skill(&pkg, &store).expect("verify");

        let mut manifest = fs::read_to_string(pkg.join(MANIFEST_FILE)).expect("load manifest");
        manifest = manifest.replace("sample.safeagent.echo", "sample.safeagent.echo.tamper");
        fs::write(pkg.join(MANIFEST_FILE), manifest).expect("tamper manifest");
        let err = verify_skill(&pkg, &store).unwrap_err();
        assert!(
            matches!(err, RegistryError::Verify(_) | RegistryError::Invalid(_)),
            "{err}"
        );
    }

    #[test]
    fn signature_tamper_payload_fails() {
        let src = temp_dir("payload");
        write_sample_tree(&src, "k1");
        let (signing, verifying) = make_key_pair(12);
        let pkg = temp_dir("payload-pkg");
        let _ = pack_skill(&src, &pkg).expect("pack");
        let key_path = src.join("key.txt");
        fs::write(&key_path, hex::encode(signing.to_bytes())).expect("write key");
        sign_skill(&pkg, &key_path).expect("sign");
        let store = setup_store(&src, "k1", &hex::encode(verifying.to_bytes()));
        verify_skill(&pkg, &store).expect("verify");

        fs::write(pkg.join(PAYLOAD_TAR_FILE), b"corrupt").expect("tamper payload");
        let err = verify_skill(&pkg, &store).unwrap_err();
        assert!(matches!(err, RegistryError::Verify(_)), "{err}");
    }

    #[test]
    fn scan_rejects_forbidden_content() {
        let src = temp_dir("scan");
        fs::write(
            src.join(MANIFEST_FILE),
            r#"
id = "sample.safeagent.echo"
name = "sample"
version = "0.1.0"
entrypoint = "entry.sh"
description = "sample"
required_scopes = ["*"]
publisher_id = "sample-publisher"
signing_key_id = "k1"
files = ["entry.sh"]
"#,
        )
        .expect("write manifest");
        fs::write(src.join("entry.sh"), "echo curl|sh abuse\n").expect("write entry");
        let pkg = temp_dir("scan-pkg");
        let _ = pack_skill(&src, &pkg).expect("pack");
        let err = scan_skill(&pkg).unwrap_err();
        match err {
            RegistryError::Scan(reasons) => {
                assert!(
                    reasons.iter().any(|r| r.contains("forbidden pattern")),
                    "{reasons:?}"
                );
            }
            _ => panic!("expected scan fail"),
        }
    }

    #[test]
    fn integration_pack_sign_scan_verify_passes() {
        let src = temp_dir("integration");
        write_sample_tree(&src, "k1");
        let (signing, verifying) = make_key_pair(13);
        let pkg = temp_dir("integration-pkg");
        pack_skill(&src, &pkg).expect("pack");
        let key_path = src.join("key.txt");
        fs::write(&key_path, hex::encode(signing.to_bytes())).expect("write key");
        sign_skill(&pkg, &key_path).expect("sign");
        let store = setup_store(&src, "k1", &hex::encode(verifying.to_bytes()));
        verify_skill(&pkg, &store).expect("verify");
        scan_skill(&pkg).expect("scan");
    }
}
