use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use axum::{
    extract::{Multipart, Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use flate2::write::GzEncoder;
use flate2::Compression;
use safeagent_skill_registry::{load_manifest, read_verified_publishers, scan_skill, verify_skill};
use serde::{Deserialize, Serialize};
use tar::Builder;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

pub const PACKAGE_TAR_GZ: &str = "package.tar.gz";

#[derive(Debug)]
pub struct RegistryError {
    pub status: StatusCode,
    pub message: String,
}

impl RegistryError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for RegistryError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({"error": self.message}).to_string();
        (self.status, body).into_response()
    }
}

#[derive(Debug, Clone)]
pub struct RegistryState {
    pub storage_root: PathBuf,
    pub catalog_path: PathBuf,
    pub verified_publishers_path: PathBuf,
    pub index: Arc<Mutex<RegistryIndex>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryResponse {
    pub accepted: bool,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RegistryIndex {
    pub skills: BTreeMap<String, SkillIndex>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SkillIndex {
    pub versions: BTreeMap<String, VersionIndex>,
    pub download_count: u64,
    pub reported_malicious: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VersionIndex {
    pub version: String,
    pub channel: String,
    pub publisher_id: String,
    pub signing_key_id: String,
    pub published_at: u64,
    pub package_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VersionResponse {
    pub version: String,
    pub channel: String,
    pub published_at: u64,
    pub package_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReputationResponse {
    pub skill_id: String,
    pub score: i64,
    pub download_count: u64,
    pub verified: bool,
    pub scan_clean: bool,
}

impl RegistryState {
    pub async fn load_index(path: &Path) -> Result<RegistryIndex, RegistryError> {
        if let Ok(raw) = fs::read_to_string(path).await {
            let parsed = serde_json::from_str::<RegistryIndex>(&raw)
                .map_err(|err| RegistryError::internal(format!("invalid catalog: {err}")))?;
            return Ok(parsed);
        }
        Ok(RegistryIndex::default())
    }

    pub async fn save_index(&self) -> Result<(), RegistryError> {
        let index = self.index.lock().await;
        let payload = serde_json::to_vec_pretty(&*index)
            .map_err(|err| RegistryError::internal(format!("catalog serialize: {err}")))?;
        fs::write(&self.catalog_path, payload)
            .await
            .map_err(|err| RegistryError::internal(format!("catalog write: {err}")))
    }
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub bind: SocketAddr,
    pub storage_root: PathBuf,
    pub verified_publishers: PathBuf,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from_str("127.0.0.1:8080").expect("bind parse"),
            storage_root: PathBuf::from("registry_store"),
            verified_publishers: PathBuf::from("registry/publishers/verified.json"),
        }
    }
}

pub async fn run_server(config: RunConfig) -> Result<(), RegistryError> {
    fs::create_dir_all(&config.storage_root)
        .await
        .map_err(|err| RegistryError::internal(format!("create storage: {err}")))?;
    let catalog_path = config.storage_root.join("catalog.json");

    let index = RegistryState::load_index(&catalog_path).await?;
    let state = RegistryState {
        storage_root: config.storage_root,
        catalog_path,
        verified_publishers_path: config.verified_publishers,
        index: Arc::new(Mutex::new(index)),
    };

    let app = app_router(state);
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|err| RegistryError::internal(format!("bind failed: {err}")))?;
    axum::serve(listener, app)
        .await
        .map_err(|err| RegistryError::internal(format!("serve failed: {err}")))
}

pub fn app_router(state: RegistryState) -> Router {
    Router::new()
        .route("/publish", post(handle_publish))
        .route("/skills", get(list_skills))
        .route("/skills/:id/versions", get(list_versions))
        .route("/skills/:id/:version/download", get(download_skill))
        .route("/skills/:id/reputation", get(skill_reputation))
        .with_state(state)
}

async fn list_skills(State(state): State<RegistryState>) -> Json<Vec<String>> {
    let index = state.index.lock().await;
    let mut ids: Vec<String> = index.skills.keys().cloned().collect();
    ids.sort();
    Json(ids)
}

async fn list_versions(
    State(state): State<RegistryState>,
    AxumPath(skill_id): AxumPath<String>,
) -> Result<Json<Vec<VersionResponse>>, RegistryError> {
    let index = state.index.lock().await;
    let skill = index
        .skills
        .get(&skill_id)
        .ok_or_else(|| RegistryError::not_found(format!("skill not found: {skill_id}")))?;

    let mut versions = skill
        .versions
        .iter()
        .map(|(version, rec)| VersionResponse {
            version: version.clone(),
            channel: rec.channel.clone(),
            published_at: rec.published_at,
            package_path: rec.package_path.clone(),
        })
        .collect::<Vec<_>>();
    versions.sort_by(|a, b| a.version.cmp(&b.version));
    Ok(Json(versions))
}

async fn skill_reputation(
    State(state): State<RegistryState>,
    AxumPath(skill_id): AxumPath<String>,
) -> Result<Json<ReputationResponse>, RegistryError> {
    let index = state.index.lock().await;
    let skill = index
        .skills
        .get(&skill_id)
        .ok_or_else(|| RegistryError::not_found(format!("skill not found: {skill_id}")))?;

    let latest = skill
        .versions
        .iter()
        .max_by(|a, b| a.1.published_at.cmp(&b.1.published_at))
        .map(|(_, entry)| entry)
        .ok_or_else(|| RegistryError::not_found("no versions for skill"))?;

    let publishers = read_verified_publishers(&state.verified_publishers_path)
        .map_err(|err| RegistryError::internal(format!("load verified publishers: {err}")))?;
    let verified = publishers
        .publishers
        .get(&latest.publisher_id)
        .is_some_and(|keys| {
            keys.iter()
                .any(|entry| entry.key_id == latest.signing_key_id)
        });

    let score = if verified { 15 } else { 0 }
        + i64::try_from(skill.download_count / 100).unwrap_or(0)
        - if skill.reported_malicious { 50 } else { 0 };

    Ok(Json(ReputationResponse {
        skill_id,
        score,
        download_count: skill.download_count,
        verified,
        scan_clean: true,
    }))
}

async fn handle_publish(
    State(state): State<RegistryState>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, RegistryError> {
    let mut files = BTreeMap::<String, Vec<u8>>::new();
    let mut channel = String::from("stable");

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| RegistryError::bad_request(format!("invalid multipart: {err}")))?
    {
        let name = field
            .name()
            .map(|value| value.to_string())
            .ok_or_else(|| RegistryError::bad_request("multipart part has no name"))?;

        if name == "channel" {
            let value = field.text().await.map_err(|err| {
                RegistryError::bad_request(format!("invalid channel field: {err}"))
            })?;
            if !matches!(value.as_str(), "stable" | "canary") {
                return Err(RegistryError::bad_request(
                    "channel must be stable or canary",
                ));
            }
            channel = value;
            continue;
        }

        let bytes = field
            .bytes()
            .await
            .map_err(|err| RegistryError::bad_request(format!("invalid upload data: {err}")))?;
        files.insert(name, bytes.to_vec());
    }

    let manifest_bytes = files
        .remove("manifest")
        .ok_or_else(|| RegistryError::bad_request("missing manifest"))?;
    let payload_bytes = files
        .remove("payload")
        .ok_or_else(|| RegistryError::bad_request("missing payload"))?;
    let signature_bytes = files
        .remove("signature")
        .ok_or_else(|| RegistryError::bad_request("missing signature"))?;
    let checksums_bytes = files
        .remove("checksums")
        .ok_or_else(|| RegistryError::bad_request("missing checksums"))?;

    let skill_root = stage_package(
        &state.storage_root,
        manifest_bytes,
        payload_bytes,
        signature_bytes,
        checksums_bytes,
    )
    .await
    .map_err(|err| RegistryError::bad_request(err.to_string()))?;

    let manifest = load_manifest(&skill_root).map_err(|err| {
        RegistryError::bad_request(format!("manifest parse/validation failed: {err}"))
    })?;

    let verify_result =
        verify_skill(&skill_root, &state.verified_publishers_path).map_err(|err| {
            RegistryError::bad_request(format!("signature verification failed: {err}"))
        })?;

    scan_skill(&skill_root)
        .map_err(|err| RegistryError::bad_request(format!("scan failed: {err}")))?;

    let published_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| RegistryError::internal(format!("time failed: {err}")))?
        .as_secs();

    let skill_id = manifest.id;
    let skill_version = manifest.version;
    let publisher_id = verify_result.publisher_id;
    let signing_key_id = verify_result.signing_key_id;
    let mut index = state.index.lock().await;
    let skill_entry = index.skills.entry(skill_id.clone()).or_default();
    if skill_entry.versions.contains_key(&skill_version) {
        return Err(RegistryError::conflict(format!(
            "version already exists: {}",
            skill_version
        )));
    }

    let destination = state.storage_root.join(&skill_id).join(&skill_version);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .await
            .map_err(|err| RegistryError::internal(format!("create destination: {err}")))?;
    }
    fs::remove_dir_all(&destination)
        .await
        .or_else(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(err)
            }
        })
        .map_err(|err| RegistryError::internal(format!("cleanup destination: {err}")))?;
    fs::rename(&skill_root, &destination)
        .await
        .map_err(|err| RegistryError::internal(format!("move package: {err}")))?;

    let package_archive = destination.join(PACKAGE_TAR_GZ);
    create_package_archive(&destination, &package_archive)
        .await
        .map_err(|err| RegistryError::internal(format!("archive package: {err}")))?;

    skill_entry.versions.insert(
        skill_version.clone(),
        VersionIndex {
            version: skill_version.clone(),
            channel,
            publisher_id,
            signing_key_id,
            published_at,
            package_path: package_archive
                .to_str()
                .ok_or_else(|| RegistryError::internal("non-utf8 package path"))?
                .to_string(),
        },
    );

    drop(index);
    state
        .save_index()
        .await
        .map_err(|err| RegistryError::internal(format!("catalog save: {err}")))?;

    Ok(Json(RegistryResponse {
        accepted: true,
        reason: format!("published {}@{}", skill_id, skill_version),
    }))
}

async fn download_skill(
    State(state): State<RegistryState>,
    AxumPath((id, version)): AxumPath<(String, String)>,
) -> Result<Response, RegistryError> {
    let package_path = {
        let index = state.index.lock().await;
        let entry = index
            .skills
            .get(&id)
            .ok_or_else(|| RegistryError::not_found(format!("skill not found: {id}")))?;
        let version_entry = entry.versions.get(&version).ok_or_else(|| {
            RegistryError::not_found(format!("version not found: {id}/{version}"))
        })?;
        PathBuf::from(&version_entry.package_path)
    };

    let bytes = fs::read(&package_path)
        .await
        .map_err(|err| RegistryError::internal(format!("read package: {err}")))?;

    {
        let mut index = state.index.lock().await;
        if let Some(entry) = index.skills.get_mut(&id) {
            entry.download_count = entry.download_count.saturating_add(1);
        }
    }
    state
        .save_index()
        .await
        .map_err(|err| RegistryError::internal(format!("catalog save: {err}")))?;

    let mut headers = HeaderMap::new();
    headers.append(
        "content-type",
        axum::http::header::HeaderValue::from_static("application/gzip"),
    );
    headers.append(
        "content-disposition",
        axum::http::header::HeaderValue::from_str(&format!(
            "attachment; filename={id}-{version}.tar.gz"
        ))
        .map_err(|err| RegistryError::internal(format!("invalid header: {err}")))?,
    );

    Ok((StatusCode::OK, headers, bytes).into_response())
}

async fn stage_package(
    storage_root: &Path,
    manifest: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
    checksums: Vec<u8>,
) -> std::io::Result<PathBuf> {
    let marker = uuid::Uuid::new_v4().to_string();
    let staging_dir = storage_root.join(".staging").join(marker);
    fs::create_dir_all(&staging_dir).await?;

    write_file(
        &staging_dir.join(safeagent_skill_registry::MANIFEST_FILE),
        manifest,
    )
    .await?;
    write_file(
        &staging_dir.join(safeagent_skill_registry::PAYLOAD_TAR_FILE),
        payload,
    )
    .await?;
    write_file(
        &staging_dir.join(safeagent_skill_registry::SIGNATURE_FILE),
        signature,
    )
    .await?;
    write_file(
        &staging_dir.join(safeagent_skill_registry::CHECKSUM_FILE),
        checksums,
    )
    .await?;
    Ok(staging_dir)
}

async fn write_file(path: &Path, bytes: Vec<u8>) -> std::io::Result<()> {
    let mut file = File::create(path).await?;
    file.write_all(&bytes).await
}

async fn create_package_archive(src_dir: &Path, out_path: &Path) -> std::io::Result<()> {
    let file = std::fs::File::create(out_path)?;
    let encoder = GzEncoder::new(file, Compression::default());
    let mut archive = Builder::new(encoder);

    for item in [
        safeagent_skill_registry::MANIFEST_FILE,
        safeagent_skill_registry::PAYLOAD_TAR_FILE,
        safeagent_skill_registry::SIGNATURE_FILE,
        safeagent_skill_registry::CHECKSUM_FILE,
    ] {
        archive.append_path_with_name(src_dir.join(item), item)?;
    }

    let encoder = archive.into_inner()?;
    encoder.finish()?;
    Ok(())
}

impl Display for RegistryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<std::io::Error> for RegistryError {
    fn from(err: std::io::Error) -> Self {
        RegistryError::internal(err.to_string())
    }
}
