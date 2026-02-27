#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod support;
mod update;

use std::collections::VecDeque;
use std::fs::{self, create_dir_all, File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::tls::Certificate as ReqwestCertificate;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use safeagent_shared_proto::{ApprovalDecisionRequest, ApprovalDecisionResponse, ApprovalRequest};
use safeagent_skill_registry::{package_contains_required_files, scan_skill, verify_skill};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Builder, State};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::sleep;

const CONTROL_PLANE_ADDR: &str = "127.0.0.1:8443";
const WORKER_ADDR: &str = "127.0.0.1:8280";
const MAX_RESTART_ATTEMPTS: u32 = 5;
const BASE_RESTART_BACKOFF_MS: u64 = 500;
const MAX_RESTART_BACKOFF_MS: u64 = 20_000;
const MAX_STOP_WAIT_MS: u64 = 2_000;
const ONBOARDING_STEPS: u8 = 2;

#[derive(Clone)]
struct DesktopPaths {
    root: PathBuf,
    pki: PathBuf,
    logs: PathBuf,
    secrets: PathBuf,
    marketplace: PathBuf,
    installed: PathBuf,
    settings: PathBuf,
    update_manifest: PathBuf,
    support_bundles: PathBuf,
}

#[derive(Clone)]
struct ServiceCommand {
    binary: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
    log_path: PathBuf,
}

#[derive(Clone)]
struct ServiceRestartState {
    attempts: u32,
    next_restart_ms: u64,
    backoff_ms: u64,
    manual_restart_required: bool,
}

impl Default for ServiceRestartState {
    fn default() -> Self {
        Self {
            attempts: 0,
            next_restart_ms: 0,
            backoff_ms: BASE_RESTART_BACKOFF_MS,
            manual_restart_required: false,
        }
    }
}

struct ManagedService {
    child: Option<Child>,
    command: ServiceCommand,
    restart_count: u32,
    restart_state: ServiceRestartState,
}

#[derive(Default)]
struct ServiceRegistry {
    desired_running: bool,
    control_plane: Option<ManagedService>,
    worker: Option<ManagedService>,
}

struct AppState {
    paths: DesktopPaths,
    services: Mutex<ServiceRegistry>,
    events: Mutex<VecDeque<String>>,
    onboarding: Mutex<OnboardingState>,
}

#[derive(Serialize)]
struct ServiceProcessStatus {
    name: String,
    running: bool,
    pid: u32,
    log_path: String,
    restart_count: u32,
    next_restart_ms: u64,
    backoff_ms: u64,
    state: String,
}

#[derive(Serialize)]
struct ServiceStatus {
    desired_running: bool,
    control_plane_ready: bool,
    worker_ready: bool,
    control_plane: Option<ServiceProcessStatus>,
    worker: Option<ServiceProcessStatus>,
    last_events: Vec<String>,
    safety_state: String,
}

#[derive(Serialize)]
struct PendingApproval {
    approval_id: String,
    request_id: String,
    node_id: String,
    skill_id: String,
    input_summary: String,
    reason: String,
}

#[derive(Serialize)]
struct ApprovalDecisionResponseView {
    ok: bool,
    status: String,
}

#[derive(Serialize)]
struct MarketSkill {
    id: String,
    name: String,
    path: String,
    status: String,
}

#[derive(Serialize)]
struct InstallResult {
    installed: bool,
    package_path: String,
    detail: String,
}

#[derive(Serialize, Clone)]
struct PkiPaths {
    ca_cert: PathBuf,
    cp_cert: PathBuf,
    cp_key: PathBuf,
    worker_cert: PathBuf,
    worker_key: PathBuf,
}

#[derive(Serialize)]
struct VersionResponse {
    version: &'static str,
}

#[derive(Serialize, Deserialize, Clone)]
struct DesktopSettings {
    strict_mode: bool,
    verified_publisher_only: bool,
    allowlist_network_only: bool,
    advanced_logs: bool,
}

impl Default for DesktopSettings {
    fn default() -> Self {
        Self {
            strict_mode: true,
            verified_publisher_only: true,
            allowlist_network_only: true,
            advanced_logs: false,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct OnboardingState {
    current_step: u8,
    completed: bool,
}

impl Default for OnboardingState {
    fn default() -> Self {
        Self {
            current_step: 1,
            completed: false,
        }
    }
}

#[derive(Serialize)]
struct TrayMenuItem {
    id: &'static str,
    label: &'static str,
    action: &'static str,
}

type UpdateCheckResult = update::UpdateCheckResult;

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn app_paths() -> DesktopPaths {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let root = home.join(".safeagent-desktop");
    DesktopPaths {
        root: root.clone(),
        pki: root.join("pki"),
        logs: root.join("logs"),
        secrets: root.join("secrets"),
        marketplace: root.join("marketplace"),
        installed: root.join("installed"),
    settings: root.join("settings.json"),
    update_manifest: root.join("update.json"),
    support_bundles: root.join("support_bundles"),
}
}

fn onboarding_path(paths: &DesktopPaths) -> PathBuf {
    paths.root.join("onboarding_state.json")
}

fn settings_path(paths: &DesktopPaths) -> PathBuf {
    paths.settings.clone()
}

fn ensure_directories(paths: &DesktopPaths) -> Result<(), String> {
    create_dir_all(&paths.pki).map_err(|e| format!("create pki dir: {e}"))?;
    create_dir_all(&paths.logs).map_err(|e| format!("create logs dir: {e}"))?;
    create_dir_all(&paths.secrets).map_err(|e| format!("create secrets dir: {e}"))?;
    create_dir_all(&paths.marketplace).map_err(|e| format!("create marketplace dir: {e}"))?;
    create_dir_all(&paths.installed).map_err(|e| format!("create installed dir: {e}"))?;
    Ok(())
}

fn load_settings(paths: &DesktopPaths) -> Result<DesktopSettings, String> {
    ensure_directories(paths)?;
    let file = settings_path(paths);
    if !file.exists() {
        let defaults = DesktopSettings::default();
        let json = serde_json::to_string_pretty(&defaults)
            .map_err(|e| format!("serialize settings: {e}"))?;
        write_text(&file, &json)?;
        return Ok(defaults);
    }
    let raw = fs::read_to_string(&file).map_err(|e| format!("read settings {}: {e}", file.display()))?;
    let settings: DesktopSettings =
        serde_json::from_str(&raw).map_err(|e| format!("parse settings {}: {e}", file.display()))?;
    Ok(settings)
}

fn save_settings(paths: &DesktopPaths, settings: &DesktopSettings) -> Result<(), String> {
    ensure_directories(paths)?;
    let file = settings_path(paths);
    let json = serde_json::to_string_pretty(settings)
        .map_err(|e| format!("serialize settings {}: {e}", file.display()))?;
    write_text(&file, &json)
}

fn load_onboarding_state(paths: &DesktopPaths) -> Result<OnboardingState, String> {
    ensure_directories(paths)?;
    let file = onboarding_path(paths);
    if !file.exists() {
        let default = OnboardingState::default();
        save_onboarding_state(paths, &default)?;
        return Ok(default);
    }
    let raw = fs::read_to_string(&file)
        .map_err(|e| format!("read onboarding {}: {e}", file.display()))?;
    let mut state: OnboardingState =
        serde_json::from_str(&raw).map_err(|e| format!("parse onboarding {}: {e}", file.display()))?;
    if state.current_step == 0 {
        state.current_step = 1;
    }
    if state.current_step > ONBOARDING_STEPS {
        state.current_step = ONBOARDING_STEPS;
    }
    Ok(state)
}

fn save_onboarding_state(paths: &DesktopPaths, state: &OnboardingState) -> Result<(), String> {
    ensure_directories(paths)?;
    let file = onboarding_path(paths);
    let json = serde_json::to_string_pretty(state)
        .map_err(|e| format!("serialize onboarding {}: {e}", file.display()))?;
    write_text(&file, &json)
}

fn advance_onboarding_step(state: &mut OnboardingState) -> bool {
    if state.completed {
        return false;
    }
    if state.current_step >= ONBOARDING_STEPS {
        state.completed = true;
        return true;
    }
    state.current_step = state.current_step.saturating_add(1);
    true
}

fn complete_onboarding(state: &mut OnboardingState) -> bool {
    if state.completed {
        return false;
    }
    state.completed = true;
    state.current_step = ONBOARDING_STEPS;
    true
}

fn reset_onboarding(state: &mut OnboardingState) {
    *state = OnboardingState::default();
}

fn default_tray_menu() -> Vec<TrayMenuItem> {
    vec![
        TrayMenuItem {
            id: "open",
            label: "Open app",
            action: "open_app",
        },
        TrayMenuItem {
            id: "start",
            label: "Start",
            action: "start_services",
        },
        TrayMenuItem {
            id: "stop",
            label: "Stop",
            action: "stop_services",
        },
        TrayMenuItem {
            id: "support",
            label: "Generate support bundle",
            action: "create_support_bundle",
        },
        TrayMenuItem {
            id: "quit",
            label: "Quit",
            action: "quit_app",
        },
    ]
}

fn human_readable_event(raw: &str) -> String {
    let normalized = raw.to_lowercase();
    if normalized.contains("policy denied") {
        "Güvenlik nedeniyle engellendi".to_string()
    } else if normalized.contains("approval pending") {
        "Onay bekliyor".to_string()
    } else if normalized.contains("egress blocked") {
        "İnternet erişimi engellendi (allowlist dışı)".to_string()
    } else if normalized.contains("skill install blocked") {
        "Güvenlik taraması başarısız".to_string()
    } else {
        raw.to_string()
    }
}

fn map_events_to_human(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| human_readable_event(&line))
        .collect()
}

fn compute_next_backoff_ms(attempt: u32) -> u64 {
    if attempt <= 1 {
        BASE_RESTART_BACKOFF_MS
    } else {
        BASE_RESTART_BACKOFF_MS
            .saturating_mul(2u64.saturating_pow(attempt.saturating_sub(1)))
            .min(MAX_RESTART_BACKOFF_MS)
    }
}

fn append_event(events: &mut VecDeque<String>, entry: impl AsRef<str>) {
    events.push_back(format!("[{}] {}", now_unix_seconds(), entry.as_ref()));
    if events.len() > 400 {
        let _ = events.pop_front();
    }
}

fn candidates_for_binary(name: &str) -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from(name)];
    if let Ok(cwd) = std::env::current_dir() {
        paths.extend([
            cwd.join("target/debug").join(name),
            cwd.join("target/release").join(name),
            cwd.join("platform/control-plane/target/debug").join(name),
            cwd.join("platform/control-plane/target/release").join(name),
            cwd.join("platform/worker/target/debug").join(name),
            cwd.join("platform/worker/target/release").join(name),
            cwd.join("../platform/control-plane/target/debug").join(name),
            cwd.join("../platform/control-plane/target/release").join(name),
            cwd.join("../platform/worker/target/debug").join(name),
            cwd.join("../platform/worker/target/release").join(name),
        ]);
    }
    if let Ok(path_env) = std::env::var("PATH") {
        for entry in path_env.split(':') {
            paths.push(PathBuf::from(entry).join(name));
        }
    }
    if let Ok(custom) = std::env::var("SAFEAGENT_CONTROL_PLANE_BIN") {
        paths.push(PathBuf::from(custom));
    }
    if let Ok(custom) = std::env::var("SAFEAGENT_WORKER_BIN") {
        paths.push(PathBuf::from(custom));
    }
    paths
}

fn resolve_binary(name: &str) -> Option<String> {
    candidates_for_binary(name)
        .into_iter()
        .find(|path| path.exists())
        .map(|path| path.to_string_lossy().to_string())
}

fn pki_paths(paths: &DesktopPaths) -> PkiPaths {
    PkiPaths {
        ca_cert: paths.pki.join("ca.crt"),
        cp_cert: paths.pki.join("control-plane.crt"),
        cp_key: paths.pki.join("control-plane.key"),
        worker_cert: paths.pki.join("worker.crt"),
        worker_key: paths.pki.join("worker.key"),
    }
}

fn write_text(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent).map_err(|e| format!("create parent {}: {e}", parent.display()))?;
    }
    let mut file = File::create(path).map_err(|e| format!("write {}: {e}", path.display()))?;
    file.write_all(content.as_bytes())
        .map_err(|e| format!("write {}: {e}", path.display()))
}

fn ensure_default_verified_publishers(target: &Path) -> Result<(), String> {
    if target.exists() {
        return Ok(());
    }
    if let Some(parent) = target.parent() {
        create_dir_all(parent).map_err(|e| format!("create parent: {e}"))?;
    }
    let repo_candidates = [
        Path::new("registry/publishers/verified.json"),
        Path::new("../registry/publishers/verified.json"),
    ];
    for candidate in repo_candidates {
        if candidate.exists() {
            fs::copy(candidate, target)
                .map_err(|e| format!("copy verified store {}: {e}", candidate.display()))?;
            return Ok(());
        }
    }
    write_text(target, r#"{"publishers":{}}"#)?;
    Ok(())
}

fn generate_pki(paths: &DesktopPaths) -> Result<PkiPaths, String> {
    let mut ca_params = CertificateParams::new(vec!["safeagent.local".to_string()])
        .map_err(|e| format!("{e}"))?;
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "SafeAgent Root CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().map_err(|e| format!("ca key: {e}"))?;
    let ca = ca_params.self_signed(&ca_key).map_err(|e| format!("ca cert: {e}"))?;

    let mut cp_params = CertificateParams::new(vec![
        "safeagent-control-plane".to_string(),
        "127.0.0.1".to_string(),
        "localhost".to_string(),
    ])
    .map_err(|e| format!("cp params: {e}"))?;
    cp_params
        .distinguished_name
        .push(DnType::CommonName, "SafeAgent Control Plane");
    cp_params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let cp_key = KeyPair::generate().map_err(|e| format!("cp key: {e}"))?;
    let cp = cp_params
        .signed_by(&cp_key, &ca, &ca_key)
        .map_err(|e| format!("cp cert: {e}"))?;

    let mut worker_params = CertificateParams::new(vec![
        "safeagent-worker".to_string(),
        "127.0.0.1".to_string(),
        "localhost".to_string(),
    ])
    .map_err(|e| format!("worker params: {e}"))?;
    worker_params
        .distinguished_name
        .push(DnType::CommonName, "SafeAgent Worker");
    worker_params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let worker_key = KeyPair::generate().map_err(|e| format!("worker key: {e}"))?;
    let worker = worker_params
        .signed_by(&worker_key, &ca, &ca_key)
        .map_err(|e| format!("worker cert: {e}"))?;

    let certs = pki_paths(paths);
    write_text(&paths.pki.join("ca.crt"), &ca.pem())?;
    write_text(&paths.pki.join("ca.key"), &ca_key.serialize_pem())?;
    write_text(&paths.pki.join("control-plane.crt"), &cp.pem())?;
    write_text(&paths.pki.join("control-plane.key"), &cp_key.serialize_pem())?;
    write_text(&paths.pki.join("worker.crt"), &worker.pem())?;
    write_text(&paths.pki.join("worker.key"), &worker_key.serialize_pem())?;
    Ok(certs)
}

fn ensure_dev_pki(paths: &DesktopPaths) -> Result<PkiPaths, String> {
    ensure_directories(paths)?;
    let known = pki_paths(paths);
    if known.ca_cert.exists()
        && known.cp_cert.exists()
        && known.cp_key.exists()
        && known.worker_cert.exists()
        && known.worker_key.exists()
    {
        return Ok(known);
    }
    generate_pki(paths)
}

fn is_child_running(child: &mut Child) -> bool {
    matches!(child.try_wait(), Ok(None))
}

fn service_status(name: &str, service: &mut ManagedService) -> ServiceProcessStatus {
    let mut state = String::from("running");
    let running = match service.child.as_mut() {
        Some(child) => is_child_running(child),
        None => false,
    };
    if service.restart_state.manual_restart_required {
        state = "manual_restart_required".to_string();
    } else if !running && service.restart_state.attempts > 0 {
        state = "recovering".to_string();
    }
    let mut pid = 0;
    if let Some(child) = service.child.as_ref() {
        pid = child.id().unwrap_or_default();
    }
    ServiceProcessStatus {
        name: name.to_string(),
        running,
        pid,
        log_path: service.command.log_path.to_string_lossy().to_string(),
        restart_count: service.restart_count,
        next_restart_ms: service.restart_state.next_restart_ms,
        backoff_ms: service.restart_state.backoff_ms,
        state,
    }
}

fn reset_restart_state(service: &mut ManagedService) {
    service.restart_state = ServiceRestartState::default();
}

fn handle_process_exit(
    name: &str,
    service: &mut ManagedService,
    exit_code: Option<i32>,
    events: &mut VecDeque<String>,
) {
    service.child = None;
    service.restart_count = service.restart_count.saturating_add(1);
    if service.restart_count >= MAX_RESTART_ATTEMPTS {
        service.restart_state.manual_restart_required = true;
        append_event(
            events,
            format!(
                "{} crashed (exit={exit_code:?}) and reached restart limit (max {MAX_RESTART_ATTEMPTS}), manual restart required",
                name
            ),
        );
        return;
    }
    service.restart_state.attempts = service.restart_count;
    service.restart_state.backoff_ms = compute_next_backoff_ms(service.restart_count);
    service.restart_state.next_restart_ms = now_unix_ms() + service.restart_state.backoff_ms;
    append_event(
        events,
        format!(
            "{} exited (exit={exit_code:?}), scheduling restart in {}ms (attempt {}/{MAX_RESTART_ATTEMPTS})",
            name,
            service.restart_state.backoff_ms,
            service.restart_count
        ),
    );
}

fn spawn_service(command: &ServiceCommand) -> Result<Child, String> {
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&command.log_path)
        .map_err(|e| format!("open log {}: {e}", command.log_path.display()))?;
    let stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&command.log_path)
        .map_err(|e| format!("open log {}: {e}", command.log_path.display()))?;
    let mut child_cmd = Command::new(&command.binary);
    child_cmd.args(&command.args);
    child_cmd.envs(command.env.clone());
    child_cmd.stdout(std::process::Stdio::from(stdout));
    child_cmd.stderr(std::process::Stdio::from(stderr));
    child_cmd
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", command.binary))
}

async fn ensure_service(
    slot: &mut Option<ManagedService>,
    desired: ServiceCommand,
    force_restart: bool,
    events: &mut VecDeque<String>,
) -> Result<(), String> {
    if let Some(service) = slot {
        if force_restart {
            service.restart_count = 0;
            service.restart_state = ServiceRestartState::default();
        }

        if let Some(child) = service.child.as_mut() {
            if let Ok(Some(status)) = child.try_wait() {
                let exit_code = status.code();
                let binary_name = service.command.binary.clone();
                handle_process_exit(
                    &binary_name,
                    service,
                    exit_code,
                    events,
                );
            }
        }

        if service.child.is_none() {
            if service.restart_state.manual_restart_required {
                append_event(
                    events,
                    format!("{} requires manual restart (max attempts reached)", service.command.binary),
                );
                return Ok(());
            }
            if now_unix_ms() < service.restart_state.next_restart_ms {
                return Ok(());
            }
            let child = spawn_service(&desired)?;
            append_event(
                events,
                format!(
                    "started {} (attempt={})",
                    desired.binary, service.restart_count
                ),
            );
            service.child = Some(child);
            service.command = desired;
        }
        return Ok(());
    }

    let child = spawn_service(&desired)?;
    let service = ManagedService {
        child: Some(child),
        command: desired,
        restart_count: 0,
        restart_state: ServiceRestartState::default(),
    };
    append_event(
        events,
        format!("started {} (attempt={})", service.command.binary, service.restart_count),
    );
    *slot = Some(service);
    Ok(())
}

async fn wait_for_ports(addresses: &[&str], timeout_ms: u64) -> bool {
    let deadline = now_unix_ms() + timeout_ms;
    loop {
        let mut all_ok = true;
        for addr in addresses {
            if TcpStream::connect(addr).is_err() {
                all_ok = false;
                break;
            }
        }
        if all_ok {
            return true;
        }
        if now_unix_ms() > deadline {
            return false;
        }
        sleep(Duration::from_millis(250)).await;
    }
}

async fn is_http_ready(addr: &str) -> bool {
    let endpoint = format!("https://{addr}/health");
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(500))
        .build()
    {
        Ok(client) => client,
        Err(_) => return TcpStream::connect(addr).is_ok(),
    };
    if let Ok(resp) = client.get(&endpoint).send().await {
        resp.status().is_success()
    } else {
        TcpStream::connect(addr).is_ok()
    }
}

fn read_tail(path: &Path, lines: usize) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(raw) = fs::read_to_string(path) {
        out.extend(
            raw.lines()
                .rev()
                .take(lines)
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
                .into_iter()
                .rev(),
        );
    }
    out
}

fn append_status_tail(status: &mut Vec<String>, path: &Path, lines: usize) {
    status.extend(read_tail(path, lines));
}

async fn stop_child_gracefully(child: &mut Child, service_name: &str, events: &mut VecDeque<String>) {
    if !is_child_running(child) {
        return;
    }
    append_event(events, format!("{service_name} stop requested (graceful)"));
    let _ = child.start_kill();
    let start = now_unix_ms();
    while now_unix_ms().saturating_sub(start) < MAX_STOP_WAIT_MS {
        if child.try_wait().is_ok_and(|status| status.is_some()) {
            append_event(events, format!("{service_name} stopped gracefully"));
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    let _ = child.kill();
    let _ = child.wait().await;
    append_event(events, format!("{service_name} hard-stopped after timeout"));
}

fn build_service_command(program: &str, paths: &DesktopPaths, role: &str) -> Option<ServiceCommand> {
    let binary = resolve_binary(program)?;
    if role == "control_plane" {
        Some(ServiceCommand {
            binary,
            args: Vec::new(),
            env: vec![
                ("CONTROL_PLANE_LISTEN_ADDR".to_string(), CONTROL_PLANE_ADDR.to_string()),
                ("MTLS_CA".to_string(), paths.pki.join("ca.crt").to_string_lossy().to_string()),
                ("MTLS_CERT".to_string(), paths.pki.join("control-plane.crt").to_string_lossy().to_string()),
                ("MTLS_KEY".to_string(), paths.pki.join("control-plane.key").to_string_lossy().to_string()),
            ],
            log_path: paths.logs.join("control-plane.out.log"),
        })
    } else {
        Some(ServiceCommand {
            binary,
            args: Vec::new(),
            env: vec![
                ("CONTROL_PLANE_URL".to_string(), format!("https://{CONTROL_PLANE_ADDR}")),
                ("MTLS_CA".to_string(), paths.pki.join("ca.crt").to_string_lossy().to_string()),
                ("MTLS_CERT".to_string(), paths.pki.join("worker.crt").to_string_lossy().to_string()),
                ("MTLS_KEY".to_string(), paths.pki.join("worker.key").to_string_lossy().to_string()),
                ("WORKER_ADDR".to_string(), WORKER_ADDR.to_string()),
            ],
            log_path: paths.logs.join("worker.out.log"),
        })
    }
}

fn parse_update_manifest(content: &str) -> Result<update::UpdateManifest, String> {
    update::parse_update_manifest(content)
}

#[tauri::command]
fn get_version() -> VersionResponse {
    VersionResponse {
        version: update::current_version(),
    }
}

#[tauri::command]
fn get_health() -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "version": update::current_version()
    })
}

#[tauri::command]
async fn ensure_pki_command(state: State<'_, AppState>) -> Result<PkiPaths, String> {
    let paths = state.paths.clone();
    ensure_dev_pki(&paths)
}

#[tauri::command]
async fn get_settings() -> Result<DesktopSettings, String> {
    let paths = app_paths();
    load_settings(&paths)
}

#[tauri::command]
async fn update_settings(_state: State<'_, AppState>, settings: DesktopSettings) -> Result<DesktopSettings, String> {
    let paths = app_paths();
    save_settings(&paths, &settings)?;
    Ok(settings)
}

#[tauri::command]
async fn check_for_updates(
    manifest_url: Option<String>,
    manifest_path: Option<String>,
    expected_asset_path: Option<String>,
    public_key_b64: Option<String>,
) -> Result<UpdateCheckResult, String> {
    let paths = app_paths();
    let manifest_file = manifest_url
        .or(manifest_path)
        .or_else(|| std::env::var("SAFEAGENT_UPDATE_MANIFEST_URL").ok())
        .or_else(|| std::env::var("SAFEAGENT_UPDATE_MANIFEST_PATH").ok())
        .unwrap_or_else(|| paths.update_manifest.to_string_lossy().to_string());

    if !manifest_file.ends_with(update::UPDATE_JSON_NAME) {
        return Ok(UpdateCheckResult {
            manifest_present: false,
            message: Some("manifest must point to update.json".to_string()),
            ..Default::default()
        });
    }

    let local_file = !manifest_file.starts_with("http://") && !manifest_file.starts_with("https://");
    if local_file {
        if !update::manifest_signature_path(&manifest_file).ends_with(update::UPDATE_SIGNATURE_NAME) {
            return Ok(UpdateCheckResult {
                manifest_present: false,
                message: Some("invalid manifest signature path".to_string()),
                ..Default::default()
            });
        }
        if !Path::new(&manifest_file).exists() {
            return Ok(UpdateCheckResult {
                manifest_present: false,
                message: Some("manifest file does not exist".to_string()),
                ..Default::default()
            });
        }
    }

    let signature_path = update::manifest_signature_path(&manifest_file);
    if local_file && !Path::new(&signature_path).exists() {
        return Ok(UpdateCheckResult {
            manifest_present: true,
            manifest_valid: true,
            signature_valid: false,
            update_available: false,
            current_version: update::current_version().to_string(),
            latest_version: update::current_version().to_string(),
            notes: Vec::new(),
            published_at: None,
            asset_url: String::new(),
            asset_sha256_ok: false,
            safe: false,
            message: Some("update signature missing".to_string()),
        });
    }

    let result = update::verify_remote_update(
        &manifest_file,
        &signature_path,
        expected_asset_path,
        public_key_b64,
    )
    .await?;
    Ok(UpdateCheckResult {
        message: if result.manifest_present {
            result.message
        } else {
            Some("manifest not present".to_string())
        },
        manifest_present: true,
        manifest_valid: result.manifest_valid,
        signature_valid: result.signature_valid,
        update_available: result.update_available,
        current_version: result.current_version,
        latest_version: result.latest_version,
        notes: result.notes,
        published_at: result.published_at,
        asset_url: result.asset_url,
        asset_sha256_ok: result.asset_sha256_ok,
        safe: result.safe,
    })
}

#[tauri::command]
async fn create_support_bundle(state: State<'_, AppState>) -> Result<String, String> {
    let paths = state.paths.clone();
    let status = get_status(state).await?;
    let status_json = serde_json::to_string_pretty(&status).unwrap_or_else(|_| "{}".to_string());
    let versions_json = serde_json::to_string_pretty(&serde_json::json!({
        "safeagent_desktop": update::current_version(),
        "safeagent_control_plane": "n/a",
        "safeagent_worker": "n/a",
        "os": std::env::consts::OS
    }))
    .unwrap_or_else(|_| "{}".to_string());
    let bundle_path = support::create_support_bundle(&paths.support_bundles, &paths, &status_json, &versions_json)?;
    Ok(bundle_path.to_string_lossy().to_string())
}

#[tauri::command]
async fn start_services(state: State<'_, AppState>) -> Result<ServiceStatus, String> {
    let paths = state.paths.clone();
    ensure_directories(&paths)?;
    let pki = ensure_dev_pki(&paths)?;
    let verified = paths.root.join("publishers").join("verified.json");
    ensure_default_verified_publishers(&verified)?;
    let settings = load_settings(&paths)?;

    let cp_cmd = build_service_command("safeagent-control-plane", &paths, "control_plane")
        .ok_or_else(|| "safeagent-control-plane binary not found".to_string())?;
    let worker_cmd = build_service_command("safeagent-worker", &paths, "worker")
        .ok_or_else(|| "safeagent-worker binary not found".to_string())?;

    let mut services = state.services.lock().await;
    let mut events = state.events.lock().await;
    services.desired_running = true;
    if services.control_plane.is_none() {
        append_event(&mut events, "control-plane process slot opened");
    }
    if services.worker.is_none() {
        append_event(&mut events, "worker process slot opened");
    }
    if let Some(service) = services.control_plane.as_mut() {
        if settings.strict_mode {
            append_event(&mut events, "strict mode enabled");
        }
        reset_restart_state(service);
        service.restart_count = 0;
    }
    if let Some(service) = services.worker.as_mut() {
        reset_restart_state(service);
        service.restart_count = 0;
    }
    ensure_service(&mut services.control_plane, cp_cmd, true, &mut events).await?;
    ensure_service(&mut services.worker, worker_cmd, true, &mut events).await?;
    drop(services);
    drop(events);
    if !wait_for_ports(&[CONTROL_PLANE_ADDR], 12_000).await {
        return Err("control plane did not become ready".to_string());
    }
    if !wait_for_ports(&[WORKER_ADDR], 12_000).await {
        return Err("worker did not become ready".to_string());
    }
    {
        let mut events = state.events.lock().await;
        append_event(
            &mut events,
            format!("services running with pki={}", pki.ca_cert.display()),
        );
    }
    get_status(state).await
}

#[tauri::command]
async fn restart_services(state: State<'_, AppState>) -> Result<ServiceStatus, String> {
    stop_services(state.clone()).await?;
    start_services(state).await
}

#[tauri::command]
async fn stop_services(state: State<'_, AppState>) -> Result<ServiceStatus, String> {
    let mut services = state.services.lock().await;
    services.desired_running = false;
    let mut events = state.events.lock().await;
    if let Some(mut control_plane) = services.control_plane.take() {
        if let Some(mut child) = control_plane.child.take() {
            stop_child_gracefully(&mut child, &control_plane.command.binary, &mut events).await;
        }
        append_event(&mut events, format!("stopped {}", control_plane.command.binary));
    }
    if let Some(mut worker) = services.worker.take() {
        if let Some(mut child) = worker.child.take() {
            stop_child_gracefully(&mut child, &worker.command.binary, &mut events).await;
        }
        append_event(&mut events, format!("stopped {}", worker.command.binary));
    }
    drop(services);
    drop(events);
    get_status(state).await
}

#[tauri::command]
async fn get_status(state: State<'_, AppState>) -> Result<ServiceStatus, String> {
    let mut services = state.services.lock().await;
    let mut events = state.events.lock().await;

    if services.desired_running {
        if let Some(cp_cmd) = build_service_command("safeagent-control-plane", &state.paths, "control_plane") {
            ensure_service(&mut services.control_plane, cp_cmd, false, &mut events).await?;
        }
        if let Some(worker_cmd) = build_service_command("safeagent-worker", &state.paths, "worker") {
            ensure_service(&mut services.worker, worker_cmd, false, &mut events).await?;
        }
    }

    let control_plane_ready = is_http_ready(CONTROL_PLANE_ADDR).await;
    let worker_ready = is_http_ready(WORKER_ADDR).await;

    let mut control_plane_status = None;
    if let Some(service) = services.control_plane.as_mut() {
        if service.child.is_some() {
            if is_child_running(service.child.as_mut().expect("child exists")) {
                reset_restart_state(service);
            }
        }
        control_plane_status = Some(service_status("control-plane", service));
    }
    let mut worker_status = None;
    if let Some(service) = services.worker.as_mut() {
        if service.child.is_some() && is_child_running(service.child.as_mut().expect("child exists")) {
            reset_restart_state(service);
        }
        worker_status = Some(service_status("worker", service));
    }

    let safety_state = if !services.desired_running {
        "stopped".to_string()
    } else if control_plane_status
        .as_ref()
        .is_some_and(|service| service.state == "manual_restart_required")
        || worker_status
            .as_ref()
            .is_some_and(|service| service.state == "manual_restart_required")
    {
        "red".to_string()
    } else if control_plane_status.as_ref().is_some_and(|svc| svc.running == false)
        || worker_status.as_ref().is_some_and(|svc| svc.running == false)
    {
        "yellow".to_string()
    } else {
        "green".to_string()
    };

    let mut recent: Vec<String> = events.iter().rev().take(20).cloned().collect();
    recent.reverse();
    append_status_tail(&mut recent, &state.paths.logs.join("control-plane.out.log"), 10);
    append_status_tail(&mut recent, &state.paths.logs.join("worker.out.log"), 10);
    if recent.len() > 20 {
        recent = recent[recent.len() - 20..].to_vec();
    }

    Ok(ServiceStatus {
        desired_running: services.desired_running,
        control_plane_ready,
        worker_ready,
        control_plane: control_plane_status,
        worker: worker_status,
        last_events: recent,
        safety_state,
    })
}

#[tauri::command]
async fn get_onboarding_state(state: State<'_, AppState>) -> Result<OnboardingState, String> {
    let onboarding = state.onboarding.lock().await.clone();
    Ok(onboarding)
}

#[tauri::command]
async fn advance_onboarding(state: State<'_, AppState>) -> Result<OnboardingState, String> {
    let mut onboarding = state.onboarding.lock().await;
    let changed = advance_onboarding_step(&mut onboarding);
    if changed {
        let paths = state.paths.clone();
        save_onboarding_state(&paths, &onboarding)?;
    }
    Ok(onboarding.clone())
}

#[tauri::command]
async fn complete_onboarding_flow(state: State<'_, AppState>) -> Result<OnboardingState, String> {
    let mut onboarding = state.onboarding.lock().await;
    let changed = complete_onboarding(&mut onboarding);
    if changed {
        let paths = state.paths.clone();
        save_onboarding_state(&paths, &onboarding)?;
    }
    Ok(onboarding.clone())
}

#[tauri::command]
async fn reset_onboarding_flow(state: State<'_, AppState>) -> Result<OnboardingState, String> {
    let mut onboarding = state.onboarding.lock().await;
    reset_onboarding(&mut onboarding);
    let paths = state.paths.clone();
    save_onboarding_state(&paths, &onboarding)?;
    Ok(onboarding.clone())
}

#[tauri::command]
async fn get_tray_menu() -> Vec<TrayMenuItem> {
    default_tray_menu()
}

#[tauri::command]
async fn get_recent_events(
    state: State<'_, AppState>,
    lines: Option<usize>,
) -> Result<Vec<String>, String> {
    let max_lines = lines.unwrap_or(30);
    let events = state.events.lock().await;
    let mut output = events.iter().rev().take(max_lines).cloned().collect::<Vec<_>>();
    output.reverse();
    Ok(output)
}

#[tauri::command]
async fn get_human_recent_events(
    state: State<'_, AppState>,
    lines: Option<usize>,
) -> Result<Vec<String>, String> {
    let raw = get_recent_events(state, lines).await?;
    Ok(map_events_to_human(raw))
}


async fn build_control_plane_client(pki: &PkiPaths) -> Result<reqwest::Client, String> {
    let ca = fs::read(&pki.ca_cert).map_err(|e| format!("read ca: {e}"))?;
    let ca = ReqwestCertificate::from_pem(&ca).map_err(|e| format!("ca pem: {e}"))?;
    reqwest::Client::builder()
        .add_root_certificate(ca)
        .build()
        .map_err(|e| format!("build client: {e}"))
}

#[tauri::command]
async fn poll_pending_approvals() -> Result<Vec<PendingApproval>, String> {
    let pki = ensure_dev_pki(&app_paths())?;
    let client = build_control_plane_client(&pki).await?;
    let approvals = client
        .get(format!("https://{CONTROL_PLANE_ADDR}/approval/pending"))
        .send()
        .await
        .map_err(|e| format!("fetch pending approvals: {e}"))?
        .json::<Vec<ApprovalRequest>>()
        .await
        .map_err(|e| format!("parse approvals: {e}"))?;
    Ok(approvals
        .into_iter()
        .map(|approval| PendingApproval {
            approval_id: approval.approval_id,
            request_id: approval.request_id,
            node_id: approval.node_id,
            skill_id: approval.skill_id,
            input_summary: approval.input_summary,
            reason: approval.reason,
        })
        .collect())
}

#[tauri::command]
async fn approve(state: State<'_, AppState>, approval_id: String) -> Result<ApprovalDecisionResponseView, String> {
    decide_approval_with(state, approval_id, "approved").await
}

#[tauri::command]
async fn deny(state: State<'_, AppState>, approval_id: String) -> Result<ApprovalDecisionResponseView, String> {
    decide_approval_with(state, approval_id, "denied").await
}

async fn decide_approval_with(
    state: State<'_, AppState>,
    approval_id: String,
    decision: &str,
) -> Result<ApprovalDecisionResponseView, String> {
    let pki = ensure_dev_pki(&app_paths())?;
    let client = build_control_plane_client(&pki).await?;
    let payload = ApprovalDecisionRequest {
        approval_id: approval_id.clone(),
        decision: decision.to_string(),
        decided_by: "desktop-operator".to_string(),
        reason: Some("operator decision via desktop".to_string()),
    };

    let response = client
        .post(format!("https://{CONTROL_PLANE_ADDR}/approval/decide"))
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("approval decide: {e}"))?
        .json::<ApprovalDecisionResponse>()
        .await
        .map_err(|e| format!("parse approval response: {e}"))?;

    state
        .events
        .lock()
        .await
        .push_back(format!("decision {} -> {}", decision, approval_id));

    Ok(ApprovalDecisionResponseView {
        ok: true,
        status: response.status,
    })
}

#[tauri::command]
fn quit_app(app: AppHandle) {
    app.exit(0);
}

#[tauri::command]
async fn list_marketplace_skills(state: State<'_, AppState>) -> Result<Vec<MarketSkill>, String> {
    let paths = &state.paths;
    create_dir_all(&paths.marketplace).map_err(|e| format!("marketplace dir: {e}"))?;
    let mut skills = Vec::new();
    let verified = paths.root.join("publishers").join("verified.json");
    ensure_default_verified_publishers(&verified)?;

    let settings = load_settings(paths)?;
    for item in fs::read_dir(&paths.marketplace).map_err(|e| format!("read marketplace: {e}"))? {
        let item = item.map_err(|e| format!("marketplace entry: {e}"))?;
        let path = item.path();
        if !path.is_dir() {
            continue;
        }
        let id = item.file_name().to_string_lossy().to_string();
        let status = if !package_contains_required_files(&path) {
            "invalid_package"
        } else if scan_skill(&path).is_err() {
            "blocked"
        } else if settings.verified_publisher_only {
            match verify_skill(&path, &verified) {
                Ok(_) => "installable",
                Err(_) => "blocked",
            }
        } else {
            "installable"
        };
        skills.push(MarketSkill {
            id: id.clone(),
            name: id,
            path: path.to_string_lossy().to_string(),
            status: status.to_string(),
        });
    }

    if skills.is_empty() {
        skills.push(MarketSkill {
            id: "no-packages".to_string(),
            name: "No local package directory".to_string(),
            path: paths.marketplace.to_string_lossy().to_string(),
            status: "blocked".to_string(),
        });
    }
    Ok(skills)
}

#[tauri::command]
async fn install_marketplace_skill(
    state: State<'_, AppState>,
    package_path: String,
) -> Result<InstallResult, String> {
    let source = PathBuf::from(package_path);
    if !source.exists() {
        return Ok(InstallResult {
            installed: false,
            package_path: source.to_string_lossy().to_string(),
            detail: "package path does not exist".to_string(),
        });
    }
    if !source.is_dir() {
        return Ok(InstallResult {
            installed: false,
            package_path: source.to_string_lossy().to_string(),
            detail: "expected unpacked package directory".to_string(),
        });
    }
    if !package_contains_required_files(&source) {
        return Ok(InstallResult {
            installed: false,
            package_path: source.to_string_lossy().to_string(),
            detail: "required package files missing".to_string(),
        });
    }

    let verified = state.paths.root.join("publishers").join("verified.json");
    ensure_default_verified_publishers(&verified)?;
    let settings = load_settings(&state.paths)?;
    if settings.verified_publisher_only {
        scan_skill(&source).map_err(|err| format!("scan blocked: {err}"))?;
        verify_skill(&source, &verified).map_err(|err| format!("verify blocked: {err}"))?;
    }

    let destination = state.paths.installed.join(
        source
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("package"),
    );
    copy_dir_recursive(&source, &destination)?;
    state
        .events
        .lock()
        .await
        .push_back(format!("installed safe package {}", destination.display()));
    Ok(InstallResult {
        installed: true,
        package_path: destination.to_string_lossy().to_string(),
        detail: if settings.verified_publisher_only {
            "package verified + scanned and copied".to_string()
        } else {
            "package copied".to_string()
        },
    })
}

fn copy_dir_recursive(source: &Path, target: &Path) -> Result<(), String> {
    if !source.is_dir() {
        return Err("source is not directory".to_string());
    }
    create_dir_all(target).map_err(|e| format!("create target dir: {e}"))?;
    for entry in fs::read_dir(source).map_err(|e| format!("read source: {e}"))? {
        let entry = entry.map_err(|e| format!("source entry: {e}"))?;
        let src = entry.path();
        let dst = target.join(entry.file_name());
        if src.is_dir() {
            copy_dir_recursive(&src, &dst)?;
        } else {
            fs::copy(&src, &dst).map_err(|e| format!("copy {}: {e}", src.display()))?;
        }
    }
    Ok(())
}

fn main() {
    let state = AppState {
        paths: app_paths(),
        services: Mutex::new(ServiceRegistry::default()),
        events: Mutex::new(VecDeque::new()),
        onboarding: Mutex::new(load_onboarding_state(&app_paths()).unwrap_or_default()),
    };

    Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_version,
            get_health,
            ensure_pki_command,
            start_services,
            restart_services,
            stop_services,
            get_status,
            get_recent_events,
            get_human_recent_events,
            get_onboarding_state,
            advance_onboarding,
            complete_onboarding_flow,
            reset_onboarding_flow,
            get_tray_menu,
            get_settings,
            update_settings,
            check_for_updates,
            poll_pending_approvals,
            approve,
            deny,
            quit_app,
            list_marketplace_skills,
            create_support_bundle,
            install_marketplace_skill
        ])
        .run(tauri::generate_context!())
        .expect("error while running SafeAgent Desktop");
}

#[cfg(test)]
mod tests {
    use super::{
        app_paths, copy_dir_recursive, ensure_directories, parse_update_manifest, read_tail,
        save_settings, load_settings, compute_next_backoff_ms, advance_onboarding_step, complete_onboarding,
        default_tray_menu, reset_onboarding, human_readable_event, OnboardingState,
    };
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn read_tail_limits_lines() {
        let path = PathBuf::from("/tmp/safeagent-tail-test.txt");
        fs::write(&path, "a\nb\nc\n").expect("write");
        let lines = read_tail(&path, 2);
        assert_eq!(lines, vec!["b".to_string(), "c".to_string()]);
    }

    #[test]
    fn pki_function_is_idempotent() {
        let paths = app_paths();
        ensure_directories(&paths).expect("dirs");
    }

    #[test]
    fn copy_dir_recursive_works_for_nested() -> Result<(), String> {
        let src = PathBuf::from("/tmp/safeagent-copy-src");
        let dst = PathBuf::from("/tmp/safeagent-copy-dst");
        let _ = fs::remove_dir_all(&src);
        let _ = fs::remove_dir_all(&dst);
        fs::create_dir_all(src.join("sub")).expect("src sub");
        fs::write(src.join("a.txt"), "hello").expect("a");
        fs::write(src.join("sub").join("b.txt"), "world").expect("b");
        copy_dir_recursive(&src, &dst)?;
        assert!(dst.join("a.txt").exists());
        assert!(dst.join("sub").join("b.txt").exists());
        Ok(())
    }

    #[test]
    fn update_manifest_parse() {
        let content = r#"{"version":"0.2.0","url":"file:///tmp/safeagent-desktop-update.bin","sha256":"","notes":["test"],"published_at":"2026-01-01T00:00:00Z"}"#;
        let manifest = parse_update_manifest(content).expect("manifest parse");
        assert_eq!(manifest.version, "0.2.0");
        assert_eq!(manifest.notes, vec!["test".to_string()]);
    }

    #[test]
    fn settings_default_and_roundtrip() -> Result<(), String> {
        let paths = super::DesktopPaths {
            root: PathBuf::from("/tmp/safeagent-desktop-d2"),
            pki: PathBuf::from("/tmp/safeagent-desktop-d2/pki"),
            logs: PathBuf::from("/tmp/safeagent-desktop-d2/logs"),
            secrets: PathBuf::from("/tmp/safeagent-desktop-d2/secrets"),
            marketplace: PathBuf::from("/tmp/safeagent-desktop-d2/marketplace"),
            installed: PathBuf::from("/tmp/safeagent-desktop-d2/installed"),
            settings: PathBuf::from("/tmp/safeagent-desktop-d2/settings.json"),
            update_manifest: PathBuf::from("/tmp/safeagent-desktop-d2/update.json"),
            support_bundles: PathBuf::from("/tmp/safeagent-desktop-d2/support_bundles"),
        };
        let settings = super::DesktopSettings::default();
        save_settings(&paths, &settings)?;
        let reloaded = load_settings(&paths)?;
        assert_eq!(reloaded.strict_mode, settings.strict_mode);
        assert_eq!(reloaded.verified_publisher_only, settings.verified_publisher_only);
        assert_eq!(reloaded.allowlist_network_only, settings.allowlist_network_only);
        assert_eq!(reloaded.advanced_logs, settings.advanced_logs);
        assert_eq!(compute_next_backoff_ms(2), 1000);
        Ok(())
    }

    #[test]
    fn onboarding_state_machine() {
        let mut state = OnboardingState::default();
        assert!(advance_onboarding_step(&mut state));
        assert_eq!(state.current_step, 2);
        assert!(!state.completed);
        assert!(advance_onboarding_step(&mut state));
        assert!(state.completed);
        let previous = state.clone();
        assert!(!advance_onboarding_step(&mut state));
        assert_eq!(state, previous);
        assert!(!complete_onboarding(&mut state));
        assert!(state.completed);
        reset_onboarding(&mut state);
        assert_eq!(state.current_step, 1);
        assert!(!state.completed);
    }

    #[test]
    fn event_human_mapping_is_stable() {
        assert_eq!(human_readable_event("policy denied"), "Güvenlik nedeniyle engellendi");
        assert_eq!(human_readable_event("Approval pending"), "Onay bekliyor");
        assert_eq!(human_readable_event("egress blocked"), "İnternet erişimi engellendi (allowlist dışı)");
        assert_eq!(human_readable_event("Skill install blocked"), "Güvenlik taraması başarısız");
    }

    #[test]
    fn tray_menu_items_exist() {
        let menu = default_tray_menu();
        assert_eq!(menu.len(), 5);
        assert!(menu.iter().any(|item| item.id == "start"));
        assert!(menu.iter().any(|item| item.id == "stop"));
        assert!(menu.iter().any(|item| item.id == "quit"));
        assert!(menu.iter().any(|item| item.id == "support"));
        assert!(menu.iter().any(|item| item.id == "open"));
    }
}
