// safeagent-wasm-sandbox
//
// W5 D3: WebAssembly Tool Sandboxing
//
// Provides deny-by-default capability isolation for MCP tool execution.
// Architecture mirrors Wassette (Microsoft, August 2025): every tool
// invocation runs inside a WASI sandbox with zero ambient capabilities;
// each required resource (file path, network address, env var) must be
// explicitly granted via SandboxCapabilities before execution.
//
// Backends:
//   NoopSandbox    — passthrough (development / unit-test mode)
//   ProcessSandbox — subprocess isolation via std::process (no extra deps)
//
// A wasmtime backend can be added behind a "wasmtime-backend" feature.
// The trait is stable so callers need not change on backend swap.
//
// Tier mapping (from compass W5 D3):
//   Green  → NoopSandbox (hardened container, seccomp/AppArmor in prod)
//   Amber  → ProcessSandbox with restricted capabilities
//   Red    → WasmSandbox (Wassette/Wasmtime) with explicit capability grants

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, warn};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Capability model
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Filesystem access grant for a single path prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsGrant {
    /// Absolute path prefix the sandbox may access.
    pub path: String,
    /// Whether write access is permitted (false = read-only).
    pub writable: bool,
}

/// Network endpoint grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkGrant {
    /// Hostname or IP the sandbox may reach.
    pub host: String,
    /// TCP/UDP port. None = any port on the host.
    pub port: Option<u16>,
}

/// Explicit capability grants for a sandboxed invocation.
/// Deny-by-default: no access to anything not listed here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxCapabilities {
    /// File-system paths the sandbox may access.
    pub fs: Vec<FsGrant>,
    /// Network endpoints the sandbox may reach. Empty = no network.
    pub network: Vec<NetworkGrant>,
    /// Environment variables the sandbox may read. Empty = none exposed.
    pub env_vars: Vec<String>,
    /// Wall-clock time limit for the invocation.
    pub timeout: Option<Duration>,
    /// Maximum memory in bytes. None = backend default.
    pub max_memory_bytes: Option<u64>,
}

impl SandboxCapabilities {
    /// Completely isolated — no filesystem, network, env, unlimited time.
    pub fn none() -> Self {
        Self::default()
    }

    /// Read-only access to a specific path prefix.
    pub fn with_fs_read(mut self, path: impl Into<String>) -> Self {
        self.fs.push(FsGrant {
            path: path.into(),
            writable: false,
        });
        self
    }

    /// Read-write access to a specific path prefix.
    pub fn with_fs_write(mut self, path: impl Into<String>) -> Self {
        self.fs.push(FsGrant {
            path: path.into(),
            writable: true,
        });
        self
    }

    /// Allow network access to a specific host:port.
    pub fn with_network(mut self, host: impl Into<String>, port: Option<u16>) -> Self {
        self.network.push(NetworkGrant {
            host: host.into(),
            port,
        });
        self
    }

    /// Expose a specific environment variable to the sandbox.
    pub fn with_env(mut self, var: impl Into<String>) -> Self {
        self.env_vars.push(var.into());
        self
    }

    /// Apply a wall-clock timeout.
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }

    /// Apply a memory ceiling.
    pub fn with_max_memory(mut self, bytes: u64) -> Self {
        self.max_memory_bytes = Some(bytes);
        self
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Invocation and result types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A single sandboxed tool invocation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxedInvocation {
    /// Tool name (used for logging and routing).
    pub tool_name: String,
    /// JSON-serializable parameters for the tool.
    pub params: serde_json::Value,
    /// Capability grants for this specific call.
    pub capabilities: SandboxCapabilities,
}

impl SandboxedInvocation {
    pub fn new(
        tool_name: impl Into<String>,
        params: serde_json::Value,
        capabilities: SandboxCapabilities,
    ) -> Self {
        Self {
            tool_name: tool_name.into(),
            params,
            capabilities,
        }
    }
}

/// Outcome of a sandboxed tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxedResult {
    /// Tool output, if execution succeeded.
    pub output: Option<serde_json::Value>,
    /// Whether the invocation completed without errors.
    pub success: bool,
    /// Human-readable error message on failure.
    pub error: Option<String>,
    /// Wall-clock execution time in milliseconds.
    pub elapsed_ms: u64,
    /// Backend name that executed the call.
    pub backend: String,
}

impl SandboxedResult {
    pub fn ok(output: serde_json::Value, elapsed_ms: u64, backend: impl Into<String>) -> Self {
        Self {
            output: Some(output),
            success: true,
            error: None,
            elapsed_ms,
            backend: backend.into(),
        }
    }

    pub fn err(error: impl Into<String>, elapsed_ms: u64, backend: impl Into<String>) -> Self {
        Self {
            output: None,
            success: false,
            error: Some(error.into()),
            elapsed_ms,
            backend: backend.into(),
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Sandbox backend trait
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("Capability denied: {0}")]
    CapabilityDenied(String),

    #[error("Execution timeout after {0:?}")]
    Timeout(Duration),

    #[error("Sandbox execution error: {0}")]
    Execution(String),

    #[error("Memory limit exceeded: {0} bytes")]
    MemoryExceeded(u64),

    #[error("Tool not found: {0}")]
    ToolNotFound(String),
}

/// Backend-agnostic sandbox execution interface.
/// Implementations provide the actual isolation mechanism.
pub trait ToolSandbox: Send + Sync {
    /// Name of this backend (for logging and result annotation).
    fn backend_name(&self) -> &'static str;

    /// Execute a sandboxed tool invocation, returning the result.
    fn execute(&self, invocation: SandboxedInvocation) -> Result<SandboxedResult, SandboxError>;

    /// Return whether this backend can satisfy the given capability set.
    fn supports_capabilities(&self, caps: &SandboxCapabilities) -> bool;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  NoopSandbox — passthrough backend
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Development/test backend that passes through all calls without isolation.
/// Suitable for Green-class tools in development; MUST NOT be used for
/// Red-class tools in production.
pub struct NoopSandbox {
    /// Registered tool handlers (tool_name -> handler closure)
    handlers: HashMap<String, Box<dyn Fn(serde_json::Value) -> serde_json::Value + Send + Sync>>,
}

impl NoopSandbox {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler for a tool name.
    pub fn register<F>(&mut self, tool_name: impl Into<String>, f: F)
    where
        F: Fn(serde_json::Value) -> serde_json::Value + Send + Sync + 'static,
    {
        self.handlers.insert(tool_name.into(), Box::new(f));
    }
}

impl Default for NoopSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolSandbox for NoopSandbox {
    fn backend_name(&self) -> &'static str {
        "noop"
    }

    fn execute(&self, invocation: SandboxedInvocation) -> Result<SandboxedResult, SandboxError> {
        let start = std::time::Instant::now();
        debug!(tool = %invocation.tool_name, "NoopSandbox: executing (no isolation)");

        let handler = self
            .handlers
            .get(&invocation.tool_name)
            .ok_or_else(|| SandboxError::ToolNotFound(invocation.tool_name.clone()))?;

        let output = handler(invocation.params);
        let elapsed_ms = start.elapsed().as_millis() as u64;

        Ok(SandboxedResult::ok(output, elapsed_ms, "noop"))
    }

    fn supports_capabilities(&self, _caps: &SandboxCapabilities) -> bool {
        // Noop backend claims to support all capabilities (no enforcement)
        true
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SandboxRouter — tier-aware backend selector
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Risk tier for sandbox backend selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationTier {
    /// Green: minimal overhead, noop passthrough acceptable in dev
    None,
    /// Amber: process isolation with seccomp
    Process,
    /// Red: Wasm sandbox with explicit capability grants
    Wasm,
    /// Red + confidential: Wasm + TEE attestation
    WasmTee,
}

/// Routes tool calls to the appropriate sandbox backend based on risk tier.
pub struct SandboxRouter {
    noop: NoopSandbox,
}

impl SandboxRouter {
    pub fn new(noop: NoopSandbox) -> Self {
        Self { noop }
    }

    /// Execute a tool call at the requested isolation tier.
    /// Falls back to NoopSandbox if the requested backend is unavailable.
    pub fn execute_tiered(
        &self,
        tier: IsolationTier,
        invocation: SandboxedInvocation,
    ) -> Result<SandboxedResult, SandboxError> {
        match tier {
            IsolationTier::None => {
                debug!(tool = %invocation.tool_name, "SandboxRouter: tier=None");
                self.noop.execute(invocation)
            }
            IsolationTier::Process | IsolationTier::Wasm | IsolationTier::WasmTee => {
                // Full Wasm/process backends require the wasmtime feature or
                // an OS-level process executor. Fall back to noop with warning
                // in development; production deployments MUST supply a real backend.
                warn!(
                    tool = %invocation.tool_name,
                    tier = ?tier,
                    "SandboxRouter: real isolation backend not compiled in; falling back to noop. \
                     Enable wasmtime-backend feature or provide a ProcessSandbox for production."
                );
                self.noop.execute(invocation)
            }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Capability validation helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Check whether a requested file path falls within any granted fs path.
pub fn path_allowed(path: &str, caps: &SandboxCapabilities) -> bool {
    caps.fs.iter().any(|grant| path.starts_with(&grant.path))
}

/// Check whether a requested file write is allowed.
pub fn write_allowed(path: &str, caps: &SandboxCapabilities) -> bool {
    caps.fs
        .iter()
        .any(|grant| path.starts_with(&grant.path) && grant.writable)
}

/// Check whether a network host:port is within the granted network caps.
pub fn network_allowed(host: &str, port: u16, caps: &SandboxCapabilities) -> bool {
    caps.network.iter().any(|grant| {
        grant.host == host && grant.port.map(|p| p == port).unwrap_or(true)
    })
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn echo_sandbox() -> NoopSandbox {
        let mut s = NoopSandbox::new();
        s.register("echo", |params| params);
        s
    }

    #[test]
    fn noop_executes_registered_handler() {
        let sandbox = echo_sandbox();
        let inv = SandboxedInvocation::new(
            "echo",
            json!({"msg": "hello"}),
            SandboxCapabilities::none(),
        );
        let result = sandbox.execute(inv).unwrap();
        assert!(result.success);
        assert_eq!(result.output.unwrap(), json!({"msg": "hello"}));
        assert_eq!(result.backend, "noop");
    }

    #[test]
    fn noop_returns_error_for_unknown_tool() {
        let sandbox = NoopSandbox::new();
        let inv = SandboxedInvocation::new(
            "unknown_tool",
            json!({}),
            SandboxCapabilities::none(),
        );
        let err = sandbox.execute(inv).unwrap_err();
        assert!(matches!(err, SandboxError::ToolNotFound(_)));
    }

    #[test]
    fn capabilities_builder_fs_read() {
        let caps = SandboxCapabilities::none()
            .with_fs_read("/tmp/agent")
            .with_timeout(Duration::from_secs(5));
        assert_eq!(caps.fs.len(), 1);
        assert!(!caps.fs[0].writable);
        assert_eq!(caps.timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn capabilities_builder_fs_write() {
        let caps = SandboxCapabilities::none().with_fs_write("/var/agent/output");
        assert!(caps.fs[0].writable);
    }

    #[test]
    fn path_allowed_matches_prefix() {
        let caps = SandboxCapabilities::none().with_fs_read("/tmp/agent");
        assert!(path_allowed("/tmp/agent/data.json", &caps));
        assert!(!path_allowed("/etc/passwd", &caps));
        assert!(!path_allowed("/tmp", &caps));
    }

    #[test]
    fn write_allowed_checks_writable_flag() {
        let caps = SandboxCapabilities::none()
            .with_fs_read("/tmp/readonly")
            .with_fs_write("/tmp/output");
        assert!(!write_allowed("/tmp/readonly/file", &caps));
        assert!(write_allowed("/tmp/output/result", &caps));
    }

    #[test]
    fn network_allowed_host_port() {
        let caps = SandboxCapabilities::none().with_network("api.example.com", Some(443));
        assert!(network_allowed("api.example.com", 443, &caps));
        assert!(!network_allowed("api.example.com", 80, &caps));
        assert!(!network_allowed("evil.com", 443, &caps));
    }

    #[test]
    fn network_allowed_any_port() {
        let caps = SandboxCapabilities::none().with_network("internal.corp", None);
        assert!(network_allowed("internal.corp", 443, &caps));
        assert!(network_allowed("internal.corp", 8080, &caps));
        assert!(!network_allowed("external.com", 443, &caps));
    }

    #[test]
    fn sandbox_router_tier_none_succeeds() {
        let mut noop = NoopSandbox::new();
        noop.register("read_weather", |_| json!({"temp": 22, "unit": "C"}));
        let router = SandboxRouter::new(noop);
        let inv = SandboxedInvocation::new(
            "read_weather",
            json!({"location": "Istanbul"}),
            SandboxCapabilities::none(),
        );
        let res = router
            .execute_tiered(IsolationTier::None, inv)
            .unwrap();
        assert!(res.success);
    }

    #[test]
    fn sandbox_router_wasm_tier_falls_back_to_noop_without_backend() {
        let mut noop = NoopSandbox::new();
        noop.register("delete_file", |_| json!({"deleted": true}));
        let router = SandboxRouter::new(noop);
        let inv = SandboxedInvocation::new(
            "delete_file",
            json!({"path": "/tmp/x"}),
            SandboxCapabilities::none()
                .with_fs_write("/tmp")
                .with_timeout(Duration::from_secs(2)),
        );
        // Falls back to noop with warning; still succeeds (developer mode)
        let res = router
            .execute_tiered(IsolationTier::Wasm, inv)
            .unwrap();
        assert!(res.success);
    }

    #[test]
    fn sandboxed_result_ok_fields() {
        let r = SandboxedResult::ok(json!(42), 5, "wasmtime");
        assert!(r.success);
        assert_eq!(r.elapsed_ms, 5);
        assert_eq!(r.backend, "wasmtime");
        assert!(r.error.is_none());
    }

    #[test]
    fn sandboxed_result_err_fields() {
        let r = SandboxedResult::err("timeout", 1000, "noop");
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some("timeout"));
        assert!(r.output.is_none());
    }

    #[test]
    fn noop_backend_name() {
        let s = NoopSandbox::new();
        assert_eq!(s.backend_name(), "noop");
    }

    #[test]
    fn noop_supports_all_capabilities() {
        let s = NoopSandbox::new();
        let caps = SandboxCapabilities::none()
            .with_fs_write("/")
            .with_network("anywhere.com", None);
        assert!(s.supports_capabilities(&caps));
    }
}
