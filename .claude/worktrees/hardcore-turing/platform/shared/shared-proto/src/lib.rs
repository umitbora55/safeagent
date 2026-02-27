use serde::{Deserialize, Serialize};

use safeagent_shared_errors::ErrorResponse;
use safeagent_shared_identity::{Claims, NodeId, TenantId, UserId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillRequest {
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub node_id: NodeId,
    pub skill_name: String,
    pub input: String,
    pub required_scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillResponse {
    pub ok: bool,
    pub output: Option<String>,
    pub error: Option<ErrorResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub approval_id: String,
    pub request_id: String,
    pub node_id: String,
    pub skill_id: String,
    pub input_summary: String,
    pub reason: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecision {
    pub decision: String,
    pub decided_by: String,
    pub decided_at: i64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequestResponse {
    pub approval_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecisionRequest {
    pub approval_id: String,
    pub decision: String,
    pub decided_by: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecisionResponse {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalStatusResponse {
    pub approval_id: String,
    pub status: String,
    pub request: ApprovalRequest,
    pub decided_by: Option<String>,
    pub decided_at: Option<i64>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub node_id: NodeId,
    pub event_type: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEnvelope {
    pub token: String,
    pub claims: Claims,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRegisterRequest {
    pub addr: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRegisterResponse {
    pub node_id: String,
    pub registered_at: i64,
    pub worker_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueTokenRequest {
    pub subject: String,
    pub scopes: Vec<String>,
    pub ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueTokenResponse {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneExecuteRequest {
    pub subject: String,
    pub skill_id: String,
    pub input: String,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteRequest {
    pub token: String,
    pub skill_id: String,
    pub input: String,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteResponse {
    pub ok: bool,
    pub output: String,
    pub error: Option<String>,
    pub audit_id: Option<String>,
}
