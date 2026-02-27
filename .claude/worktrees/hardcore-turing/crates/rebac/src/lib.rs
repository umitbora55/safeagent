//! W10: ReBAC + AuthZEN Engine
//!
//! Implements Zanzibar-style Relationship-Based Access Control (ReBAC) using
//! OpenFGA semantics, plus an OpenID AuthZEN-compatible PDP endpoint,
//! dynamic scope inference, and task-scoped TTL delegation.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, warn};
use uuid::Uuid;

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum RebacError {
    #[error("circular relation detected in tuple graph")]
    CircularRelation,
    #[error("type mismatch: expected {expected}, got {actual}")]
    TypeMismatch { expected: String, actual: String },
    #[error("unknown object type: {0}")]
    UnknownObjectType(String),
    #[error("unknown relation: {relation} on type {object_type}")]
    UnknownRelation {
        relation: String,
        object_type: String,
    },
    #[error("scope {0} not found in registry")]
    ScopeNotFound(String),
    #[error("delegation expired at {0}")]
    DelegationExpired(DateTime<Utc>),
    #[error("max check depth exceeded")]
    MaxDepthExceeded,
}

// ── Core Types ───────────────────────────────────────────────────────────────

/// A typed object reference: `(type, id)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectRef {
    pub object_type: String,
    pub object_id: String,
}

impl ObjectRef {
    pub fn new(object_type: impl Into<String>, object_id: impl Into<String>) -> Self {
        Self {
            object_type: object_type.into(),
            object_id: object_id.into(),
        }
    }

    pub fn key(&self) -> String {
        format!("{}:{}", self.object_type, self.object_id)
    }
}

/// A userset reference: the set of users that have `relation` on `object`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UsersetRef {
    pub object: ObjectRef,
    pub relation: String,
}

/// The "user" in a relation tuple — either a direct user object or a userset.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TupleUser {
    Direct(ObjectRef),
    Userset(UsersetRef),
}

impl TupleUser {
    pub fn user(user_type: impl Into<String>, user_id: impl Into<String>) -> Self {
        TupleUser::Direct(ObjectRef::new(user_type, user_id))
    }

    pub fn userset(
        object_type: impl Into<String>,
        object_id: impl Into<String>,
        relation: impl Into<String>,
    ) -> Self {
        TupleUser::Userset(UsersetRef {
            object: ObjectRef::new(object_type, object_id),
            relation: relation.into(),
        })
    }
}

/// An OpenFGA-style relation tuple: `(user, relation, object)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationTuple {
    pub id: String,
    pub user: TupleUser,
    pub relation: String,
    pub object: ObjectRef,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, String>,
}

impl RelationTuple {
    pub fn new(user: TupleUser, relation: impl Into<String>, object: ObjectRef) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            user,
            relation: relation.into(),
            object,
            created_at: Utc::now(),
            expires_at: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_ttl(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_at {
            Utc::now() > exp
        } else {
            false
        }
    }
}

// ── Type System ──────────────────────────────────────────────────────────────

/// Defines what relations an object type supports and which are computed
/// via rewrites (union, intersection, exclusion, tupleset).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelationRewrite {
    /// Direct tuples only.
    Direct,
    /// Union of multiple relation rewrites.
    Union(Vec<String>),
    /// user from tupleset: compute `relation` on objects referenced by `tupleset`.
    TuplesetJoin {
        /// relation on object whose users we collect
        tupleset: String,
        /// relation on those collected users' referenced objects
        computed_userset: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDefinition {
    pub type_name: String,
    /// relation_name -> rewrite rule
    pub relations: HashMap<String, RelationRewrite>,
}

impl TypeDefinition {
    pub fn new(type_name: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            relations: HashMap::new(),
        }
    }

    pub fn with_direct(mut self, relation: impl Into<String>) -> Self {
        self.relations
            .insert(relation.into(), RelationRewrite::Direct);
        self
    }

    pub fn with_union(mut self, relation: impl Into<String>, parents: Vec<String>) -> Self {
        self.relations
            .insert(relation.into(), RelationRewrite::Union(parents));
        self
    }

    pub fn with_tupleset_join(
        mut self,
        relation: impl Into<String>,
        tupleset: impl Into<String>,
        computed_userset: impl Into<String>,
    ) -> Self {
        self.relations.insert(
            relation.into(),
            RelationRewrite::TuplesetJoin {
                tupleset: tupleset.into(),
                computed_userset: computed_userset.into(),
            },
        );
        self
    }
}

/// Authorization model — collection of type definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthModel {
    pub id: String,
    pub types: HashMap<String, TypeDefinition>,
}

impl AuthModel {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            types: HashMap::new(),
        }
    }

    pub fn add_type(mut self, typedef: TypeDefinition) -> Self {
        self.types.insert(typedef.type_name.clone(), typedef);
        self
    }

    /// Build a default SafeAgent authorization model.
    pub fn safeagent_default() -> Self {
        Self::new()
            .add_type(
                TypeDefinition::new("user")
                    .with_direct("member"),
            )
            .add_type(
                TypeDefinition::new("team")
                    .with_direct("member")
                    .with_direct("admin"),
            )
            .add_type(
                TypeDefinition::new("agent")
                    .with_direct("owner")
                    .with_direct("operator")
                    .with_tupleset_join("can_invoke", "owner", "member")
                    .with_union("admin", vec!["owner".into()]),
            )
            .add_type(
                TypeDefinition::new("tool")
                    .with_direct("allowed_agent")
                    .with_direct("blocked_agent")
                    .with_union("can_use", vec!["allowed_agent".into()]),
            )
            .add_type(
                TypeDefinition::new("namespace")
                    .with_direct("owner")
                    .with_direct("viewer")
                    .with_union("can_read", vec!["owner".into(), "viewer".into()]),
            )
    }
}

impl Default for AuthModel {
    fn default() -> Self {
        Self::safeagent_default()
    }
}

// ── ReBAC Engine (Zanzibar-style) ────────────────────────────────────────────

const MAX_CHECK_DEPTH: usize = 25;

/// In-memory tuple store with DashMap.
pub struct TupleStore {
    /// object_key -> Vec<RelationTuple>
    tuples: DashMap<String, Vec<RelationTuple>>,
}

impl TupleStore {
    pub fn new() -> Self {
        Self {
            tuples: DashMap::new(),
        }
    }

    pub fn write(&self, tuple: RelationTuple) {
        let key = tuple.object.key();
        self.tuples.entry(key).or_default().push(tuple);
    }

    pub fn delete(&self, tuple_id: &str) {
        for mut entry in self.tuples.iter_mut() {
            entry.value_mut().retain(|t| t.id != tuple_id);
        }
    }

    /// Get all non-expired tuples for `(relation, object)`.
    pub fn read(&self, relation: &str, object: &ObjectRef) -> Vec<RelationTuple> {
        let key = object.key();
        self.tuples
            .get(&key)
            .map(|v| {
                v.iter()
                    .filter(|t| t.relation == relation && !t.is_expired())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for TupleStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a ReBAC check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckResult {
    Allowed,
    Denied,
}

/// The core ReBAC engine implementing Zanzibar-style `check()`.
pub struct RebacEngine {
    store: Arc<TupleStore>,
    model: AuthModel,
}

impl RebacEngine {
    pub fn new(store: Arc<TupleStore>, model: AuthModel) -> Self {
        Self { store, model }
    }

    pub fn with_default_model(store: Arc<TupleStore>) -> Self {
        Self::new(store, AuthModel::safeagent_default())
    }

    /// Check whether `user` has `relation` on `object`.
    pub fn check(
        &self,
        user: &ObjectRef,
        relation: &str,
        object: &ObjectRef,
    ) -> Result<CheckResult, RebacError> {
        let mut visited = HashSet::new();
        self.check_recursive(user, relation, object, 0, &mut visited)
    }

    fn check_recursive(
        &self,
        user: &ObjectRef,
        relation: &str,
        object: &ObjectRef,
        depth: usize,
        visited: &mut HashSet<String>,
    ) -> Result<CheckResult, RebacError> {
        if depth > MAX_CHECK_DEPTH {
            return Err(RebacError::MaxDepthExceeded);
        }

        let visit_key = format!("{}#{}@{}", object.key(), relation, user.key());
        if visited.contains(&visit_key) {
            return Err(RebacError::CircularRelation);
        }
        visited.insert(visit_key);

        // Look up rewrite rule
        let rewrite = self
            .model
            .types
            .get(&object.object_type)
            .and_then(|td| td.relations.get(relation))
            .cloned()
            .unwrap_or(RelationRewrite::Direct);

        match rewrite {
            RelationRewrite::Direct => {
                let tuples = self.store.read(relation, object);
                for tuple in &tuples {
                    match &tuple.user {
                        TupleUser::Direct(direct_user) => {
                            if direct_user == user {
                                debug!("direct match: {} has {} on {}", user.key(), relation, object.key());
                                return Ok(CheckResult::Allowed);
                            }
                        }
                        TupleUser::Userset(userset) => {
                            // user is in userset if user has userset.relation on userset.object
                            match self.check_recursive(
                                user,
                                &userset.relation,
                                &userset.object,
                                depth + 1,
                                visited,
                            )? {
                                CheckResult::Allowed => {
                                    return Ok(CheckResult::Allowed);
                                }
                                CheckResult::Denied => {}
                            }
                        }
                    }
                }
                Ok(CheckResult::Denied)
            }

            RelationRewrite::Union(relations) => {
                for rel in &relations {
                    match self.check_recursive(user, rel, object, depth + 1, visited)? {
                        CheckResult::Allowed => return Ok(CheckResult::Allowed),
                        CheckResult::Denied => {}
                    }
                }
                Ok(CheckResult::Denied)
            }

            RelationRewrite::TuplesetJoin {
                tupleset,
                computed_userset,
            } => {
                // Collect all objects referenced via tupleset relation
                let ts_tuples = self.store.read(&tupleset, object);
                for ts_tuple in &ts_tuples {
                    if let TupleUser::Direct(ts_object) = &ts_tuple.user {
                        // ts_object is e.g. a "team" — check if user has computed_userset on it
                        match self.check_recursive(
                            user,
                            &computed_userset,
                            ts_object,
                            depth + 1,
                            visited,
                        )? {
                            CheckResult::Allowed => return Ok(CheckResult::Allowed),
                            CheckResult::Denied => {}
                        }
                    }
                }
                Ok(CheckResult::Denied)
            }
        }
    }

    /// List all users that have `relation` on `object` (BFS expansion).
    pub fn expand(&self, relation: &str, object: &ObjectRef) -> Vec<ObjectRef> {
        let mut result = Vec::new();
        let mut queue: VecDeque<(String, ObjectRef)> = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back((relation.to_string(), object.clone()));

        while let Some((rel, obj)) = queue.pop_front() {
            let key = format!("{}#{}", obj.key(), rel);
            if visited.contains(&key) {
                continue;
            }
            visited.insert(key);

            let tuples = self.store.read(&rel, &obj);
            for tuple in tuples {
                match tuple.user {
                    TupleUser::Direct(user) => result.push(user),
                    TupleUser::Userset(userset) => {
                        queue.push_back((userset.relation, userset.object));
                    }
                }
            }
        }
        result
    }
}

// ── AuthZEN PDP ──────────────────────────────────────────────────────────────

/// OpenID AuthZEN-compatible access request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthZenRequest {
    pub subject: AuthZenSubject,
    pub action: AuthZenAction,
    pub resource: AuthZenResource,
    pub context: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthZenSubject {
    /// Subject type, e.g. "user", "agent"
    #[serde(rename = "type")]
    pub subject_type: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthZenAction {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthZenResource {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
}

/// OpenID AuthZEN-compatible access response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthZenResponse {
    pub decision: bool,
    pub context: HashMap<String, serde_json::Value>,
}

impl AuthZenResponse {
    pub fn allow() -> Self {
        Self {
            decision: true,
            context: HashMap::new(),
        }
    }

    pub fn deny() -> Self {
        Self {
            decision: false,
            context: HashMap::new(),
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.context.insert(
            "reason".into(),
            serde_json::Value::String(reason.into()),
        );
        self
    }
}

/// AuthZEN PDP that delegates to the ReBAC engine.
pub struct AuthZenPdp {
    engine: Arc<RebacEngine>,
    /// Maps AuthZEN action names to ReBAC relations.
    action_relation_map: HashMap<String, String>,
}

impl AuthZenPdp {
    pub fn new(engine: Arc<RebacEngine>) -> Self {
        let mut map = HashMap::new();
        // Default mappings
        map.insert("invoke".into(), "can_invoke".into());
        map.insert("use_tool".into(), "can_use".into());
        map.insert("read".into(), "can_read".into());
        map.insert("admin".into(), "admin".into());
        map.insert("own".into(), "owner".into());
        map.insert("operate".into(), "operator".into());

        Self {
            engine,
            action_relation_map: map,
        }
    }

    pub fn with_action_mapping(
        mut self,
        action: impl Into<String>,
        relation: impl Into<String>,
    ) -> Self {
        self.action_relation_map.insert(action.into(), relation.into());
        self
    }

    /// Evaluate an AuthZEN access request.
    pub fn evaluate(&self, request: &AuthZenRequest) -> AuthZenResponse {
        let relation = match self.action_relation_map.get(&request.action.name) {
            Some(r) => r.clone(),
            None => {
                warn!(
                    "AuthZEN: no relation mapping for action '{}'",
                    request.action.name
                );
                return AuthZenResponse::deny().with_reason("unknown action");
            }
        };

        let subject = ObjectRef::new(
            &request.subject.subject_type,
            &request.subject.id,
        );
        let resource = ObjectRef::new(
            &request.resource.resource_type,
            &request.resource.id,
        );

        match self.engine.check(&subject, &relation, &resource) {
            Ok(CheckResult::Allowed) => AuthZenResponse::allow(),
            Ok(CheckResult::Denied) => {
                AuthZenResponse::deny().with_reason(format!(
                    "subject '{}' does not have '{}' on '{}'",
                    subject.key(),
                    relation,
                    resource.key()
                ))
            }
            Err(e) => {
                warn!("AuthZEN check error: {}", e);
                AuthZenResponse::deny().with_reason(format!("check error: {}", e))
            }
        }
    }
}

// ── Scope Inference ──────────────────────────────────────────────────────────

/// Inferred scope for a task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferredScope {
    pub task_id: String,
    pub agent: ObjectRef,
    /// Set of (relation, object) pairs this agent is authorized for this task.
    pub grants: Vec<ScopeGrant>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeGrant {
    pub relation: String,
    pub object: ObjectRef,
}

impl ScopeGrant {
    pub fn new(relation: impl Into<String>, object: ObjectRef) -> Self {
        Self {
            relation: relation.into(),
            object,
        }
    }
}

/// Infers minimal required scope for an agent performing a task.
pub struct ScopeInferenceEngine {
    engine: Arc<RebacEngine>,
}

impl ScopeInferenceEngine {
    pub fn new(engine: Arc<RebacEngine>) -> Self {
        Self { engine }
    }

    /// Given an agent and requested actions on objects, infer the minimal scope.
    /// Returns only grants for which the agent actually has the relation.
    pub fn infer(
        &self,
        task_id: impl Into<String>,
        agent: &ObjectRef,
        requested: &[ScopeGrant],
        ttl_seconds: i64,
    ) -> InferredScope {
        let mut grants = Vec::new();
        for req in requested {
            match self.engine.check(agent, &req.relation, &req.object) {
                Ok(CheckResult::Allowed) => grants.push(req.clone()),
                _ => {
                    debug!(
                        "Scope inference: {} denied {} on {}",
                        agent.key(),
                        req.relation,
                        req.object.key()
                    );
                }
            }
        }

        InferredScope {
            task_id: task_id.into(),
            agent: agent.clone(),
            grants,
            expires_at: Utc::now() + chrono::Duration::seconds(ttl_seconds),
        }
    }
}

// ── Task-Scoped TTL Delegation Registry ─────────────────────────────────────

/// Registry that stores task-scoped inferred scopes with TTL enforcement.
pub struct TaskScopeRegistry {
    scopes: DashMap<String, InferredScope>,
}

impl TaskScopeRegistry {
    pub fn new() -> Self {
        Self {
            scopes: DashMap::new(),
        }
    }

    pub fn register(&self, scope: InferredScope) {
        self.scopes.insert(scope.task_id.clone(), scope);
    }

    pub fn get(&self, task_id: &str) -> Option<InferredScope> {
        self.scopes.get(task_id).and_then(|entry| {
            if Utc::now() > entry.expires_at {
                None // expired
            } else {
                Some(entry.clone())
            }
        })
    }

    pub fn revoke(&self, task_id: &str) {
        self.scopes.remove(task_id);
    }

    /// Check if `agent` has `relation` on `object` within the scope of `task_id`.
    pub fn check_scope(
        &self,
        task_id: &str,
        agent: &ObjectRef,
        relation: &str,
        object: &ObjectRef,
    ) -> bool {
        self.get(task_id).map_or(false, |scope| {
            &scope.agent == agent
                && scope.grants.iter().any(|g| {
                    g.relation == relation && &g.object == object
                })
        })
    }

    /// Evict all expired scopes.
    pub fn evict_expired(&self) -> usize {
        let now = Utc::now();
        let expired_keys: Vec<String> = self
            .scopes
            .iter()
            .filter(|e| now > e.expires_at)
            .map(|e| e.key().clone())
            .collect();
        let count = expired_keys.len();
        for key in expired_keys {
            self.scopes.remove(&key);
        }
        count
    }

    pub fn active_count(&self) -> usize {
        self.scopes.len()
    }
}

impl Default for TaskScopeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── KPI Tracker ──────────────────────────────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RebacKpis {
    pub total_checks: u64,
    pub allowed: u64,
    pub denied: u64,
    pub errors: u64,
    pub authzen_requests: u64,
    pub scope_inferences: u64,
    pub active_task_scopes: u64,
}

impl RebacKpis {
    pub fn allow_rate(&self) -> f64 {
        if self.total_checks == 0 {
            0.0
        } else {
            self.allowed as f64 / self.total_checks as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> Arc<TupleStore> {
        Arc::new(TupleStore::new())
    }

    fn make_engine(store: Arc<TupleStore>) -> Arc<RebacEngine> {
        Arc::new(RebacEngine::with_default_model(store))
    }

    // ── ObjectRef tests ──────────────────────────────────────────────────────

    #[test]
    fn object_ref_key_format() {
        let obj = ObjectRef::new("agent", "claude-1");
        assert_eq!(obj.key(), "agent:claude-1");
    }

    // ── Tuple expiry ─────────────────────────────────────────────────────────

    #[test]
    fn expired_tuple_not_matched() {
        let store = make_store();
        let alice = ObjectRef::new("user", "alice");
        let agent = ObjectRef::new("agent", "bot-1");
        let past = Utc::now() - chrono::Duration::seconds(10);
        let tuple = RelationTuple::new(
            TupleUser::Direct(alice.clone()),
            "owner",
            agent.clone(),
        )
        .with_ttl(past);
        store.write(tuple);

        let engine = make_engine(store);
        let result = engine.check(&alice, "owner", &agent).unwrap();
        assert_eq!(result, CheckResult::Denied);
    }

    // ── Direct relation ──────────────────────────────────────────────────────

    #[test]
    fn direct_owner_check() {
        let store = make_store();
        let alice = ObjectRef::new("user", "alice");
        let agent = ObjectRef::new("agent", "bot-1");
        store.write(RelationTuple::new(
            TupleUser::Direct(alice.clone()),
            "owner",
            agent.clone(),
        ));

        let engine = make_engine(store);
        assert_eq!(engine.check(&alice, "owner", &agent).unwrap(), CheckResult::Allowed);
    }

    #[test]
    fn unknown_user_denied() {
        let store = make_store();
        let alice = ObjectRef::new("user", "alice");
        let bob = ObjectRef::new("user", "bob");
        let agent = ObjectRef::new("agent", "bot-1");
        store.write(RelationTuple::new(
            TupleUser::Direct(alice.clone()),
            "owner",
            agent.clone(),
        ));

        let engine = make_engine(store);
        assert_eq!(engine.check(&bob, "owner", &agent).unwrap(), CheckResult::Denied);
    }

    // ── Union relation ───────────────────────────────────────────────────────

    #[test]
    fn admin_via_union_of_owner() {
        let store = make_store();
        let alice = ObjectRef::new("user", "alice");
        let agent = ObjectRef::new("agent", "bot-1");
        // alice is owner of bot-1; admin = union[owner]
        store.write(RelationTuple::new(
            TupleUser::Direct(alice.clone()),
            "owner",
            agent.clone(),
        ));

        let engine = make_engine(store);
        // admin relation is union[owner] in default model
        assert_eq!(engine.check(&alice, "admin", &agent).unwrap(), CheckResult::Allowed);
    }

    // ── Userset relation ─────────────────────────────────────────────────────

    #[test]
    fn userset_membership() {
        let store = make_store();
        let alice = ObjectRef::new("user", "alice");
        let team = ObjectRef::new("team", "engineers");

        // alice is member of engineers team
        store.write(RelationTuple::new(
            TupleUser::Direct(alice.clone()),
            "member",
            team.clone(),
        ));

        let engine = make_engine(store);
        assert_eq!(engine.check(&alice, "member", &team).unwrap(), CheckResult::Allowed);
    }

    #[test]
    fn indirect_tool_access_via_userset() {
        let store = make_store();
        let alice = ObjectRef::new("user", "alice");
        let agent = ObjectRef::new("agent", "bot-1");
        let tool = ObjectRef::new("tool", "web-search");

        // agent is allowed_agent of tool
        store.write(RelationTuple::new(
            TupleUser::Direct(agent.clone()),
            "allowed_agent",
            tool.clone(),
        ));

        let engine = make_engine(store);
        // can_use = union[allowed_agent]
        assert_eq!(engine.check(&agent, "can_use", &tool).unwrap(), CheckResult::Allowed);
        // alice doesn't have direct access
        assert_eq!(engine.check(&alice, "can_use", &tool).unwrap(), CheckResult::Denied);
    }

    // ── TuplesetJoin ─────────────────────────────────────────────────────────

    #[test]
    fn can_invoke_via_tupleset_join() {
        let store = make_store();
        let alice = ObjectRef::new("user", "alice");
        let team = ObjectRef::new("team", "eng");
        let agent = ObjectRef::new("agent", "bot-1");

        // bot-1 owner = team:eng (userset)
        store.write(RelationTuple::new(
            TupleUser::Direct(team.clone()),
            "owner",
            agent.clone(),
        ));
        // alice is member of team:eng
        store.write(RelationTuple::new(
            TupleUser::Direct(alice.clone()),
            "member",
            team.clone(),
        ));

        let engine = make_engine(store);
        // can_invoke = tupleset_join(owner, member)
        // alice member of team:eng, team:eng is owner of bot-1 → alice can_invoke bot-1
        assert_eq!(engine.check(&alice, "can_invoke", &agent).unwrap(), CheckResult::Allowed);
    }

    // ── Expand ───────────────────────────────────────────────────────────────

    #[test]
    fn expand_returns_all_direct_owners() {
        let store = make_store();
        let alice = ObjectRef::new("user", "alice");
        let bob = ObjectRef::new("user", "bob");
        let agent = ObjectRef::new("agent", "bot-1");

        store.write(RelationTuple::new(TupleUser::Direct(alice.clone()), "owner", agent.clone()));
        store.write(RelationTuple::new(TupleUser::Direct(bob.clone()), "owner", agent.clone()));

        let engine = make_engine(store);
        let owners = engine.expand("owner", &agent);
        assert_eq!(owners.len(), 2);
        assert!(owners.contains(&alice));
        assert!(owners.contains(&bob));
    }

    // ── AuthZEN PDP ──────────────────────────────────────────────────────────

    #[test]
    fn authzen_allow() {
        let store = make_store();
        let alice = ObjectRef::new("user", "alice");
        let agent = ObjectRef::new("agent", "bot-1");
        store.write(RelationTuple::new(TupleUser::Direct(alice.clone()), "owner", agent.clone()));

        let engine = make_engine(store);
        let pdp = AuthZenPdp::new(engine);

        let req = AuthZenRequest {
            subject: AuthZenSubject {
                subject_type: "user".into(),
                id: "alice".into(),
            },
            action: AuthZenAction { name: "own".into() },
            resource: AuthZenResource {
                resource_type: "agent".into(),
                id: "bot-1".into(),
            },
            context: HashMap::new(),
        };

        let resp = pdp.evaluate(&req);
        assert!(resp.decision);
    }

    #[test]
    fn authzen_deny_unknown_action() {
        let store = make_store();
        let engine = make_engine(store);
        let pdp = AuthZenPdp::new(engine);

        let req = AuthZenRequest {
            subject: AuthZenSubject {
                subject_type: "user".into(),
                id: "alice".into(),
            },
            action: AuthZenAction { name: "fly".into() },
            resource: AuthZenResource {
                resource_type: "agent".into(),
                id: "bot-1".into(),
            },
            context: HashMap::new(),
        };

        let resp = pdp.evaluate(&req);
        assert!(!resp.decision);
    }

    // ── Scope Inference ──────────────────────────────────────────────────────

    #[test]
    fn scope_inference_filters_unauthorized() {
        let store = make_store();
        let agent = ObjectRef::new("agent", "bot-1");
        let tool_a = ObjectRef::new("tool", "web-search");
        let tool_b = ObjectRef::new("tool", "file-write");

        // bot-1 can use tool_a but not tool_b
        store.write(RelationTuple::new(
            TupleUser::Direct(agent.clone()),
            "allowed_agent",
            tool_a.clone(),
        ));

        let engine = make_engine(store);
        let inference_engine = ScopeInferenceEngine::new(Arc::clone(&engine));

        let scope = inference_engine.infer(
            "task-1",
            &agent,
            &[
                ScopeGrant::new("can_use", tool_a.clone()),
                ScopeGrant::new("can_use", tool_b.clone()),
            ],
            300,
        );

        assert_eq!(scope.grants.len(), 1);
        assert_eq!(scope.grants[0].object, tool_a);
    }

    // ── TaskScopeRegistry ────────────────────────────────────────────────────

    #[test]
    fn task_scope_check_success() {
        let store = make_store();
        let agent = ObjectRef::new("agent", "bot-1");
        let tool = ObjectRef::new("tool", "web-search");

        store.write(RelationTuple::new(
            TupleUser::Direct(agent.clone()),
            "allowed_agent",
            tool.clone(),
        ));

        let engine = make_engine(store);
        let inference_engine = ScopeInferenceEngine::new(Arc::clone(&engine));
        let registry = TaskScopeRegistry::new();

        let scope = inference_engine.infer("task-1", &agent, &[ScopeGrant::new("can_use", tool.clone())], 300);
        registry.register(scope);

        assert!(registry.check_scope("task-1", &agent, "can_use", &tool));
        assert!(!registry.check_scope("task-1", &agent, "admin", &tool));
    }

    #[test]
    fn task_scope_expired_returns_none() {
        let registry = TaskScopeRegistry::new();
        let agent = ObjectRef::new("agent", "bot-1");

        let scope = InferredScope {
            task_id: "task-expired".into(),
            agent: agent.clone(),
            grants: vec![],
            expires_at: Utc::now() - chrono::Duration::seconds(1),
        };
        registry.register(scope);

        assert!(registry.get("task-expired").is_none());
    }

    #[test]
    fn evict_expired_removes_stale_scopes() {
        let registry = TaskScopeRegistry::new();
        let agent = ObjectRef::new("agent", "bot-1");

        for i in 0..3 {
            let scope = InferredScope {
                task_id: format!("task-{}", i),
                agent: agent.clone(),
                grants: vec![],
                expires_at: Utc::now() - chrono::Duration::seconds(1),
            };
            registry.register(scope);
        }
        // one live scope
        let live = InferredScope {
            task_id: "task-live".into(),
            agent: agent.clone(),
            grants: vec![],
            expires_at: Utc::now() + chrono::Duration::seconds(300),
        };
        registry.register(live);

        let evicted = registry.evict_expired();
        assert_eq!(evicted, 3);
        assert_eq!(registry.active_count(), 1);
    }

    // ── KPIs ─────────────────────────────────────────────────────────────────

    #[test]
    fn kpis_allow_rate_zero_on_empty() {
        let kpis = RebacKpis::default();
        assert_eq!(kpis.allow_rate(), 0.0);
    }

    #[test]
    fn kpis_allow_rate_computed() {
        let kpis = RebacKpis {
            total_checks: 10,
            allowed: 7,
            denied: 3,
            ..Default::default()
        };
        assert!((kpis.allow_rate() - 0.7).abs() < f64::EPSILON);
    }
}
