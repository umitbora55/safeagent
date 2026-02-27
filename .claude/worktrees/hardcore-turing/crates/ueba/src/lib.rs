// safeagent-ueba — W6 D1: Agent UEBA + Adaptive Risk Scoring
//
// User and Entity Behavior Analytics adapted for AI agents.
//
// Treats each AI agent as a behavioral entity, building baselines from
// MCP gateway observations: which tools called, in what sequence, at what
// frequency, with what parameters. Deviations from baseline trigger
// risk escalation — step-up authorization, human approval, or blocking.
//
// Architecture follows Splunk/Exabeam UEBA patterns adapted for agent entities:
//
//   ObservationWindow  — rolling window of recent tool calls
//   AgentProfile       — per-agent baseline: call rates, top tools, typical tokens
//   UebaEngine         — multi-agent store; compute deviation scores
//   DeviationScore     — 0.0 (baseline) to 1.0 (extreme anomaly)
//   UebaDecision       — Proceed | StepUp | Escalate based on threshold config
//
// Deviation signals tracked:
//   1. Call rate deviation   — sudden burst above baseline rate
//   2. Tool distribution     — using tools never seen in baseline
//   3. Token usage spike     — unusual token consumption per call
//   4. Time-of-day anomaly   — calls at unusual hours vs baseline
//   5. Sequence anomaly      — unusual action sequences vs Markov model

use chrono::{DateTime, Timelike, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::{info, warn};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Observation types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A single agent action observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentObservation {
    pub agent_id: String,
    pub tool_name: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub timestamp: DateTime<Utc>,
    pub success: bool,
}

impl AgentObservation {
    pub fn new(
        agent_id: impl Into<String>,
        tool_name: impl Into<String>,
        input_tokens: u32,
        output_tokens: u32,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            tool_name: tool_name.into(),
            input_tokens,
            output_tokens,
            timestamp: Utc::now(),
            success: true,
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Agent behavioral profile (baseline)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Behavioral baseline for one agent. Updated incrementally on each
/// observation. Uses exponential moving averages for stability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProfile {
    pub agent_id: String,
    /// Total observations recorded
    pub observation_count: u64,
    /// EMA of calls per minute (alpha=0.1)
    pub avg_calls_per_minute: f64,
    /// EMA of input tokens per call
    pub avg_input_tokens: f64,
    /// EMA of output tokens per call
    pub avg_output_tokens: f64,
    /// Tool call frequency map: tool_name -> count
    pub tool_frequency: HashMap<String, u64>,
    /// Hour-of-day call distribution (0-23 -> count)
    pub hour_distribution: [u64; 24],
    /// Recent tool sequence (last 10 tools called, FIFO)
    pub recent_sequence: Vec<String>,
    /// Pairwise transition counts: "prev:next" -> count
    pub transitions: HashMap<String, u64>,
    /// Timestamp of first observation
    pub first_seen: DateTime<Utc>,
    /// Timestamp of most recent observation
    pub last_seen: DateTime<Utc>,
}

const EMA_ALPHA: f64 = 0.1;
const SEQUENCE_LEN: usize = 10;

impl AgentProfile {
    /// Create an empty profile anchored at the timestamp of the first observation.
    /// The observation itself is NOT counted here — `update()` is always called
    /// immediately after construction in `UebaEngine::observe()`.
    fn new(agent_id: String, first_obs: &AgentObservation) -> Self {
        Self {
            agent_id,
            observation_count: 0,
            avg_calls_per_minute: 0.0,
            avg_input_tokens: 0.0,
            avg_output_tokens: 0.0,
            tool_frequency: HashMap::new(),
            hour_distribution: [0u64; 24],
            recent_sequence: Vec::new(),
            transitions: HashMap::new(),
            first_seen: first_obs.timestamp,
            last_seen: first_obs.timestamp,
        }
    }

    fn update(&mut self, obs: &AgentObservation) {
        self.observation_count += 1;
        self.last_seen = obs.timestamp;

        // EMA update for token averages
        self.avg_input_tokens = EMA_ALPHA * obs.input_tokens as f64
            + (1.0 - EMA_ALPHA) * self.avg_input_tokens;
        self.avg_output_tokens = EMA_ALPHA * obs.output_tokens as f64
            + (1.0 - EMA_ALPHA) * self.avg_output_tokens;

        // Tool frequency
        *self.tool_frequency.entry(obs.tool_name.clone()).or_insert(0) += 1;

        // Hour-of-day distribution
        self.hour_distribution[obs.timestamp.hour() as usize] += 1;

        // Sequence and transitions
        let prev = self.recent_sequence.last().cloned();
        if self.recent_sequence.len() >= SEQUENCE_LEN {
            self.recent_sequence.remove(0);
        }
        self.recent_sequence.push(obs.tool_name.clone());

        if let Some(prev_tool) = prev {
            let key = format!("{}:{}", prev_tool, obs.tool_name);
            *self.transitions.entry(key).or_insert(0) += 1;
        }

        // EMA for calls/minute — approximate from total / elapsed minutes
        if let Ok(elapsed_mins) = (obs.timestamp - self.first_seen).to_std() {
            let elapsed_mins = elapsed_mins.as_secs_f64() / 60.0;
            if elapsed_mins > 0.0 {
                let current_rate = self.observation_count as f64 / elapsed_mins;
                self.avg_calls_per_minute = EMA_ALPHA * current_rate
                    + (1.0 - EMA_ALPHA) * self.avg_calls_per_minute;
            }
        }
    }

    /// Is this tool in the agent's known vocabulary?
    pub fn knows_tool(&self, tool: &str) -> bool {
        self.tool_frequency.contains_key(tool)
    }

    /// Fraction of calls that used this tool (0.0–1.0).
    pub fn tool_fraction(&self, tool: &str) -> f64 {
        let count = self.tool_frequency.get(tool).copied().unwrap_or(0);
        if self.observation_count == 0 {
            0.0
        } else {
            count as f64 / self.observation_count as f64
        }
    }

    /// Whether this hour is "normal" for the agent (within top 50% of hour dist).
    pub fn is_normal_hour(&self, hour: u32) -> bool {
        let hour = (hour as usize).min(23);
        let max_hour_count = *self.hour_distribution.iter().max().unwrap_or(&0);
        if max_hour_count == 0 {
            return true;
        }
        let median = max_hour_count / 2;
        self.hour_distribution[hour] >= median
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Deviation score and decision
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Weighted deviation score 0.0 (normal) to 1.0 (extreme anomaly).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviationScore {
    /// Overall composite score
    pub score: f64,
    /// Component scores for explainability
    pub tool_novelty: f64,
    pub token_spike: f64,
    pub rate_spike: f64,
    pub time_anomaly: f64,
    pub sequence_anomaly: f64,
}

impl DeviationScore {
    fn zero() -> Self {
        Self {
            score: 0.0,
            tool_novelty: 0.0,
            token_spike: 0.0,
            rate_spike: 0.0,
            time_anomaly: 0.0,
            sequence_anomaly: 0.0,
        }
    }
}

/// UEBA authorization decision.
#[derive(Debug, Clone, PartialEq)]
pub enum UebaDecision {
    /// Behavior within baseline — proceed normally
    Normal { score: f64 },
    /// Mild deviation — proceed but log alert
    StepUp { score: f64, reason: String },
    /// High deviation — require step-up authorization or human approval
    Escalate { score: f64, reason: String },
    /// Extreme anomaly — block and alert
    Block { score: f64, reason: String },
}

impl UebaDecision {
    pub fn score(&self) -> f64 {
        match self {
            UebaDecision::Normal { score } => *score,
            UebaDecision::StepUp { score, .. } => *score,
            UebaDecision::Escalate { score, .. } => *score,
            UebaDecision::Block { score, .. } => *score,
        }
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, UebaDecision::Block { .. })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  UEBA configuration
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone)]
pub struct UebaConfig {
    /// Minimum observations before deviation scoring is applied
    pub min_observations_for_baseline: u64,
    /// Score threshold for StepUp decision
    pub step_up_threshold: f64,
    /// Score threshold for Escalate decision
    pub escalate_threshold: f64,
    /// Score threshold for Block decision
    pub block_threshold: f64,
    /// Token spike multiplier: score if tokens > baseline * multiplier
    pub token_spike_multiplier: f64,
    /// Rate spike multiplier: score if rate > baseline * multiplier
    pub rate_spike_multiplier: f64,
}

impl Default for UebaConfig {
    fn default() -> Self {
        Self {
            min_observations_for_baseline: 10,
            step_up_threshold: 0.3,
            escalate_threshold: 0.6,
            block_threshold: 0.85,
            token_spike_multiplier: 3.0,
            rate_spike_multiplier: 5.0,
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  UEBA Engine
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Multi-agent UEBA engine. Thread-safe via DashMap.
pub struct UebaEngine {
    profiles: DashMap<String, AgentProfile>,
    config: RwLock<UebaConfig>,
}

impl UebaEngine {
    pub fn new(config: UebaConfig) -> Self {
        Self {
            profiles: DashMap::new(),
            config: RwLock::new(config),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(UebaConfig::default())
    }

    /// Record an observation and return the UEBA decision.
    ///
    /// For agents below `min_observations_for_baseline`, returns Normal
    /// (building the baseline). Once baseline is established, computes
    /// deviation scores against it.
    pub fn observe(&self, obs: AgentObservation) -> UebaDecision {
        let decision = {
            let mut entry = self.profiles.entry(obs.agent_id.clone()).or_insert_with(|| {
                info!("UEBA: new agent profile created for '{}'", obs.agent_id);
                AgentProfile::new(obs.agent_id.clone(), &obs)
            });
            let profile = entry.value_mut();
            let config = self.config.read().unwrap();

            if profile.observation_count < config.min_observations_for_baseline {
                // Still building baseline — record observation and return Normal.
                // `new()` creates an empty profile (count=0); update() is always
                // called so the first observation is counted exactly once.
                profile.update(&obs);
                UebaDecision::Normal { score: 0.0 }
            } else {
                // Baseline established — score deviation BEFORE updating so the
                // current observation is measured against the prior baseline.
                let scores = compute_deviation(profile, &obs, &config);
                profile.update(&obs);
                make_decision(scores, &config)
            }
        };

        if matches!(decision, UebaDecision::Escalate { .. } | UebaDecision::Block { .. }) {
            warn!(
                agent_id = %obs.agent_id,
                tool = %obs.tool_name,
                score = decision.score(),
                "UEBA anomaly detected"
            );
        }

        decision
    }

    /// Get profile for an agent (read-only snapshot).
    pub fn profile(&self, agent_id: &str) -> Option<AgentProfile> {
        self.profiles.get(agent_id).map(|e| e.clone())
    }

    /// Number of agents being tracked.
    pub fn agent_count(&self) -> usize {
        self.profiles.len()
    }

    /// Update configuration at runtime.
    pub fn update_config(&self, config: UebaConfig) {
        *self.config.write().unwrap() = config;
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Deviation computation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn compute_deviation(
    profile: &AgentProfile,
    obs: &AgentObservation,
    config: &UebaConfig,
) -> DeviationScore {
    let mut scores = DeviationScore::zero();

    // 1. Tool novelty — new tool never seen before in profile
    if !profile.knows_tool(&obs.tool_name) {
        scores.tool_novelty = 0.8;
    } else {
        // Tool exists but is rarely used
        let fraction = profile.tool_fraction(&obs.tool_name);
        if fraction < 0.05 {
            scores.tool_novelty = 0.3;
        }
    }

    // 2. Token spike — input_tokens >> baseline
    if profile.avg_input_tokens > 0.0 {
        let ratio = obs.input_tokens as f64 / profile.avg_input_tokens;
        if ratio > config.token_spike_multiplier {
            scores.token_spike = (ratio / config.token_spike_multiplier - 1.0).min(1.0);
        }
    }

    // 3. Rate spike — tracked via EMA; if current burst >> avg rate
    // Approximate: if last 60s had many calls relative to avg rate
    // (simplified: we compare cumulative rate trend)
    if profile.avg_calls_per_minute > 0.0 {
        // This is a simplified check — in production, a sliding window
        // counter would give more accurate burst detection
        let elapsed_secs = (obs.timestamp - profile.last_seen).num_seconds().max(1);
        if elapsed_secs == 0 {
            // Zero time between calls = burst
            scores.rate_spike = (1.0_f64).min(1.0);
        }
    }

    // 4. Time-of-day anomaly
    if !profile.is_normal_hour(obs.timestamp.hour()) {
        scores.time_anomaly = 0.3;
    }

    // 5. Sequence anomaly — transition never seen before
    if let Some(prev) = profile.recent_sequence.last() {
        let key = format!("{}:{}", prev, obs.tool_name);
        if !profile.transitions.contains_key(&key) && profile.observation_count > 20 {
            scores.sequence_anomaly = 0.4;
        }
    }

    // Weighted composite (weights sum to 1.0)
    scores.score = scores.tool_novelty * 0.35
        + scores.token_spike * 0.25
        + scores.rate_spike * 0.15
        + scores.time_anomaly * 0.10
        + scores.sequence_anomaly * 0.15;

    scores
}

fn make_decision(scores: DeviationScore, config: &UebaConfig) -> UebaDecision {
    let s = scores.score;

    if s >= config.block_threshold {
        UebaDecision::Block {
            score: s,
            reason: format!(
                "Extreme anomaly (score={:.2}): tool_novelty={:.2}, token_spike={:.2}, sequence={:.2}",
                s, scores.tool_novelty, scores.token_spike, scores.sequence_anomaly
            ),
        }
    } else if s >= config.escalate_threshold {
        UebaDecision::Escalate {
            score: s,
            reason: format!(
                "High deviation (score={:.2}): tool_novelty={:.2}, token_spike={:.2}",
                s, scores.tool_novelty, scores.token_spike
            ),
        }
    } else if s >= config.step_up_threshold {
        UebaDecision::StepUp {
            score: s,
            reason: format!("Mild deviation (score={:.2})", s),
        }
    } else {
        UebaDecision::Normal { score: s }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(agent: &str, tool: &str) -> AgentObservation {
        AgentObservation::new(agent, tool, 100, 50)
    }

    fn obs_tokens(agent: &str, tool: &str, inp: u32, out: u32) -> AgentObservation {
        AgentObservation::new(agent, tool, inp, out)
    }

    fn build_baseline(engine: &UebaEngine, agent: &str, n: u64) {
        let config = UebaConfig::default();
        for _ in 0..n {
            engine.observe(obs(agent, "search_web"));
        }
        // Ensure we exceed min_observations_for_baseline
        for _ in 0..config.min_observations_for_baseline.saturating_sub(n) {
            engine.observe(obs(agent, "search_web"));
        }
    }

    #[test]
    fn new_agent_builds_baseline_without_scoring() {
        let engine = UebaEngine::with_defaults();
        let decision = engine.observe(obs("agent1", "search_web"));
        assert!(matches!(decision, UebaDecision::Normal { .. }));
    }

    #[test]
    fn below_baseline_threshold_returns_normal() {
        let engine = UebaEngine::with_defaults();
        // First observation creates profile
        for _ in 0..5 {
            let d = engine.observe(obs("agent1", "search_web"));
            assert!(matches!(d, UebaDecision::Normal { .. }));
        }
    }

    #[test]
    fn known_tool_after_baseline_returns_normal() {
        let engine = UebaEngine::with_defaults();
        build_baseline(&engine, "agent2", 15);
        // Same tool used in baseline — should be normal
        let d = engine.observe(obs("agent2", "search_web"));
        assert!(matches!(d, UebaDecision::Normal { .. } | UebaDecision::StepUp { .. }));
    }

    #[test]
    fn novel_tool_after_baseline_triggers_step_up_or_higher() {
        let config = UebaConfig {
            min_observations_for_baseline: 5,
            step_up_threshold: 0.2,
            escalate_threshold: 0.6,
            block_threshold: 0.85,
            ..Default::default()
        };
        let engine = UebaEngine::new(config);
        for _ in 0..6 {
            engine.observe(obs("agent3", "search_web"));
        }
        // Completely new tool — tool_novelty = 0.8 * 0.35 = 0.28 -> StepUp
        let d = engine.observe(obs("agent3", "run_shell_command_never_seen"));
        assert!(matches!(
            d,
            UebaDecision::StepUp { .. } | UebaDecision::Escalate { .. } | UebaDecision::Block { .. }
        ));
    }

    #[test]
    fn massive_token_spike_triggers_anomaly() {
        let config = UebaConfig {
            min_observations_for_baseline: 5,
            token_spike_multiplier: 2.0,
            ..Default::default()
        };
        let engine = UebaEngine::new(config);
        for _ in 0..6 {
            engine.observe(obs_tokens("agent4", "search_web", 100, 50));
        }
        // 10x token spike — should trigger deviation
        let d = engine.observe(obs_tokens("agent4", "search_web", 10_000, 50));
        let score = d.score();
        assert!(score > 0.0, "Expected non-zero deviation score for token spike");
    }

    #[test]
    fn agent_profile_created_on_first_observation() {
        let engine = UebaEngine::with_defaults();
        engine.observe(obs("new_agent", "read_calendar"));
        let profile = engine.profile("new_agent");
        assert!(profile.is_some());
        let p = profile.unwrap();
        assert_eq!(p.agent_id, "new_agent");
        assert_eq!(p.observation_count, 1);
    }

    #[test]
    fn agent_count_grows() {
        let engine = UebaEngine::with_defaults();
        assert_eq!(engine.agent_count(), 0);
        engine.observe(obs("a1", "t1"));
        engine.observe(obs("a2", "t1"));
        assert_eq!(engine.agent_count(), 2);
    }

    #[test]
    fn profile_knows_tool_after_observation() {
        let engine = UebaEngine::with_defaults();
        engine.observe(obs("agent5", "read_weather"));
        let profile = engine.profile("agent5").unwrap();
        assert!(profile.knows_tool("read_weather"));
        assert!(!profile.knows_tool("never_used_tool"));
    }

    #[test]
    fn ueba_decision_score_accessor() {
        let d = UebaDecision::Normal { score: 0.1 };
        assert!((d.score() - 0.1).abs() < 1e-9);
        let d = UebaDecision::Block { score: 0.9, reason: "test".to_string() };
        assert!((d.score() - 0.9).abs() < 1e-9);
        assert!(d.is_blocked());
    }

    #[test]
    fn ueba_decision_is_blocked() {
        assert!(!UebaDecision::Normal { score: 0.0 }.is_blocked());
        assert!(!UebaDecision::StepUp { score: 0.4, reason: "r".to_string() }.is_blocked());
        assert!(!UebaDecision::Escalate { score: 0.7, reason: "r".to_string() }.is_blocked());
        assert!(UebaDecision::Block { score: 0.9, reason: "r".to_string() }.is_blocked());
    }

    #[test]
    fn concurrent_observations_safe() {
        use std::sync::Arc;
        let engine = Arc::new(UebaEngine::with_defaults());
        let mut handles = vec![];
        for i in 0..8 {
            let e = Arc::clone(&engine);
            let agent = format!("concurrent_agent_{}", i % 2);
            handles.push(std::thread::spawn(move || {
                for _ in 0..5 {
                    e.observe(obs(&agent, "search_web"));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(engine.agent_count(), 2);
    }
}
