# CRITICAL_FLOWS.md — Kritik İş Akışları

> FAZ 0 Read-Only Analiz | Tarih: 2026-02-24

---

## Flow 1: User Message → LLM Response (Ana Akış)

### Sequence Diagram

```
┌────────┐ ┌───────────┐ ┌────────────┐ ┌───────────┐ ┌──────────┐ ┌───────────┐ ┌──────────┐
│  User  │ │  Gateway  │ │PromptGuard │ │PolicyEngine│ │LLMRouter │ │ Provider  │ │MemoryStore│
└───┬────┘ └─────┬─────┘ └─────┬──────┘ └─────┬─────┘ └────┬─────┘ └─────┬─────┘ └─────┬─────┘
    │            │             │              │            │             │             │
    │ input      │             │              │            │             │             │
    ├───────────►│             │              │            │             │             │
    │            │ sanitize    │              │            │             │             │
    │            ├────────────►│              │            │             │             │
    │            │             │              │            │             │             │
    │            │ SanitizeResult              │            │             │             │
    │            │◄────────────┤              │            │             │             │
    │            │             │              │            │             │             │
    │            │ risk>0.5?   │              │            │             │             │
    │            │ ──BLOCK──   │              │            │             │             │
    │            │             │              │            │             │             │
    │            │ check_budget│              │            │             │             │
    │            ├─────────────┼─────────────►│            │             │             │
    │            │             │              │            │             │             │
    │            │ PolicyDecision             │            │             │             │
    │            │◄────────────┼──────────────┤            │             │             │
    │            │             │              │            │             │             │
    │            │ route       │              │            │             │             │
    │            ├─────────────┼──────────────┼───────────►│             │             │
    │            │             │              │            │             │             │
    │            │ provider    │              │            │             │             │
    │            │◄────────────┼──────────────┼────────────┤             │             │
    │            │             │              │            │             │             │
    │            │ API call    │              │            │             │             │
    │            ├─────────────┼──────────────┼────────────┼────────────►│             │
    │            │             │              │            │             │             │
    │            │ response    │              │            │             │             │
    │            │◄────────────┼──────────────┼────────────┼─────────────┤             │
    │            │             │              │            │             │             │
    │            │ add_message │              │            │             │             │
    │            ├─────────────┼──────────────┼────────────┼─────────────┼────────────►│
    │            │             │              │            │             │             │
    │ response   │             │              │            │             │             │
    │◄───────────┤             │              │            │             │             │
    │            │             │              │            │             │             │
```

### Kod Referansları

#### Step 1: User Input (Gateway)
**Kaynak:** `crates/gateway/src/main.rs:950-980`
```rust
// CLI input loop
loop {
    let input = read_input()?;
    if input.is_empty() { continue; }

    // Process message
    let response = process_message(&input, &ctx).await?;
    println!("{}", response);
}
```

#### Step 2: Sanitization (PromptGuard)
**Kaynak:** `crates/prompt-guard/src/lib.rs:180-250`
```rust
pub fn sanitize(&self, text: &str, source: ContentSource) -> SanitizeResult {
    let mut threats = Vec::new();
    let mut risk_score = 0.0;

    // 1. Check invisible characters
    if has_invisible_chars(text) {
        threats.push(Threat::new(ThreatType::InvisibleCharacters));
        risk_score += 0.3;  // Cap: 0.3
    }

    // 2. Check prompt injection
    let normalized = normalize(text);
    for pattern in &self.injection_patterns {
        if pattern.is_match(&normalized) {
            threats.push(Threat::new(ThreatType::PromptInjection));
            risk_score += 0.6;  // Cap: 0.6
            break;
        }
    }

    // 3. Remove threats, return clean text
    SanitizeResult {
        clean_text: remove_threats(text),
        threats,
        risk_score: risk_score.min(1.0),
    }
}
```

#### Step 3: Policy Check (PolicyEngine)
**Kaynak:** `crates/policy-engine/src/lib.rs:200-250`
```rust
pub fn check_budget(&self) -> Result<(), PolicyError> {
    let daily = self.daily_spend.load(Ordering::SeqCst);
    if let Some(limit) = self.config.daily_spend_limit_microdollars {
        if daily > limit {
            return Err(PolicyError::BudgetExceeded {
                spent: daily,
                limit,
            });
        }
    }
    Ok(())
}

pub fn check_action(&self, action: &ActionType) -> PolicyDecision {
    match action.level() {
        PermissionLevel::Green => PolicyDecision::Allow,
        PermissionLevel::Yellow => PolicyDecision::AllowWithNotification(
            format!("Action {} will be performed", action)
        ),
        PermissionLevel::Red => PolicyDecision::RequireApproval(
            format!("Action {} requires approval", action)
        ),
    }
}
```

#### Step 4: LLM Routing
**Kaynak:** `crates/llm-router/src/lib.rs:500-600`
```rust
pub async fn route(&self, request: &LlmRequest) -> RoutingResult {
    // 1. Extract features
    let features = extract_features(request);

    // 2. Determine complexity
    let complexity = features_to_complexity(&features);

    // 3. Select tier
    let tier = match complexity {
        TaskComplexity::Simple => ModelTier::Economy,
        TaskComplexity::Medium => ModelTier::Standard,
        TaskComplexity::Complex => ModelTier::Premium,
    };

    // 4. Check circuit breaker
    let provider = self.select_healthy_provider(tier)?;

    RoutingResult { tier, provider, model: provider.model_for_tier(tier) }
}
```

#### Step 5: Provider Call
**Kaynak:** `crates/gateway/src/providers.rs:200-300`
```rust
impl AnthropicProvider {
    pub async fn complete(&self, request: &LlmRequest) -> Result<LlmResponse> {
        let body = json!({
            "model": self.model,
            "max_tokens": request.max_tokens.unwrap_or(4096),
            "messages": request.messages,
            "system": request.system_prompt,
        });

        let response = self.client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&body)
            .send()
            .await?;

        // Parse response...
    }
}
```

#### Step 6: Cost Recording
**Kaynak:** `crates/cost-ledger/src/lib.rs:150-200`
```rust
pub fn record(&self, entry: &CostEntry) -> Result<()> {
    let conn = self.pool.get()?;
    conn.execute(
        "INSERT INTO cost_entries
         (timestamp, model_name, tier, input_tokens, output_tokens,
          cache_read_tokens, cache_write_tokens, cost_microdollars,
          cache_status, platform, latency_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            entry.timestamp.to_rfc3339(),
            entry.model_name,
            entry.tier,
            entry.input_tokens,
            entry.output_tokens,
            entry.cache_read_tokens,
            entry.cache_write_tokens,
            entry.cost_microdollars,
            entry.cache_status,
            entry.platform,
            entry.latency_ms,
        ],
    )?;
    Ok(())
}
```

#### Step 7: Memory Storage
**Kaynak:** `crates/memory/src/lib.rs:120-160`
```rust
pub fn add_message(&self, entry: &MessageEntry) -> Result<()> {
    let conn = self.pool.get()?;
    conn.execute(
        "INSERT INTO messages
         (id, chat_id, sender_id, role, content, platform, timestamp, token_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            entry.id.0,
            entry.chat_id.0,
            entry.sender_id.0,
            entry.role.as_str(),
            entry.content,
            entry.platform.as_str(),
            entry.timestamp.to_rfc3339(),
            entry.token_count,
        ],
    )?;
    Ok(())
}
```

---

## Flow 2: Vault Unlock → Key Decryption

### Sequence Diagram

```
┌────────┐ ┌───────────┐ ┌─────────────────┐ ┌──────────┐
│  User  │ │  Gateway  │ │ CredentialVault │ │ SQLite   │
└───┬────┘ └─────┬─────┘ └────────┬────────┘ └────┬─────┘
    │            │                │               │
    │ password   │                │               │
    ├───────────►│                │               │
    │            │ unlock(pw)     │               │
    │            ├───────────────►│               │
    │            │                │ load verifier │
    │            │                ├──────────────►│
    │            │                │◄──────────────┤
    │            │                │               │
    │            │                │ Argon2id(pw)  │
    │            │                │ ──────────►   │
    │            │                │               │
    │            │                │ decrypt verify│
    │            │                │ ──────────►   │
    │            │                │               │
    │            │                │ match?        │
    │            │                │ ──────────►   │
    │            │                │               │
    │            │ Ok/Err         │               │
    │            │◄───────────────┤               │
    │            │                │               │
    │            │ load_all_keys  │               │
    │            ├───────────────►│               │
    │            │                │ SELECT * FROM │
    │            │                │ credentials   │
    │            │                ├──────────────►│
    │            │                │◄──────────────┤
    │            │                │               │
    │            │                │ AES-256-GCM   │
    │            │                │ decrypt each  │
    │            │                │               │
    │            │ keys           │               │
    │            │◄───────────────┤               │
    │ ready      │                │               │
    │◄───────────┤                │               │
    │            │                │               │
```

### Kod Referansları

#### Argon2id Key Derivation
**Kaynak:** `crates/credential-vault/src/lib.rs:100-130`
```rust
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let params = argon2::Params::new(
        65536,  // m_cost: 64 MiB memory
        3,      // t_cost: 3 iterations
        4,      // p_cost: 4 parallelism
        Some(32) // output length
    ).expect("valid params");

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("hash success");
    key
}
```

#### AES-256-GCM Decryption
**Kaynak:** `crates/credential-vault/src/lib.rs:180-220`
```rust
fn decrypt_value(&self, encrypted: &[u8]) -> Result<SensitiveString> {
    if encrypted.len() < NONCE_SIZE + 16 {
        return Err(VaultError::InvalidData);
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = self.cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::DecryptionFailed)?;

    let string = String::from_utf8(plaintext)
        .map_err(|_| VaultError::InvalidUtf8)?;

    Ok(SensitiveString(string))
}
```

#### Password Verification
**Kaynak:** `crates/credential-vault/src/lib.rs:250-280`
```rust
pub fn unlock(&mut self, password: &str) -> Result<()> {
    // 1. Load salt and encrypted verifier from DB
    let (salt, encrypted_verifier) = self.load_verifier()?;

    // 2. Derive key from password
    let key = derive_key(password, &salt);
    self.cipher = Some(Aes256Gcm::new(&key.into()));

    // 3. Try to decrypt verifier
    let decrypted = self.decrypt_value(&encrypted_verifier)?;

    // 4. Check verifier value
    if decrypted.0 != VERIFIER_TOKEN {
        self.cipher = None;
        return Err(VaultError::WrongPassword);
    }

    self.unlocked = true;
    Ok(())
}
```

---

## Flow 3: Circuit Breaker → Provider Fallback

### State Machine

```
                    ┌────────────────┐
                    │     CLOSED     │◄─────────────────────────┐
                    │  (normal op)   │                          │
                    └───────┬────────┘                          │
                            │                                   │
                            │ failure_count >= 5                │
                            ▼                                   │
                    ┌────────────────┐                          │
                    │      OPEN      │                          │
                    │ (reject calls) │                          │
                    └───────┬────────┘                          │
                            │                                   │
                            │ 60 seconds elapsed                │
                            ▼                                   │
                    ┌────────────────┐                          │
                    │   HALF-OPEN    │──── success ────────────►│
                    │  (probe call)  │                          │
                    └───────┬────────┘                          │
                            │                                   │
                            │ failure                           │
                            ▼                                   │
                    ┌────────────────┐                          │
                    │      OPEN      │──── timeout ─────────────┘
                    │   (reset)      │
                    └────────────────┘
```

### Sequence Diagram

```
┌────────┐ ┌───────────┐ ┌───────────────┐ ┌───────────┐ ┌───────────┐
│LLMRouter│ │CircuitBrkr│ │AnthropicProv │ │ OpenAIProv│ │GeminiProv │
└───┬────┘ └─────┬─────┘ └──────┬───────┘ └─────┬─────┘ └─────┬─────┘
    │            │              │               │             │
    │ can_call?  │              │               │             │
    ├───────────►│              │               │             │
    │            │              │               │             │
    │ OPEN (5 failures)         │               │             │
    │◄───────────┤              │               │             │
    │            │              │               │             │
    │            │──────────────┼───── SKIP ────┼─────────────│
    │            │              │               │             │
    │ try_next   │              │               │             │
    ├───────────►│ can_call?    │               │             │
    │            ├──────────────┼──────────────►│             │
    │            │              │               │             │
    │            │ CLOSED       │               │             │
    │            │◄─────────────┼───────────────┤             │
    │            │              │               │             │
    │ call       │              │               │             │
    ├────────────┼──────────────┼──────────────►│             │
    │            │              │               │             │
    │ response   │              │               │             │
    │◄───────────┼──────────────┼───────────────┤             │
    │            │              │               │             │
    │ record_success            │               │             │
    ├───────────►│              │               │             │
    │            │              │               │             │
```

### Kod Referansları

#### CircuitBreaker Implementation
**Kaynak:** `crates/gateway/src/circuit_breaker.rs:40-100`
```rust
impl CircuitBreaker {
    pub fn can_call(&self) -> bool {
        let state = self.state.read().unwrap();
        match *state {
            State::Closed => true,
            State::Open => {
                // Check if timeout elapsed
                let elapsed = Instant::now() - *self.last_failure.read().unwrap();
                if elapsed > Duration::from_secs(TIMEOUT_SECONDS) {
                    drop(state);
                    *self.state.write().unwrap() = State::HalfOpen;
                    true
                } else {
                    false
                }
            }
            State::HalfOpen => true,
        }
    }

    pub fn record_failure(&self) {
        let mut failures = self.failure_count.write().unwrap();
        *failures += 1;
        *self.last_failure.write().unwrap() = Instant::now();

        if *failures >= FAILURE_THRESHOLD {
            *self.state.write().unwrap() = State::Open;
        }
    }

    pub fn record_success(&self) {
        let state = *self.state.read().unwrap();
        if state == State::HalfOpen {
            let mut successes = self.success_count.write().unwrap();
            *successes += 1;
            if *successes >= SUCCESS_THRESHOLD {
                *self.state.write().unwrap() = State::Closed;
                *self.failure_count.write().unwrap() = 0;
                *successes = 0;
            }
        }
    }
}
```

#### MultiProviderRouter Fallback
**Kaynak:** `crates/gateway/src/providers.rs:400-480`
```rust
impl MultiProviderRouter {
    pub async fn complete(&self, request: &LlmRequest) -> Result<LlmResponse> {
        let providers = self.get_provider_order();

        for provider in providers {
            // Check circuit breaker
            if !self.circuit_breakers[&provider.id()].can_call() {
                tracing::warn!("Circuit open for {}, skipping", provider.id());
                continue;
            }

            match provider.complete(request).await {
                Ok(response) => {
                    self.circuit_breakers[&provider.id()].record_success();
                    return Ok(response);
                }
                Err(e) => {
                    tracing::error!("Provider {} failed: {}", provider.id(), e);
                    self.circuit_breakers[&provider.id()].record_failure();
                    // Continue to next provider
                }
            }
        }

        Err(anyhow!("All providers failed"))
    }
}
```

---

## Flow 4: Skill Execution (Tool Use)

### Sequence Diagram

```
┌────────┐ ┌───────────┐ ┌────────────┐ ┌──────────┐ ┌───────────┐
│  LLM   │ │  Gateway  │ │PolicyEngine│ │  Skill   │ │  AuditLog │
└───┬────┘ └─────┬─────┘ └─────┬──────┘ └────┬─────┘ └─────┬─────┘
    │            │             │             │             │
    │ tool_call  │             │             │             │
    ├───────────►│             │             │             │
    │            │             │             │             │
    │            │ check_action│             │             │
    │            ├────────────►│             │             │
    │            │             │             │             │
    │            │ decision    │             │             │
    │            │◄────────────┤             │             │
    │            │             │             │             │
    │            │ [if Red: RequireApproval] │             │
    │            │ ─────► ask user ──────►   │             │
    │            │             │             │             │
    │            │ [if allowed]│             │             │
    │            │ execute     │             │             │
    │            ├─────────────┼────────────►│             │
    │            │             │             │             │
    │            │             │             │ validate_url│
    │            │             │             │ (SSRF check)│
    │            │             │             │             │
    │            │ result      │             │             │
    │            │◄────────────┼─────────────┤             │
    │            │             │             │             │
    │            │ record      │             │             │
    │            ├─────────────┼─────────────┼────────────►│
    │            │             │             │             │
    │ tool_result│             │             │             │
    │◄───────────┤             │             │             │
    │            │             │             │             │
```

### Kod Referansları

#### Skill Permission Check
**Kaynak:** `crates/policy-engine/src/lib.rs:120-150`
```rust
pub fn action_for_skill(skill_id: &str) -> ActionType {
    match skill_id {
        "web_search" => ActionType::SearchWeb,
        "file_reader" => ActionType::ReadFile,
        "email_sender" => ActionType::SendEmail,
        "shell_executor" => ActionType::RunShellCommand,
        _ => ActionType::Unknown,
    }
}
```

#### SSRF Protection
**Kaynak:** `crates/skills/src/lib.rs:100-160`
```rust
pub fn validate_url(url: &str) -> Result<(), SkillError> {
    let parsed = Url::parse(url)?;

    // Block file:// scheme
    if parsed.scheme() == "file" {
        return Err(SkillError::Ssrf("file:// URLs blocked"));
    }

    // Block localhost
    if let Some(host) = parsed.host_str() {
        if host == "localhost" || host == "127.0.0.1" {
            return Err(SkillError::Ssrf("localhost blocked"));
        }

        // Block cloud metadata endpoints
        if host == "169.254.169.254" {
            return Err(SkillError::Ssrf("metadata endpoint blocked"));
        }

        // Check for private IPs
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_private_ip(&ip) {
                return Err(SkillError::Ssrf("private IP blocked"));
            }
        }
    }

    Ok(())
}
```

#### Shell Executor Safety
**Kaynak:** `crates/skills/src/shell_executor.rs:80-130`
```rust
const BLOCKED_PATTERNS: &[&str] = &[
    "rm -rf", "rm -fr", "mkfs", "dd if=",
    "sudo", "su -", "passwd", "/etc/shadow",
    "chmod 777", "curl | sh", "wget | sh",
];

const BLOCKED_CHAINING: &[&str] = &[
    "&&", "||", ";", "|", "`", "$(",
];

pub fn validate_command(&self, cmd: &str) -> Result<()> {
    // Check blocked patterns
    for pattern in BLOCKED_PATTERNS {
        if cmd.contains(pattern) {
            return Err(SkillError::BlockedCommand(pattern.to_string()));
        }
    }

    // Check shell chaining
    for chain in BLOCKED_CHAINING {
        if cmd.contains(chain) {
            return Err(SkillError::ChainBlocked(chain.to_string()));
        }
    }

    // Check allowlist
    if !self.allowlist.iter().any(|a| cmd.starts_with(a)) {
        return Err(SkillError::NotAllowed);
    }

    Ok(())
}
```

---

## Flow 5: Graceful Shutdown

### Sequence Diagram

```
┌──────────┐ ┌───────────────┐ ┌───────────┐ ┌──────────┐ ┌──────────┐
│  SIGTERM │ │ShutdownHandler│ │ TelegramBr│ │ MemoryStr│ │ AuditLog │
└────┬─────┘ └───────┬───────┘ └─────┬─────┘ └────┬─────┘ └────┬─────┘
     │               │               │            │            │
     │ signal        │               │            │            │
     ├──────────────►│               │            │            │
     │               │               │            │            │
     │               │ broadcast     │            │            │
     │               │ shutdown      │            │            │
     │               ├──────────────►│            │            │
     │               │               │            │            │
     │               │               │ stop poll  │            │
     │               │               │ ─────────► │            │
     │               │               │            │            │
     │               │ wait_tasks    │            │            │
     │               │ ────────────► │            │            │
     │               │               │            │            │
     │               │ cleanup       │            │            │
     │               ├───────────────┼───────────►│            │
     │               │               │            │            │
     │               │               │            │ flush      │
     │               │               │            │ ──────────►│
     │               │               │            │            │
     │               │ save timestamp│            │            │
     │               │ ─────────────►│            │            │
     │               │               │            │            │
     │               │ exit(0)       │            │            │
     │               │               │            │            │
```

### Kod Referansları

#### Signal Handler
**Kaynak:** `crates/gateway/src/shutdown.rs:30-60`
```rust
pub struct ShutdownSignal {
    sender: broadcast::Sender<()>,
}

impl ShutdownSignal {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1);
        Self { sender }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.sender.subscribe()
    }

    pub async fn listen(&self) {
        let ctrl_c = tokio::signal::ctrl_c();

        #[cfg(unix)]
        let mut sigterm = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate()
        ).expect("SIGTERM handler");

        tokio::select! {
            _ = ctrl_c => {
                tracing::info!("Received SIGINT");
            }
            #[cfg(unix)]
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM");
            }
        }

        let _ = self.sender.send(());
    }
}
```

#### Cleanup Function
**Kaynak:** `crates/gateway/src/shutdown.rs:80-110`
```rust
pub async fn cleanup(ctx: &Context) -> Result<()> {
    tracing::info!("Starting graceful shutdown...");

    // 1. Stop accepting new requests
    ctx.shutdown.trigger();

    // 2. Wait for in-flight requests (max 30s)
    tokio::time::timeout(
        Duration::from_secs(30),
        ctx.wait_for_tasks()
    ).await.ok();

    // 3. Flush pending writes
    ctx.memory.flush()?;
    ctx.audit.flush()?;
    ctx.cost.flush()?;

    // 4. Save shutdown timestamp
    let timestamp = chrono::Utc::now().to_rfc3339();
    std::fs::write(
        ctx.data_dir.join("last_shutdown"),
        timestamp
    )?;

    tracing::info!("Shutdown complete");
    Ok(())
}
```

---

**Sonraki Doküman:** → `TESTS_AND_CI.md`
