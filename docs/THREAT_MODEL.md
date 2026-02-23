# SafeAgent Threat Model

This document describes what SafeAgent protects against and what falls outside its scope. Understanding these boundaries helps users make informed security decisions.

---

## Protected Threats

### 1. Credential Theft from Disk
**Attack:** An attacker gains read access to SafeAgent's data directory.

**Protection:** All API keys and tokens are stored in `vault.db`, encrypted with AES-256-GCM. The encryption key is derived from the user's master password via Argon2id (memory-hard KDF), making brute-force attacks computationally expensive.

**Residual risk:** If the attacker also knows the vault password, encryption provides no protection.

### 2. Prompt Injection
**Attack:** Malicious content in user input or external data attempts to override system instructions, extract secrets, or manipulate SafeAgent's behavior.

**Protection:**
- `prompt-guard` crate detects injection patterns (instruction override, role spoofing, leet-speak bypass, newline injection, invisible characters).
- Risk scoring blocks high-risk inputs before they reach the LLM.
- System prompt instructs the model to treat untrusted content as data, not instructions.
- Nonce-based content wrapping prevents marker spoofing.

**Residual risk:** Novel injection techniques not covered by current patterns may bypass detection.

### 3. API Key Exposure in Logs
**Attack:** API keys or tokens accidentally appear in log output, terminal display, or audit records.

**Protection:**
- `SensitiveString` type redacts values in Debug output (`[REDACTED]`).
- Audit log applies regex-based secret redaction before writing to disk.
- Patterns covered: Anthropic keys (`sk-ant-*`), Voyage keys (`pa-*`), Telegram tokens, generic `password=` / `token=` patterns.

**Residual risk:** Custom API key formats not matching known patterns may not be redacted.

### 4. Accidental Overspending
**Attack:** Runaway loops, misconfigured routing, or unexpected usage leads to large API bills.

**Protection:**
- Daily and monthly hard spending caps (configurable in policy engine).
- Pre-request budget check blocks API calls when limits are reached.
- Per-message cost display with session and daily totals.
- Cost ledger tracks all spending in local SQLite.
- `safeagent stats` provides cost visibility.

**Residual risk:** Cost is recorded after API response; a single expensive request may slightly exceed the limit before the cap takes effect.

### 5. Unauthorized Platform Access
**Attack:** Unauthorized users send messages to the SafeAgent Telegram bot.

**Protection:**
- Telegram bridge uses an allowlist of chat IDs — only pre-configured chats receive responses.
- Bot token stored encrypted in vault.

**Residual risk:** If the chat ID allowlist is misconfigured (e.g., group chat ID), unintended users in that group may interact with the bot.

---

## Out of Scope

### 1. Memory-Resident Attacks
**Threat:** An attacker with access to the running process memory reads decrypted keys.

**Why out of scope:** Once the vault is unlocked, decrypted keys exist in process memory. Protecting against memory-resident attacks requires OS-level memory protection (mlock, guard pages) which is not currently implemented. This is a limitation shared by most application-level encryption.

**Mitigation:** Run SafeAgent on a trusted machine. Lock the vault when not in use.

### 2. Root/Admin-Level Compromise
**Threat:** An attacker with root access to the host machine.

**Why out of scope:** A root attacker can read process memory, attach debuggers, modify binaries, and bypass any application-level protection. No application can defend against a fully compromised OS.

**Mitigation:** Use full-disk encryption. Keep the OS patched. Restrict root access.

### 3. Physical Access
**Threat:** An attacker with physical access to the machine.

**Why out of scope:** Physical access enables disk extraction, cold-boot attacks, and hardware keyloggers — all outside application control.

**Mitigation:** Full-disk encryption (FileVault / LUKS). Strong device password. Lock screen when away.

### 4. Compromised LLM Provider
**Threat:** Anthropic or Voyage AI's servers are compromised or behave maliciously.

**Why out of scope:** SafeAgent sends prompts and conversation history to these APIs by design. A compromised provider could log, modify, or leak this data.

**Mitigation:** Review Anthropic's data retention policy. Avoid sending highly sensitive information in prompts. SafeAgent does not send vault passwords or other credentials to APIs.

### 5. Supply Chain Attacks on Dependencies
**Threat:** A malicious update to a Rust crate dependency.

**Why out of scope:** SafeAgent depends on ~100+ transitive crates. Verifying each update is infeasible at the application level.

**Mitigation:** `Cargo.lock` pins exact dependency versions. `cargo audit` checks for known vulnerabilities. Dependency updates are reviewed before merging.

### 6. Network-Level Attacks (MITM)
**Threat:** Man-in-the-middle intercepts API calls.

**Why partially mitigated:** All API calls use HTTPS (TLS) via `reqwest` with `rustls-tls`. Certificate validation is enabled by default. However, SafeAgent does not implement certificate pinning.

**Mitigation:** Use trusted networks. SafeAgent's TLS configuration follows standard best practices.

---

## Data Flow Summary

| Data | Stored Where | Encrypted | Sent To |
|------|-------------|-----------|---------|
| API keys | vault.db | AES-256-GCM | Anthropic (in HTTP header), Voyage AI (in HTTP header) |
| Vault password | Never stored | N/A | Never sent anywhere |
| Conversation history | memory.db | No (plaintext SQLite) | Anthropic API (as context) |
| User facts | memory.db | No (plaintext SQLite) | Anthropic API (in system prompt) |
| Cost records | cost_ledger.db | No | Never sent anywhere |
| Audit log | audit.db | No | Never sent anywhere |
| Telegram chat ID | vault.db | AES-256-GCM | Telegram API |

---

## Recommendations for High-Security Users

1. **Use full-disk encryption** (FileVault on macOS, LUKS on Linux).
2. **Set file permissions:** `chmod 600 vault.db memory.db audit.db cost_ledger.db`
3. **Use a strong vault password** (12+ characters, not reused elsewhere).
4. **Run on a single-user machine** — SharedSystems expose memory.db to other users.
5. **Review API provider policies** before sending sensitive data.
6. **Set conservative spending limits** to catch unexpected behavior early.
7. **Periodically run** `safeagent doctor` to check for permission issues.
