# Troubleshooting

Quick reference for common SafeAgent issues. Run `safeagent doctor` first — it catches most problems automatically.

---

## Error Codes

### SA-E001: Vault password too short

**Symptom:** `safeagent init` rejects your password.

**Fix:** Use a password with at least 4 characters. Longer is better — this password protects all your API keys with AES-256-GCM encryption.

---

### SA-E002: Wrong vault password

**Symptom:** `safeagent run` or `safeagent init` says "Wrong vault password."

**Fix:**
1. Try your password again (check caps lock).
2. If forgotten, delete the vault and re-run init:
   ```bash
   # Find your data directory
   safeagent doctor  # shows path at [1/7]

   # Delete vault (you'll need to re-enter API keys)
   rm "<data-dir>/vault.db"
   safeagent init
   ```

---

### SA-E003: API key validation failed

**Symptom:** `safeagent init` reports API key validation failure.

**Cause & Fix by status code:**

| Status | Meaning | Fix |
|--------|---------|-----|
| 401 | Invalid key | Check key at [console.anthropic.com](https://console.anthropic.com/settings/keys) |
| 429 | Rate limited | Key is valid. Wait a moment and try again. |
| 529 | Overloaded | Key is valid. Anthropic servers are busy — try later. |
| 503 | Unavailable | Key is valid. Service temporarily down. |
| Network error | Can't reach API | Check internet, DNS, firewall, proxy. |

---

### SA-E004: Telegram token validation failed

**Symptom:** `safeagent init` says Telegram token is invalid.

**Fix:**
1. Open Telegram and message [@BotFather](https://t.me/BotFather).
2. Send `/mybots` to see your bots.
3. Select your bot → API Token → copy the full token.
4. Run `safeagent init` again and paste the new token.

---

### SA-E005: Could not reach Telegram API

**Symptom:** Network error when validating Telegram token.

**Fix:**
1. Check internet connection.
2. Try: `curl -s https://api.telegram.org | head -1`
3. If blocked, check if Telegram is restricted in your network/country. Consider a VPN.

---

### SA-E006: Empty key

**Symptom:** `safeagent init` says a key "cannot be empty."

**Fix:** Run `safeagent init` again and provide the required value. Don't press Enter on an empty prompt.

---

## Common Issues

### Vault password forgotten

You cannot recover a forgotten vault password. The vault uses Argon2id + AES-256-GCM — there is no backdoor by design.

```bash
# Delete vault and re-initialize
rm "<data-dir>/vault.db"
safeagent init
```

You will need to re-enter all API keys.

---

### Telegram bot not responding

1. **Check token:** Run `safeagent doctor` — look for `telegram_token` status.
2. **Check chat ID:** Make sure `telegram_chat_id` matches your Telegram user/group ID.
3. **Check network:** `safeagent doctor` tests Telegram API connectivity.
4. **Check bot status:** Send `/start` to your bot on Telegram.
5. **Restart:** Stop SafeAgent (Ctrl+C) and run `safeagent run` again.

---

### Embedding routing unavailable

**Symptom:** `🧠 Embedding: unavailable` in CLI output.

**Cause:** Voyage AI key not configured.

**Fix:**
```bash
safeagent init
# At Step 4/4, add your Voyage AI key
```

Without embedding routing, SafeAgent uses rule-based routing. This still works but may be less accurate for borderline requests.

---

### Cache showing "below_threshold"

**Symptom:** Dashboard shows `BELOW_THRESHOLD` status.

**Cause:** Your request is shorter than the provider's minimum cache token requirement (1024 for Sonnet, 4096 for Haiku/Opus).

**Not a problem.** Short requests are cheap anyway. Cache benefits increase with longer conversations.

---

### Cache showing "miss"

**Symptom:** Dashboard shows `MISS` status even after several messages.

**Possible causes:**
1. **First message in session** — cache needs a write before it can hit.
2. **Model switched** — different models have separate caches.
3. **Context changed** — system prompt or early history changed.

Cache hits typically start from the 2nd-3rd message in a conversation.

---

### High API costs

1. Switch to economy mode:
   ```
   /mode economy
   ```
   Or set in config:
   ```toml
   [router]
   mode = "economy"
   ```

2. Set spending limits:
   ```toml
   [policy]
   daily_limit_usd = 5.0
   monthly_limit_usd = 30.0
   ```

3. Check `/stats` in CLI to monitor usage.

---

### Build errors

```bash
# Clean and rebuild
cargo clean
cargo build --workspace

# If dependency issues
cargo update
cargo build --workspace
```

Minimum requirements: Rust 1.75+, ~500MB disk space for build.

---

### File permission warnings

**Symptom:** `safeagent doctor` warns about world-readable files.

**Fix:**
```bash
chmod 600 "<data-dir>/vault.db"
chmod 600 "<data-dir>/memory.db"
```

This prevents other users on shared systems from reading your encrypted vault and conversation history.

---

## Data Directory Location

| Platform | Path |
|----------|------|
| macOS | `~/Library/Application Support/dev.safeagent.SafeAgent/` |
| Linux | `~/.local/share/SafeAgent/` |
| Fallback | `./.safeagent/` |

---

## Getting Help

- **GitHub Issues:** [github.com/umitbora55/safeagent/issues](https://github.com/umitbora55/safeagent/issues)
- **Security issues:** See [SECURITY.md](../SECURITY.md)
