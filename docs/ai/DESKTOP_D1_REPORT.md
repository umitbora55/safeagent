# D1 — Desktop App MVP Report

## Screen Layouts

`desktop-ui/index.html` currently renders a minimal production-ready control shell:

- Home panel with **Start** / **Stop** / **Refresh** actions
- Service status panel (desired state, control-plane ready, worker ready, process metadata)
- Last 20 event log panel
- Marketplace panel (local package list + install action)
- Approval queue panel
- Approval popup modal (approve / deny)

## Exposed Commands (Tauri IPC)

- `start_services()`
- `stop_services()`
- `get_status()`
- `get_recent_events(lines?)`
- `poll_pending_approvals()`
- `approve(approval_id)`
- `deny(approval_id)`
- `list_marketplace_skills()`
- `install_marketplace_skill(package_path)`
- `get_version()`, `get_health()`, `ensure_pki_command()`

## Single-process Startup Strategy

Desktop app uses `safeagent-desktop` backend wrapper to orchestrate both binaries:

- Auto-created directories:
  - `~/.safeagent-desktop/pki`
  - `~/.safeagent-desktop/logs`
  - `~/.safeagent-desktop/secrets`
  - `~/.safeagent-desktop/marketplace`
  - `~/.safeagent-desktop/installed`
- Dev PKI is generated lazily (`CA`, `control-plane` cert/key, `worker` cert/key) under `.safeagent-desktop/pki`.
- `start_services()` resolves local binary paths and launches:
  - `safeagent-control-plane`
  - `safeagent-worker`
- Reads service health via `127.0.0.1:8443` and `127.0.0.1:8280`.
- Periodic `get_status()` in UI gives lightweight auto-monitoring and simple restart attempts when desired state is running.

## Approval Flow

- UI polls `/approval/pending` via `poll_pending_approvals()`.
- If pending request exists:
  - popup opens automatically
  - operator can `approve` or `deny` with decision logged into event stream.
- Approval decision is sent to control-plane `/approval/decide` using local dev client cert and CA.

## Marketplace Integration

- UI reads package directories from `~/.safeagent-desktop/marketplace`.
- `list_marketplace_skills` checks required package files and runs:
  - `scan_skill(...)`
  - `verify_skill(...)` against local verified publisher list
- Unsafe packages are marked `blocked`, installable packages marked `installable`.
- `install_marketplace_skill` copies verified package into `~/.safeagent-desktop/installed`.

## Known Limitations

- Backend is intentionally minimal MVP:
  - approval polling interval is fixed and lightweight
  - logs shown are process/event logs only (no pretty graphs)
  - install path currently expects unpacked local package directory
- No native installer (`.msi`/`.dmg`/`.deb`) is introduced in this phase.
- App currently assumes both service binaries are available or configured via environment variables.

## Verification Commands

```bash
just desktop-check
```

and

```bash
just desktop-check-log
```

## desktop-check PASS Excerpt

```text
running 3 tests
test tests::pki_function_is_idempotent ... ok
test tests::read_tail_limits_lines ... ok
test tests::copy_dir_recursive_works_for_nested ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

From `logs/desktop_check.log` this confirms:
- `safeagent-desktop` build succeeded
- all desktop unit tests passed

## Desktop UI Screenshot (text description)

- A single-window layout with top control toolbar, green/red status dot, and start/stop controls.
- Left: service status + readiness, middle: live event list, right: marketplace table, bottom: approval queue.
- A centered modal appears on pending approval with “Allow” and “Deny” buttons and request metadata.
