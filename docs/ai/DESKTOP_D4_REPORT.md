# DESKTOP D4 — One-Click UX + Onboarding Wizard + Tray/Menu Bar

## What changed

- Added a zero-config first-run wizard (`desktop-ui/index.html`):
  - Step 1: “SafeAgent’e Hoş Geldiniz”
  - Step 2: required 4 toggles + onboarding finish
  - Completed state is persisted at `~/.safeagent-desktop/onboarding_state.json`.
- Wired tray-style controls and controls section into the app shell:
  - Open app
  - Start
  - Stop
  - Generate support bundle
  - Quit
- Introduced human-readable event feed for operators in UI:
  - `policy denied` → “Güvenlik nedeniyle engellendi”
  - `approval pending` → “Onay bekliyor”
  - `egress blocked` → “İnternet erişimi engellendi (allowlist dışı)”
  - `skill install blocked` → “Güvenlik taraması başarısız”
- Added approval modal copy and flow:
  - fixed Turkish warning text
  - shows “İşlem”, “Kaynak”
  - 30-second timeout auto-deny
- Graceful stop UX:
  - Stop button label becomes “Kapanıyor…” during shutdown
  - stop path calls async stop routine and refreshes status.

## New command + checks

- `desktop/src/main.rs`:
  - new onboarding state model/commands:
    - `get_onboarding_state`
    - `advance_onboarding`
    - `complete_onboarding_flow`
    - `reset_onboarding_flow`
  - new command: `get_tray_menu`
  - new command: `get_human_recent_events`
  - human event mapping helper: `human_readable_event`
- `desktop-ui/index.html`:
  - onboarding overlay and step handling
  - approval modal with countdown and deny/approve controls
  - tray control buttons and menu label rendering
- `Justfile`:
  - added `desktop-ux-check`
  - added `desktop-ux-check` to `verify-v2`

## Screens

- `onboardingWizard` overlay (2 step max)
- Home dashboard (status, settings, events, marketplace, approval queue)
- Approval modal (İzin Ver / Engelle)
- Manual package install card

## Tray/menu list

- `Open app`
- `Start`
- `Stop`
- `Generate support bundle`
- `Quit`

## Event mapping table

| Raw event fragment | Human-readable event |
| --- | --- |
| `policy denied` | Güvenlik nedeniyle engellendi |
| `approval pending` | Onay bekliyor |
| `egress blocked` | İnternet erişimi engellendi (allowlist dışı) |
| `skill install blocked` | Güvenlik taraması başarısız |

## verify-v2 / desktop-ux-check PASS excerpt

`logs/desktop_ux_check.log`
```text
running 1 test
test tests::onboarding_state_machine ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out
running 1 test
test tests::event_human_mapping_is_stable ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out
running 1 test
test tests::tray_menu_items_exist ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out
```
