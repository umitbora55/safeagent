# PHASE 2.1.2 — Linux CI Proof (Sandbox)

## Workflow
- `.github/workflows/platform-v2.yml`
- Workflow URL: `https://github.com/umitbora55/safeagent/actions/workflows/platform-v2.yml`
- Workflow run link: `https://github.com/umitbora55/safeagent/actions/runs/<run_id>` (CI run sonrası güncellenecek)

## Çalıştırılan Komutlar
- `just verify-v2`
- `just sandbox-tests-v2`
- CI’de her iki komut da ayrı adımda ve ayrı log dosyası ile kaydedildi.

## Linux Sanal Ortam Kanıtı (beklenen çıkış)
`logs/sandbox_tests_v2_linux.log` içinde:

```text
running 5 tests
test test_no_new_privs_set ... ok
test test_capabilities_dropped ... ok
test test_rlimit_enforced ... ok
test test_seccomp_blocks_disallowed_syscall ... ok
test test_skill_exec_under_sandbox ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in ...
```

`logs/verify_v2_phase_2_1_linux.log` içinde:

```text
... just sandbox-tests-v2 ...
... test result: ok. 5 passed; 0 failed; ... finished in ...
...
verify-v2 ...
```

## Not
Bu dosya Linux runner’da yeni workflow çalıştırıldıktan sonra gerçek log özetleri ile güncellenecektir.
