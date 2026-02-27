# SafeAgent Feature Matrix

| Feature | Community | Pro | Enterprise | Coming Next |
|---|---:|---:|---:|---|
| Local install script (`install_macos.sh`, `install_linux.sh`, `install_windows.ps1`) | ✅ | ✅ | ✅ | - |
| Demo/runbook (`demo_local.sh`) | ✅ | ✅ | ✅ | - |
| mTLS control-plane/worker | ✅ | ✅ | ✅ | - |
| Basic policy checks + prompt safety | ✅ | ✅ | ✅ | - |
| Sandbox + egress isolation | ✅ | ✅ | ✅ | - |
| Approval flow + red-action audit trail | ✅ | ✅ | ✅ | - |
| Human-in-the-loop workflows | ✅ | ✅ | ✅ | - |
| Adversarial test gates (jailbreak + poison) | ⚪️ Manual/optional | ✅ (default in CI) | ✅ | - |
| Exploit replay + regression checks | ⚪️ Manual/optional | ✅ | ✅ | - |
| Vault integration | ❌ | ⚪️ Optional | ✅ | - |
| KMS/Cloud key abstraction | ❌ | ⚪️ Optional | ✅ | - |
| Signed marketplace + scan pipeline | ⚪️ Optional | ✅ (self-hosted) | ✅ (policy enforced) | ✅ policy federation |
| Rate limiting and queue backpressure | ⚪️ Optional | ✅ | ✅ | - |
| Tenant-aware cost controls | ⚪️ Optional | ✅ | ✅ | - |
| Audit export with integrity metadata | ⚪️ Basic | ✅ | ✅ | ✅ SIEM schema templates |
| SLA / support commitments | ❌ | ❌ | ✅ | - |
| Procurement bundle (security answers + compliance) | ❌ | ❌ | ✅ | - |
| Incident response package | ❌ | ❌ | ✅ | - |
| Dedicated enterprise onboarding | ❌ | ❌ | ✅ | - |
| Priority CVE/security advisory response | ❌ | ❌ | ✅ | ✅ quarterly advisory |

Legend: ✅ included; ⚪️ included only via config / optional add-on; ❌ not in edition.
