//! OS keychain integration for vault password storage.
//! macOS: Security framework (Keychain)
//! Linux: Secret Service API (GNOME Keyring, KWallet)

const SERVICE_NAME: &str = "safeagent";
const ACCOUNT_NAME: &str = "vault_password";

/// Store vault password in OS keychain.
pub fn store_password(password: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let status = Command::new("security")
            .args(["add-generic-password", "-a", ACCOUNT_NAME, "-s", SERVICE_NAME, "-w", password, "-U"])
            .output()
            .map_err(|e| format!("Failed to run security command: {}", e))?;
        if !status.status.success() {
            return Err(format!("Keychain store failed: {}", String::from_utf8_lossy(&status.stderr)));
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let status = Command::new("secret-tool")
            .args(["store", "--label", "SafeAgent Vault Password", "service", SERVICE_NAME, "account", ACCOUNT_NAME])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(password.as_bytes())?;
                }
                child.wait()
            })
            .map_err(|e| format!("Failed to run secret-tool: {}", e))?;
        if !status.success() {
            return Err("secret-tool store failed. Install gnome-keyring or kwallet.".into());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = password;
        Err("OS keychain not supported on this platform".into())
    }
}

/// Retrieve vault password from OS keychain.
pub fn retrieve_password() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let output = Command::new("security")
            .args(["find-generic-password", "-a", ACCOUNT_NAME, "-s", SERVICE_NAME, "-w"])
            .output()
            .map_err(|e| format!("Failed to run security command: {}", e))?;
        if !output.status.success() {
            return Err("Password not found in Keychain. Run `safeagent init` to set up.".into());
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let output = Command::new("secret-tool")
            .args(["lookup", "service", SERVICE_NAME, "account", ACCOUNT_NAME])
            .output()
            .map_err(|e| format!("Failed to run secret-tool: {}", e))?;
        if !output.status.success() {
            return Err("Password not found in Secret Service. Run `safeagent init` to set up.".into());
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("OS keychain not supported on this platform".into())
    }
}

/// Delete vault password from OS keychain.
pub fn delete_password() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let status = Command::new("security")
            .args(["delete-generic-password", "-a", ACCOUNT_NAME, "-s", SERVICE_NAME])
            .output()
            .map_err(|e| format!("Failed to run security command: {}", e))?;
        if !status.status.success() {
            return Err("Password not found in Keychain".into());
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let status = Command::new("secret-tool")
            .args(["clear", "service", SERVICE_NAME, "account", ACCOUNT_NAME])
            .output()
            .map_err(|e| format!("Failed to run secret-tool: {}", e))?;
        if !status.success() {
            return Err("Failed to clear from Secret Service".into());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("OS keychain not supported on this platform".into())
    }
}

/// Check if OS keychain is available on this system.
pub fn is_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("security").arg("help").output().is_ok()
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("secret-tool").arg("--version").output().is_ok()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        false
    }
}
