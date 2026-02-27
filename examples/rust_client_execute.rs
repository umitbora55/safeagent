use safeagent_sdk_rust::{SafeAgentClientConfig, SafeAgentError};

fn main() -> Result<(), SafeAgentError> {
    let client = SafeAgentClientConfig::new("https://control-plane.example.local")
        .token("test-token")
        .build()?;

    let token = "mock-token";
    let runtime = tokio::runtime::Runtime::new().map_err(|_| SafeAgentError::Config("runtime".into()))?;
    runtime.block_on(async {
        let response = client
            .execute("tenant-1", "echo", "hello", "demo-req-1")
            .await?;
        println!("ok={} output={}", response.ok, response.output);
        Ok::<(), SafeAgentError>(())
    })?;
    let _ = token;
    Ok(())
}
