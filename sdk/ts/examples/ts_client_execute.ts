import { SafeAgentClient } from "../src/index";

async function main() {
  const client = new SafeAgentClient({
    baseUrl: "https://control-plane.example.local",
    timeoutMs: 3000,
  });

  const token = "test-token-opaque";
  const response = await client.execute("tenant-1", "echo", "ping", "req-42", token);
  console.log({
    ok: response.ok,
    output: response.output,
    error: response.error,
  });
}

void main();
