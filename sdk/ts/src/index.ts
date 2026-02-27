export type RetryPolicy = {
  maxRetries: number;
  baseDelayMs: number;
};

export type SafeAgentConfig = {
  baseUrl: string;
  timeoutMs?: number;
  token?: string;
  retries?: Partial<RetryPolicy>;
};

export type WorkerRegisterRequest = {
  addr: string;
  version: string;
};

export type WorkerRegisterResponse = {
  node_id: string;
  registered_at: number;
  worker_version: string;
};

export type IssueTokenRequest = {
  subject: string;
  scopes: string[];
  ttl_secs: number;
};

export type IssueTokenResponse = {
  token: string;
};

export type ExecuteRequest = {
  token: string;
  tenant_id: string;
  skill_id: string;
  input: string;
  request_id: string;
};

export type ExecuteResponse = {
  ok: boolean;
  output: string;
  error: string | null;
  audit_id: string | null;
};

export type ApprovalDecisionRequest = {
  approval_id: string;
  decision: "approved" | "denied";
  decided_by: string;
  reason?: string;
};

export type ApprovalDecisionResponse = {
  status: string;
};

export type ApprovalRequest = {
  approval_id: string;
  request_id: string;
  node_id: string;
  skill_id: string;
  input_summary: string;
  reason: string;
  created_at: number;
  expires_at: number;
};

export type Jwks = {
  keys: Array<{
    kty: string;
    crv: string;
    x: string;
    kid: string;
    alg: string;
    use: string;
  }>;
};

type HttpError = Error & { status?: number };

export class SafeAgentClient {
  private readonly baseUrl: string;
  private readonly token?: string;
  private readonly timeoutMs: number;
  private readonly retries: RetryPolicy;

  constructor(private readonly config: SafeAgentConfig) {
    this.baseUrl = this.trimTrailingSlash(config.baseUrl);
    this.token = config.token;
    this.timeoutMs = config.timeoutMs ?? 10_000;
    const cfg = config.retries ?? {};
    this.retries = {
      maxRetries: cfg.maxRetries ?? 3,
      baseDelayMs: cfg.baseDelayMs ?? 120,
    };
  }

  setToken(token: string): void {
    this.config.token = token;
  }

  clearToken(): void {
    this.config.token = undefined;
  }

  async registerWorker(request: WorkerRegisterRequest): Promise<WorkerRegisterResponse> {
    return this.request<WorkerRegisterRequest, WorkerRegisterResponse>("POST", "/register", request);
  }

  async issueToken(
    subject: string,
    scopes: string[],
    ttlSecs = 60,
  ): Promise<IssueTokenResponse> {
    return this.request<IssueTokenRequest, IssueTokenResponse>("POST", "/issue-token", {
      subject,
      scopes,
      ttl_secs: ttlSecs,
    });
  }

  async execute(
    tenantId: string,
    skillId: string,
    input: string,
    requestId: string,
    token?: string,
  ): Promise<ExecuteResponse> {
    const reqToken = token ?? this.token;
    if (!reqToken) {
      throw new Error("missing token: call with token argument or configure bearer token");
    }
    return this.request<ExecuteRequest, ExecuteResponse>("POST", "/execute", {
      token: reqToken,
      tenant_id: tenantId,
      skill_id: skillId,
      input,
      request_id: requestId,
    });
  }

  async getPendingApprovals(): Promise<ApprovalRequest[]> {
    return this.request<never, ApprovalRequest[]>("GET", "/approval/pending");
  }

  async approve(
    approvalId: string,
    decidedBy: string,
    reason?: string,
  ): Promise<ApprovalDecisionResponse> {
    return this.request<ApprovalDecisionRequest, ApprovalDecisionResponse>("POST", "/approval/decide", {
      approval_id: approvalId,
      decision: "approved",
      decided_by: decidedBy,
      reason,
    });
  }

  async deny(
    approvalId: string,
    decidedBy: string,
    reason?: string,
  ): Promise<ApprovalDecisionResponse> {
    return this.request<ApprovalDecisionRequest, ApprovalDecisionResponse>("POST", "/approval/decide", {
      approval_id: approvalId,
      decision: "denied",
      decided_by: decidedBy,
      reason,
    });
  }

  async fetchJwks(): Promise<Jwks> {
    return this.request<never, Jwks>("GET", "/jwks");
  }

  private async request<TReq, TRes>(
    method: "GET" | "POST",
    path: string,
    body?: TReq,
  ): Promise<TRes> {
    let retriesLeft = this.retries.maxRetries;
    let lastError: string | undefined;

    while (true) {
      try {
        const response = await this.sendOnce(method, path, body);
        if (!response.ok) {
          const bodyText = await response.text();
          if (response.status >= 500 && retriesLeft > 0) {
            retriesLeft -= 1;
            lastError = `${response.status}: ${bodyText}`;
            await this.sleep(this.retries.baseDelayMs * (2 ** (this.retries.maxRetries - retriesLeft)));
            continue;
          }
          const err = new Error(`HTTP ${response.status}: ${bodyText}`) as HttpError;
          err.status = response.status;
          throw err;
        }
        return (await response.json()) as TRes;
      } catch (err) {
        if (retriesLeft > 0) {
          retriesLeft -= 1;
          lastError = String(err);
          await this.sleep(this.retries.baseDelayMs * (2 ** (this.retries.maxRetries - retriesLeft)));
          continue;
        }
        throw new Error(lastError ?? "request failed");
      }
    }
  }

  private async sendOnce<TReq>(method: "GET" | "POST", path: string, body?: TReq): Promise<Response> {
    const headers = {
      accept: "application/json",
      "content-type": "application/json",
    };
    const init: RequestInit = {
      method,
      headers,
      signal: AbortSignal.timeout(this.timeoutMs),
    };

    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }

    const token = this.config.token;
    if (token) {
      init.headers = { ...headers, Authorization: `Bearer ${token}` };
    }

    return fetch(`${this.baseUrl}${path}`, init);
  }

  private trimTrailingSlash(baseUrl: string): string {
    return baseUrl.replace(/\/+$/, "");
  }

  private async sleep(ms: number): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, ms));
  }
}
