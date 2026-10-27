// OpenCode Free 429s (#5253). Two things are pinned here:
//  - sessions: the free lane's credentials are one virtual "noauth" connection
//    shared by every caller, so sessions must be scoped by the caller, or one
//    caller inherits another's exhausted session;
//  - 429 policy: FreeUsageLimitError (quota) is never retried, a short
//    Retry-After is honored, otherwise exponential backoff.
// Only the TLS transport is mocked; the executor and BaseExecutor are real.
import { describe, it, expect, vi, beforeEach } from "vitest";

const { tlsFetchMock } = vi.hoisted(() => ({ tlsFetchMock: vi.fn() }));

vi.mock("../../open-sse/services/opencodeTlsClient.js", async (importOriginal) => ({
  ...(await importOriginal()),
  opencodeTlsFetch: tlsFetchMock,
}));

const { getExecutor } = await import("../../open-sse/executors/index.js");
const { translateSessionId, OPENCODE_SESSION_RE } = await import("../../open-sse/executors/opencode.js");
const { generateBinaryStyleId } = await import("../../open-sse/utils/sessionManager.js");

// Shape returned by getProviderCredentials for noAuth providers (src/sse/services/auth.js).
function sharedCredentials(rawHeaders = {}) {
  return { id: "noauth", connectionName: "Public", accessToken: "public", providerSpecificData: {}, rawHeaders };
}

function sessionFor(rawHeaders, body = { messages: [{ role: "user", content: "hi" }] }) {
  return getExecutor("opencode").prepareRequestCredentials({ body, credentials: sharedCredentials(rawHeaders) })._opencodeSession;
}

const QUOTA_BODY = {
  type: "error",
  error: { type: "FreeUsageLimitError", message: "Free usage limit reached." },
};

function res(status, body = {}, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

function runExecute(log = { debug: vi.fn(), warn: vi.fn() }) {
  return getExecutor("opencode").execute({
    model: "glm-5.3-flash-free",
    body: { messages: [{ role: "user", content: "hi" }] },
    stream: true,
    credentials: sharedCredentials({ authorization: "Bearer sk-caller-secret" }),
    log,
  });
}

describe("OpenCode Free session scoping on the shared noauth connection", () => {
  it("gives different callers different upstream sessions", () => {
    const a = sessionFor({ authorization: "Bearer key-A" });
    const b = sessionFor({ authorization: "Bearer key-B" });
    expect(a).toMatch(OPENCODE_SESSION_RE);
    expect(b).toMatch(OPENCODE_SESSION_RE);
    expect(a).not.toBe(b);
  });

  it("keeps one stable session per caller across requests", () => {
    expect(sessionFor({ "x-api-key": "key-C" })).toBe(sessionFor({ "x-api-key": "key-C" }));
  });

  it("does not let two callers' identical assistant history share a session", () => {
    const body = {
      messages: [
        { role: "user", content: "hi" },
        { role: "assistant", content: "Sure — I'll start by looking at the repository layout and the build config." },
        { role: "user", content: "go on" },
      ],
    };
    expect(sessionFor({ authorization: "Bearer key-D" }, body)).not.toBe(sessionFor({ authorization: "Bearer key-E" }, body));
  });

  it("separates the same raw client session id coming from different callers", () => {
    expect(translateSessionId("default", "claude", "auth:a")).not.toBe(translateSessionId("default", "claude", "auth:b"));
    expect(translateSessionId("default", "claude", "auth:a")).toBe(translateSessionId("default", "claude", "auth:a"));
  });

  // chatCore's seed for the shared connection is random per request when the
  // client sends no session signal; it used to mint one upstream session per
  // request and per combo model (seen live: 7 sessions for one conversation).
  it("ignores chatCore's per-request random seed and keeps one session per caller", () => {
    const executor = getExecutor("opencode");
    const body = { messages: [{ role: "system", content: "s" }, { role: "user", content: "hi" }] };
    const prepare = () => executor.prepareRequestCredentials({
      body,
      credentials: sharedCredentials({ authorization: "Bearer key-F" }),
      providerSessionId: generateBinaryStyleId(),
    });
    const first = prepare();
    const second = prepare();
    expect(second._opencodeSession).toBe(first._opencodeSession);
    expect(first._opencodeSessionSource).toBe("stable");
  });

  it("still separates conversations the client identifies itself", () => {
    const executor = getExecutor("opencode");
    const body = { messages: [{ role: "user", content: "hi" }] };
    const forConversation = (id) => executor.prepareRequestCredentials({
      body,
      credentials: sharedCredentials({ authorization: "Bearer key-G", "x-session-id": id }),
      providerSessionId: generateBinaryStyleId(),
    });
    const a1 = forConversation("conv-1");
    const a2 = forConversation("conv-1");
    const b = forConversation("conv-2");
    expect(a2._opencodeSession).toBe(a1._opencodeSession);
    expect(b._opencodeSession).not.toBe(a1._opencodeSession);
    expect(a1._opencodeSessionSource).toBe("conversation");
  });

  it("passes a native OpenCode session from the client through untouched", () => {
    const native = "ses_0123456789abABCDEFGHIJKLMN";
    expect(sessionFor({ "x-opencode-session": native })).toBe(native);
  });
});

describe("OpenCode Free 429 retry policy", () => {
  const executor = getExecutor("opencode");

  it("never retries FreeUsageLimitError, whatever its Retry-After", async () => {
    expect(await executor.computeRetryDelay(res(429, QUOTA_BODY, { "retry-after": "55075" }), 1)).toBe(false);
    expect(await executor.computeRetryDelay(res(429, QUOTA_BODY, { "retry-after": "1" }), 1)).toBe(false);
  });

  it("waits out a short Retry-After and refuses a long one", async () => {
    expect(await executor.computeRetryDelay(res(429, {}, { "retry-after": "3" }), 1)).toBe(3000);
    expect(await executor.computeRetryDelay(res(429, {}, { "retry-after": "600" }), 1)).toBe(false);
  });

  it("backs off exponentially without a Retry-After", async () => {
    const first = await executor.computeRetryDelay(res(429), 1);
    const second = await executor.computeRetryDelay(res(429), 2);
    expect(first).toBeGreaterThanOrEqual(1000);
    expect(first).toBeLessThan(1500);
    expect(second).toBeGreaterThanOrEqual(2000);
    expect(second).toBeLessThan(2500);
  });

  it("leaves non-429 statuses to the configured retry", async () => {
    expect(await executor.computeRetryDelay(res(503), 1)).toBeNull();
  });
});

describe("OpenCode Free 429 through execute()", () => {
  beforeEach(() => {
    tlsFetchMock.mockReset();
  });

  it("returns a quota 429 after one upstream call and logs it without secrets", async () => {
    tlsFetchMock.mockResolvedValue(res(429, QUOTA_BODY, { "retry-after": "55075", "x-opencode-log-id": "01a17c86-1b04" }));
    const log = { debug: vi.fn(), warn: vi.fn() };

    const { response } = await runExecute(log);

    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("55075");
    expect(tlsFetchMock).toHaveBeenCalledTimes(1);

    const line = log.warn.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(line).toContain("free-tier quota exhausted (FreeUsageLimitError)");
    expect(line).toContain("retry-after=55075s");
    expect(line).toContain("transport=tls-client");
    expect(line).toContain("upstream-log-id=01a17c86-1b04");
    expect(line).not.toContain("sk-caller-secret");
    expect(line).not.toMatch(/ses_[0-9a-f]{12}/);
  });

  it("retries a transient 429 on the same session and succeeds", async () => {
    tlsFetchMock
      .mockResolvedValueOnce(res(429, { error: { type: "RateLimitError" } }, { "retry-after": "0" }))
      .mockResolvedValueOnce(res(200, { ok: true }));

    const { response } = await runExecute();

    expect(response.status).toBe(200);
    expect(tlsFetchMock).toHaveBeenCalledTimes(2);
    const sessions = tlsFetchMock.mock.calls.map(([, init]) => init.headers["x-opencode-session"]);
    expect(sessions[1]).toBe(sessions[0]);
  });
});
