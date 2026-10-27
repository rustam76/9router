// A missing wreq-js and an exhausted free-tier quota must reach the client as
// different failures: the first is a 9router install fault (502, no retries),
// the second is the upstream's 429 FreeUsageLimitError passed through intact.
//
// Drives the REAL handleChatCore and OpenCode executor; only the TLS transport
// (opencodeTlsFetch) is mocked.
import { describe, it, expect, vi, beforeEach } from "vitest";

const { tlsFetchMock } = vi.hoisted(() => ({ tlsFetchMock: vi.fn() }));

vi.mock("../../open-sse/services/opencodeTlsClient.js", async (importOriginal) => ({
  ...(await importOriginal()),
  opencodeTlsFetch: tlsFetchMock,
}));

vi.mock("../../open-sse/utils/requestLogger.js", () => ({
  createRequestLogger: async () => ({
    logClientRawRequest: vi.fn(),
    logRawRequest: vi.fn(),
    logTargetRequest: vi.fn(),
    logProviderResponse: vi.fn(),
    logConvertedResponse: vi.fn(),
    logError: vi.fn(),
  }),
}));

vi.mock("@/lib/usageDb.js", () => ({
  trackPendingRequest: vi.fn(),
  appendRequestLog: vi.fn(async () => {}),
  saveRequestDetail: vi.fn(async () => {}),
  saveRequestUsage: vi.fn(async () => {}),
}));

const { handleChatCore } = await import("../../open-sse/handlers/chatCore.js");
const { OpencodeTlsUnavailableError } = await import("../../open-sse/services/opencodeTlsClient.js");

function callOpencodeFree() {
  return handleChatCore({
    body: {
      model: "oc/glm-5.3-flash-free",
      stream: false,
      messages: [{ role: "user", content: "hi" }],
    },
    modelInfo: { provider: "opencode", model: "glm-5.3-flash-free" },
    credentials: { providerSpecificData: {} },
    connectionId: "oc-dep-vs-quota",
    sourceFormatOverride: "openai",
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn() },
  });
}

describe("OpenCode Free: dependency failure vs quota exhaustion", () => {
  beforeEach(() => {
    tlsFetchMock.mockReset();
  });

  it("reports a missing wreq-js as a 502 naming the load error, without retrying", async () => {
    tlsFetchMock.mockRejectedValue(new OpencodeTlsUnavailableError(
      "wreq-js unavailable (wreq-js is missing and the on-demand install failed (connect ECONNREFUSED))"
    ));

    const result = await callOpencodeFree();

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain("wreq-js unavailable");
    expect(result.error).toContain("connect ECONNREFUSED");
    expect(tlsFetchMock).toHaveBeenCalledTimes(1);
  });

  it("passes the upstream 429 FreeUsageLimitError through as a quota error", async () => {
    const upstreamBody = {
      type: "error",
      error: { type: "FreeUsageLimitError", message: "Free usage limit reached. Try again later." },
    };
    tlsFetchMock.mockResolvedValue(new Response(JSON.stringify(upstreamBody), {
      status: 429,
      headers: { "content-type": "application/json" },
    }));

    const result = await callOpencodeFree();

    expect(result.success).toBe(false);
    expect(result.status).toBe(429);
    expect(result.error).toContain("FreeUsageLimitError");
    expect(result.error).not.toContain("wreq-js");
  });
});
