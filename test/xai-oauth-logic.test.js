const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");

const logic = require("../extensions/xai-oauth-logic.cjs");

const PNG_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAC0lEQVR42mP8/x8AAwMCAO3ZqFkAAAAASUVORK5CYII=";

function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-xai-oauth-"));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("parseExpiry handles numeric and date inputs", () => {
  assert.equal(logic.parseExpiry(1234), 1234);
  assert.equal(logic.parseExpiry("5678"), 5678);
  assert.equal(logic.parseExpiry("2026-01-02T03:04:05Z"), Date.parse("2026-01-02T03:04:05Z"));
  assert.equal(logic.parseExpiry(""), undefined);
  assert.equal(logic.parseExpiry("not-a-date"), undefined);
});

test("authorize and callback helpers validate expected xAI shapes", () => {
  assert.equal(logic.callbackCorsOrigin("https://auth.x.ai"), "https://auth.x.ai");
  assert.equal(logic.callbackCorsOrigin("https://accounts.x.ai"), "https://accounts.x.ai");
  assert.equal(logic.callbackCorsOrigin("https://example.com"), undefined);

  assert.equal(logic.validateXaiEndpoint("https://auth.x.ai/oauth2/token"), "https://auth.x.ai/oauth2/token");
  assert.throws(() => logic.validateXaiEndpoint("http://auth.x.ai/oauth2/token"));
  assert.throws(() => logic.validateXaiEndpoint("https://evil.example/oauth2/token"));

  const authorizeUrl = new URL(
    logic.buildAuthorizeUrl(
      { authorization_endpoint: "https://auth.x.ai/oauth2/authorize" },
      "http://127.0.0.1:56121/callback",
      "challenge",
      "state",
      "nonce",
    ),
  );
  assert.equal(authorizeUrl.origin, "https://auth.x.ai");
  assert.equal(authorizeUrl.pathname, "/oauth2/authorize");
  assert.equal(authorizeUrl.searchParams.get("client_id"), logic.XAI_OAUTH_CLIENT_ID);
  assert.equal(authorizeUrl.searchParams.get("redirect_uri"), "http://127.0.0.1:56121/callback");
  assert.equal(authorizeUrl.searchParams.get("code_challenge"), "challenge");
  assert.equal(authorizeUrl.searchParams.get("state"), "state");

  assert.deepEqual(logic.parseCallbackInput("code=abc&state=xyz"), { code: "abc", state: "xyz", error: undefined, error_description: undefined });
  assert.deepEqual(logic.parseCallbackInput("https://example.com/callback?error=access_denied"), {
    code: undefined,
    state: undefined,
    error: "access_denied",
    error_description: undefined,
  });
  assert.equal(logic.parseCallbackInput(""), undefined);
});

test("credential loading prefers official and legacy Grok formats", () =>
  withTempDir((tmpDir) => {
    const originalHome = process.env.HOME;
    process.env.HOME = tmpDir;
    try {
      const authDir = path.join(tmpDir, ".grok");
      fs.mkdirSync(authDir, { recursive: true });

      fs.writeFileSync(
        path.join(authDir, "auth.json"),
        JSON.stringify({
          [logic.XAI_GROK_CLI_AUTH_SCOPE_KEY]: {
            key: "access-token",
            refresh_token: "refresh-token",
            expires_at: "2026-01-02T03:04:05Z",
          },
        }),
      );
      assert.deepEqual(logic.getGrokAuthCredentials(), {
        refresh: "refresh-token",
        access: "access-token",
        expires: Date.parse("2026-01-02T03:04:05Z") - logic.XAI_OAUTH_REFRESH_SKEW_MS,
        tokenEndpoint: "https://auth.x.ai/oauth2/token",
        tokenType: "Bearer",
      });

      fs.writeFileSync(
        path.join(authDir, "auth.json"),
        JSON.stringify({
          [logic.XAI_GROK_CLI_LEGACY_AUTH_SCOPE_KEY]: { token: "legacy-token" },
        }),
      );
      const legacy = logic.getGrokAuthCredentials();
      assert.equal(legacy.access, "legacy-token");
      assert.equal(legacy.refresh, "");

      fs.writeFileSync(
        path.join(authDir, "auth.json"),
        JSON.stringify({
          access_token: "top-level-token",
          refresh: "refresh-two",
          expires: 10_000,
        }),
      );
      assert.deepEqual(logic.getGrokAuthCredentials(), {
        refresh: "refresh-two",
        access: "top-level-token",
        expires: 10_000,
        tokenEndpoint: "https://auth.x.ai/oauth2/token",
        tokenType: "Bearer",
      });
    } finally {
      process.env.HOME = originalHome;
    }
  }));

test("image helpers normalize local files, URLs, and path quoting", () =>
  withTempDir((tmpDir) => {
    const pngPath = path.join(tmpDir, "My Image.png");
    const expectedBase64 = Buffer.from(PNG_BASE64, "base64").toString("base64");
    fs.writeFileSync(pngPath, Buffer.from(PNG_BASE64, "base64"));

  assert.equal(logic.stripShellQuotes(`"${pngPath}"`), pngPath);
  assert.equal(logic.unescapeShellPath(String.raw`"/tmp/My\ Image.png"`), "/tmp/My Image.png");
  assert.equal(logic.imageMimeTypeForPath(pngPath), "image/png");
  assert.equal(logic.normalizeXaiImageInput("https://example.com/image.png"), "https://example.com/image.png");
  assert.equal(logic.normalizeXaiImageInput(`"${pngPath}"`), `data:image/png;base64,${expectedBase64}`);
    assert.throws(() => logic.normalizeXaiImageInput(path.join(tmpDir, "missing.gif")));
    assert.throws(() => logic.imageMimeTypeForPath(path.join(tmpDir, "missing.gif")));
  }));

test("responses payload rewriting keeps text, images, and reasoning compatible", () => {
  assert.equal(logic.extractResponsesText({ output_text: "hello" }), "hello");
  assert.equal(logic.extractResponsesText({ output: [{ content: [{ type: "output_text", text: "a" }, { type: "output_text", text: "b" }] }] }), "ab");
  assert.equal(logic.grokSupportsReasoningEffort("grok-4.3"), true);
  assert.equal(logic.grokSupportsReasoningEffort("grok-4.2"), false);
  assert.equal(logic.textFromResponsesContent([{ type: "input_text", text: "one" }, { type: "output_text", text: "two" }]), "one\ntwo");

  const imageParts = logic.normalizeResponsesImageParts([
    { type: "image_url", image_url: { url: "https://example.com/image.png", detail: "high" } },
  ]);
  assert.equal(imageParts[0].type, "input_image");
  assert.equal(imageParts[0].image_url, "https://example.com/image.png");
  assert.equal(imageParts[0].detail, "high");

  const rewritten = logic.rewriteXaiResponsesPayload(
    {
      model: "grok-4.3",
      input: [
        { role: "system", content: [{ type: "text", text: "Keep it short." }] },
        { role: "user", content: [{ type: "text", text: "Question?" }] },
        {
          type: "function_call_output",
          call_id: "tool-1",
          output: [
            { type: "input_text", text: "tool text" },
            { type: "input_image", image_url: "https://example.com/image.png", detail: "high" },
          ],
        },
      ],
      reasoning: { effort: "minimal" },
      include: ["reasoning.encrypted_content", "foo"],
      prompt_cache_retention: "24h",
      response_format: { type: "json_object" },
    },
    { id: "grok-4.3", input: ["text", "image"] },
    { sessionId: "session-123" },
  );

  assert.equal(rewritten.instructions, "Keep it short.");
  assert.deepEqual(rewritten.text, { format: { type: "json_object" } });
  assert.equal(rewritten.prompt_cache_key, "session-123");
  assert.equal(rewritten.reasoning.effort, "low");
  assert.deepEqual(rewritten.include, ["foo"]);
  assert.equal(rewritten.input[0].role, "user");
  assert.equal(rewritten.input[1].type, "function_call_output");
  assert.equal(rewritten.input[1].output, "tool text\n[1 image attached in the following user message]");
  assert.equal(rewritten.input[2].role, "user");
  assert.equal(rewritten.input[2].content[0].type, "input_text");
  assert.equal(rewritten.input[2].content[1].detail, "high");
});

test("callback server serves the callback route and CORS preflight", async () => {
  const server = await logic.startCallbackServer();
  const callbackPromise = server.waitForCallback();

  const optionsResponse = await fetch(server.redirectUri, {
    method: "OPTIONS",
    headers: { Origin: "https://auth.x.ai" },
  });
  assert.equal(optionsResponse.status, 204);
  assert.equal(optionsResponse.headers.get("access-control-allow-origin"), "https://auth.x.ai");

  const callbackUrl = new URL(server.redirectUri);
  callbackUrl.searchParams.set("code", "abc123");
  callbackUrl.searchParams.set("state", "state-1");

  const callbackResponse = await fetch(callbackUrl, {
    headers: { Origin: "https://auth.x.ai" },
  });
  assert.equal(callbackResponse.status, 200);
  assert.match(await callbackResponse.text(), /authorization received/i);

  const callback = await callbackPromise;
  assert.deepEqual(callback, { code: "abc123", state: "state-1", error: undefined, error_description: undefined });
});
