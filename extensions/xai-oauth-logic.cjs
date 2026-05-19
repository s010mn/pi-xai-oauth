"use strict";

const { createHash, randomBytes } = require("crypto");
const { existsSync, readFileSync } = require("fs");
const { createServer } = require("http");
const { homedir } = require("os");
const { extname, isAbsolute, join, resolve } = require("path");
const { fileURLToPath } = require("url");

const XAI_OAUTH_ISSUER = "https://auth.x.ai";
const XAI_OAUTH_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828";
const XAI_OAUTH_SCOPE = "openid profile email offline_access grok-cli:access api:access";
const XAI_OAUTH_REDIRECT_HOST = "127.0.0.1";
const XAI_OAUTH_REDIRECT_PORT = 56121;
const XAI_OAUTH_REDIRECT_PATH = "/callback";
const XAI_OAUTH_REFRESH_SKEW_MS = 2 * 60 * 1000;
const XAI_GROK_CLI_AUTH_SCOPE_KEY = `${XAI_OAUTH_ISSUER}::${XAI_OAUTH_CLIENT_ID}`;
const XAI_GROK_CLI_LEGACY_AUTH_SCOPE_KEY = "https://accounts.x.ai/sign-in";

function parseExpiry(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "string" || !value.trim()) return undefined;

  const numeric = Number(value);
  if (Number.isFinite(numeric)) return numeric;

  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function getGrokAuthCredentials() {
  const authPath = join(homedir(), ".grok", "auth.json");
  if (!existsSync(authPath)) return null;

  try {
    const data = JSON.parse(readFileSync(authPath, "utf8"));

    const oidc = data?.[XAI_GROK_CLI_AUTH_SCOPE_KEY];
    if (oidc && typeof oidc === "object") {
      const access = String(oidc.key || oidc.access_token || oidc.token || "");
      if (access) {
        const expires = parseExpiry(oidc.expires_at) || Date.now() + 6 * 60 * 60 * 1000;
        return {
          refresh: String(oidc.refresh_token || oidc.refresh || ""),
          access,
          expires: expires - XAI_OAUTH_REFRESH_SKEW_MS,
          tokenEndpoint: `${XAI_OAUTH_ISSUER}/oauth2/token`,
          tokenType: "Bearer",
        };
      }
    }

    const legacy = data?.[XAI_GROK_CLI_LEGACY_AUTH_SCOPE_KEY];
    const legacyAccess = legacy && typeof legacy === "object" ? legacy.key || legacy.access_token || legacy.token : "";
    if (legacyAccess) {
      return {
        refresh: "",
        access: String(legacyAccess),
        expires: Date.now() + 30 * 24 * 60 * 60 * 1000,
      };
    }

    const topLevelAccess = data?.access_token || data?.token;
    if (topLevelAccess) {
      return {
        refresh: String(data.refresh_token || data.refresh || ""),
        access: String(topLevelAccess),
        expires: parseExpiry(data.expires_at || data.expires) || Date.now() + 30 * 24 * 60 * 60 * 1000,
        tokenEndpoint: `${XAI_OAUTH_ISSUER}/oauth2/token`,
        tokenType: String(data.token_type || "Bearer"),
      };
    }
  } catch {
    return null;
  }

  return null;
}

function pkcePair() {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

function validateXaiEndpoint(url) {
  const parsed = new URL(url);
  const host = parsed.hostname.toLowerCase();
  if (parsed.protocol !== "https:" || (host !== "x.ai" && !host.endsWith(".x.ai"))) {
    throw new Error(`xAI OAuth discovery returned an unexpected endpoint: ${url}`);
  }
  return url;
}

function callbackCorsOrigin(origin) {
  return origin === "https://accounts.x.ai" || origin === "https://auth.x.ai" ? origin : undefined;
}

async function startCallbackServer() {
  let resolveCallback;
  const callbackPromise = new Promise((resolve) => {
    resolveCallback = resolve;
  });

  const makeServer = () =>
    createServer((req, res) => {
      const origin = callbackCorsOrigin(req.headers.origin);
      const writeCors = () => {
        if (!origin) return;
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", "Content-Type");
        res.setHeader("Access-Control-Allow-Private-Network", "true");
        res.setHeader("Vary", "Origin");
      };

      if (req.method === "OPTIONS") {
        writeCors();
        res.writeHead(204);
        res.end();
        return;
      }

      const url = new URL(req.url || "/", `http://${XAI_OAUTH_REDIRECT_HOST}`);
      if (url.pathname !== XAI_OAUTH_REDIRECT_PATH) {
        res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("Not found");
        return;
      }

      const result = {
        code: url.searchParams.get("code") || undefined,
        state: url.searchParams.get("state") || undefined,
        error: url.searchParams.get("error") || undefined,
        error_description: url.searchParams.get("error_description") || undefined,
      };
      resolveCallback(result);

      writeCors();
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(
        result.error
          ? "<html><body><h1>xAI authorization failed.</h1>You can close this tab.</body></html>"
          : "<html><body><h1>xAI authorization received.</h1>You can close this tab.</body></html>",
      );
    });

  const listen = (port) =>
    new Promise((resolve, reject) => {
      const server = makeServer();
      server.once("error", reject);
      server.listen(port, XAI_OAUTH_REDIRECT_HOST, () => {
        server.removeListener("error", reject);
        resolve(server);
      });
    });

  let server;
  try {
    server = await listen(XAI_OAUTH_REDIRECT_PORT);
  } catch {
    server = await listen(0);
  }

  const address = server.address();
  if (!address || typeof address === "string") {
    server.close();
    throw new Error("Could not determine xAI OAuth callback port");
  }

  const redirectUri = `http://${XAI_OAUTH_REDIRECT_HOST}:${address.port}${XAI_OAUTH_REDIRECT_PATH}`;

  const close = () => {
    try {
      server.close();
    } catch {
      // ignore
    }
  };

  return {
    redirectUri,
    close,
    resolveCallback,
    waitForCallback: async (signal) => {
      let timer;
      let abortHandler;
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("Timed out waiting for xAI OAuth callback")), 180_000);
        abortHandler = () => {
          if (timer) clearTimeout(timer);
          reject(new Error("xAI OAuth login was cancelled"));
        };
        signal?.addEventListener("abort", abortHandler, { once: true });
      });

      try {
        return await Promise.race([callbackPromise, timeout]);
      } finally {
        if (timer) clearTimeout(timer);
        if (abortHandler) signal?.removeEventListener("abort", abortHandler);
        close();
      }
    },
  };
}

function buildAuthorizeUrl(discovery, redirectUri, challenge, state, nonce) {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: XAI_OAUTH_CLIENT_ID,
    redirect_uri: redirectUri,
    scope: XAI_OAUTH_SCOPE,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
    nonce,
  });
  return `${discovery.authorization_endpoint}?${params.toString()}`;
}

function parseCallbackInput(input) {
  const value = input.trim();
  if (!value) return undefined;

  try {
    const url = value.startsWith("http")
      ? new URL(value)
      : new URL(`http://${XAI_OAUTH_REDIRECT_HOST}${XAI_OAUTH_REDIRECT_PATH}?${value.replace(/^\?/, "")}`);
    return {
      code: url.searchParams.get("code") || undefined,
      state: url.searchParams.get("state") || undefined,
      error: url.searchParams.get("error") || undefined,
      error_description: url.searchParams.get("error_description") || undefined,
    };
  } catch {
    if (/^[A-Za-z0-9_-]{20,}$/.test(value)) return { code: value };
    return undefined;
  }
}

function credentialsFromTokenPayload(data, tokenEndpoint, fallbackRefresh = "") {
  if (!data.access_token) {
    throw new Error("xAI token response did not include an access token");
  }

  const refresh = data.refresh_token || fallbackRefresh;
  if (!refresh) {
    throw new Error("xAI token response did not include a refresh token");
  }

  return {
    refresh,
    access: data.access_token,
    expires: Date.now() + (data.expires_in || 3600) * 1000 - XAI_OAUTH_REFRESH_SKEW_MS,
    tokenEndpoint,
    idToken: data.id_token || "",
    tokenType: data.token_type || "Bearer",
  };
}

function stripShellQuotes(value) {
  const trimmed = value.trim();
  if (
    trimmed.length >= 2 &&
    ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'")))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function unescapeShellPath(value) {
  return stripShellQuotes(value).replace(/\\([\\\s'"()&;@])/g, "$1");
}

function imageMimeTypeForPath(path) {
  switch (extname(path).toLowerCase()) {
    case ".jpg":
    case ".jpeg":
      return "image/jpeg";
    case ".png":
      return "image/png";
    default:
      throw new Error("xAI image understanding supports local .jpg, .jpeg, and .png files only");
  }
}

function resolveLocalImagePath(value) {
  const cleaned = unescapeShellPath(value);
  if (!cleaned) return undefined;

  if (cleaned.startsWith("file://")) {
    try {
      return fileURLToPath(cleaned);
    } catch {
      return undefined;
    }
  }

  const candidates = [cleaned];
  if (!isAbsolute(cleaned)) candidates.push(resolve(process.cwd(), cleaned));

  return candidates.find((candidate) => existsSync(candidate));
}

function normalizeXaiImageInput(value) {
  if (typeof value !== "string" || !value.trim()) return undefined;
  const cleaned = stripShellQuotes(value);

  if (/^https?:\/\//i.test(cleaned) || /^data:image\//i.test(cleaned)) {
    return cleaned;
  }

  const localPath = resolveLocalImagePath(cleaned);
  if (!localPath) {
    throw new Error(`Image file does not exist or is not a valid URL: ${cleaned}`);
  }

  const mimeType = imageMimeTypeForPath(localPath);
  const data = readFileSync(localPath).toString("base64");
  return `data:${mimeType};base64,${data}`;
}

function extractResponsesText(data) {
  if (typeof data?.output_text === "string" && data.output_text) return data.output_text;
  const chunks = [];
  for (const item of data?.output || []) {
    for (const part of item?.content || []) {
      if (typeof part?.text === "string" && (part.type === "output_text" || part.text)) chunks.push(part.text);
    }
  }
  return chunks.join("") || JSON.stringify(data);
}

function grokSupportsReasoningEffort(modelId) {
  const normalized = (modelId || "").toLowerCase().split("/").pop() || "";
  return normalized.startsWith("grok-3-mini") || normalized.startsWith("grok-4.20-multi-agent") || normalized.startsWith("grok-4.3");
}

function textFromResponsesContent(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((part) => {
      if (typeof part === "string") return part;
      if (!part || typeof part !== "object") return "";
      const item = part;
      const type = typeof item.type === "string" ? item.type : "";
      return ["text", "input_text", "output_text"].includes(type) && typeof item.text === "string" ? item.text : "";
    })
    .filter(Boolean)
    .join("\n");
}

function normalizeResponsesImageParts(value) {
  if (Array.isArray(value)) return value.map(normalizeResponsesImageParts);
  if (!value || typeof value !== "object") return value;

  const obj = { ...value };
  if (obj.type === "image" && typeof obj.data === "string" && typeof obj.mimeType === "string") {
    return {
      type: "input_image",
      image_url: `data:${obj.mimeType};base64,${obj.data}`,
      detail: typeof obj.detail === "string" && obj.detail ? obj.detail : "auto",
    };
  }
  if (obj.type === "image_url") {
    const imageUrl = typeof obj.image_url === "object" && obj.image_url ? obj.image_url.url : obj.image_url;
    const detail = typeof obj.image_url === "object" && obj.image_url ? obj.image_url.detail : obj.detail;
    obj.type = "input_image";
    obj.image_url = imageUrl;
    if (typeof detail === "string" && detail) obj.detail = detail;
  }
  if (obj.type === "input_image") {
    const imageUrl = typeof obj.image_url === "object" && obj.image_url ? obj.image_url.url : obj.image_url;
    const detail = typeof obj.image_url === "object" && obj.image_url ? obj.image_url.detail : obj.detail;
    const normalized = normalizeXaiImageInput(imageUrl);
    if (normalized) obj.image_url = normalized;
    if (typeof detail === "string" && detail) obj.detail = detail;
    if (typeof obj.detail !== "string" || !obj.detail) obj.detail = "auto";
  }
  if (Array.isArray(obj.content)) obj.content = normalizeResponsesImageParts(obj.content);
  if (Array.isArray(obj.output)) obj.output = normalizeResponsesImageParts(obj.output);
  return obj;
}

function isResponsesInputImagePart(value) {
  return !!value && typeof value === "object" && value.type === "input_image";
}

function textForFunctionCallOutput(output) {
  if (typeof output === "string") return output;
  if (!Array.isArray(output)) return output === undefined || output === null ? "" : JSON.stringify(output);

  const chunks = [];
  let imageCount = 0;
  for (const part of output) {
    if (isResponsesInputImagePart(part)) {
      imageCount++;
      continue;
    }
    const text = textFromResponsesContent([part]).trim();
    if (text) chunks.push(text);
  }
  if (imageCount > 0) chunks.push(`[${imageCount} image${imageCount === 1 ? "" : "s"} attached in the following user message]`);
  return chunks.join("\n") || (imageCount > 0 ? `[${imageCount} image${imageCount === 1 ? "" : "s"} attached]` : "");
}

function normalizeXaiResponsesInput(input, model) {
  const normalizedInput = input.map(normalizeResponsesImageParts);
  const rewritten = [];
  const modelInputs = Array.isArray(model?.input) ? model.input : [];
  const supportsImages = modelInputs.includes("image");

  for (const item of normalizedInput) {
    if (!item || typeof item !== "object" || item.type !== "function_call_output" || !Array.isArray(item.output)) {
      rewritten.push(item);
      continue;
    }

    const outputParts = item.output;
    const imageParts = outputParts.filter(isResponsesInputImagePart);
    const outputText = textForFunctionCallOutput(outputParts);
    rewritten.push({ ...item, output: outputText || "(tool returned no text output)" });

    if (supportsImages && imageParts.length > 0) {
      const label = `The previous tool result${item.call_id ? ` (${item.call_id})` : ""} included ${imageParts.length} image${imageParts.length === 1 ? "" : "s"}. Use the attached image${imageParts.length === 1 ? "" : "s"} as the visual output from that tool.`;
      rewritten.push({
        role: "user",
        content: [{ type: "input_text", text: label }, ...imageParts],
      });
    }
  }

  return rewritten;
}

function rewriteXaiResponsesPayload(payload, model, options) {
  if (!payload || typeof payload !== "object") return payload;
  const body = { ...payload };

  if (Array.isArray(body.input)) {
    const input = normalizeXaiResponsesInput([...body.input], model);
    const instructionParts = [];
    while (input.length > 0) {
      const first = input[0];
      if (!first || typeof first !== "object" || (first.role !== "developer" && first.role !== "system")) break;
      const text = textFromResponsesContent(first.content).trim();
      if (text) instructionParts.push(text);
      input.shift();
    }
    if (instructionParts.length > 0) {
      body.instructions = [body.instructions, ...instructionParts].filter((part) => typeof part === "string" && part).join("\n\n");
    }
    body.input = input;
  } else if (typeof body.input === "string") {
    // String input is valid and should stay string-shaped.
  }

  if (body.response_format && !body.text) {
    body.text = { format: body.response_format };
    delete body.response_format;
  }

  if (body.reasoning && typeof body.reasoning === "object") {
    const effort = body.reasoning.effort;
    if (typeof effort === "string" && effort !== "none" && grokSupportsReasoningEffort(String(body.model || model?.id))) {
      body.reasoning = { effort: effort === "minimal" ? "low" : effort };
    } else {
      delete body.reasoning;
    }
  }

  if (Array.isArray(body.include)) {
    body.include = body.include.filter((item) => item !== "reasoning.encrypted_content");
    if (body.include.length === 0) delete body.include;
  }

  delete body.prompt_cache_retention;
  if (options?.sessionId && !body.prompt_cache_key) body.prompt_cache_key = options.sessionId;

  return body;
}

module.exports = {
  XAI_OAUTH_ISSUER,
  XAI_OAUTH_CLIENT_ID,
  XAI_OAUTH_SCOPE,
  XAI_OAUTH_REDIRECT_HOST,
  XAI_OAUTH_REDIRECT_PORT,
  XAI_OAUTH_REDIRECT_PATH,
  XAI_OAUTH_REFRESH_SKEW_MS,
  XAI_GROK_CLI_AUTH_SCOPE_KEY,
  XAI_GROK_CLI_LEGACY_AUTH_SCOPE_KEY,
  parseExpiry,
  getGrokAuthCredentials,
  pkcePair,
  validateXaiEndpoint,
  callbackCorsOrigin,
  startCallbackServer,
  buildAuthorizeUrl,
  parseCallbackInput,
  credentialsFromTokenPayload,
  stripShellQuotes,
  unescapeShellPath,
  imageMimeTypeForPath,
  resolveLocalImagePath,
  normalizeXaiImageInput,
  extractResponsesText,
  grokSupportsReasoningEffort,
  textFromResponsesContent,
  normalizeResponsesImageParts,
  isResponsesInputImagePart,
  textForFunctionCallOutput,
  normalizeXaiResponsesInput,
  rewriteXaiResponsesPayload,
};
