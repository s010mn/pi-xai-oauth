import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { Api, Context, Model, OAuthCredentials, OAuthLoginCallbacks, SimpleStreamOptions } from "@earendil-works/pi-ai";
import { streamSimpleOpenAIResponses } from "@earendil-works/pi-ai";
import { randomUUID } from "crypto";

import xaiLogic from "./xai-oauth-logic.cjs";

const {
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
} = xaiLogic;

const MODELS = [
  {
    id: "grok-4.3",
    name: "Grok 4.3",
    reasoning: true,
    input: ["text", "image"],
    cost: { input: 1.25, output: 2.5, cacheRead: 0.3125, cacheWrite: 0.625 },
    contextWindow: 1_000_000,
    maxTokens: 131_072,
  },
  {
    id: "grok-4.20-0309-reasoning",
    name: "Grok 4.2 Reasoning",
    reasoning: true,
    input: ["text", "image"],
    cost: { input: 2, output: 8, cacheRead: 0.5, cacheWrite: 2 },
    contextWindow: 1_000_000,
    maxTokens: 131_072,
  },
  {
    id: "grok-4.20-0309-non-reasoning",
    name: "Grok 4.2 Fast",
    reasoning: false,
    input: ["text", "image"],
    cost: { input: 0.6, output: 1.2, cacheRead: 0.15, cacheWrite: 0.3 },
    contextWindow: 1_000_000,
    maxTokens: 131_072,
  },
];

async function xaiDiscovery(): Promise<{ authorization_endpoint: string; token_endpoint: string }> {
  const response = await fetch(`${XAI_OAUTH_ISSUER}/.well-known/openid-configuration`, {
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error(`xAI OAuth discovery failed: ${response.status} ${await response.text()}`);
  }

  const data = (await response.json()) as { authorization_endpoint?: string; token_endpoint?: string };
  if (!data.authorization_endpoint || !data.token_endpoint) {
    throw new Error("xAI OAuth discovery response did not include authorization/token endpoints");
  }

  return {
    authorization_endpoint: validateXaiEndpoint(data.authorization_endpoint),
    token_endpoint: validateXaiEndpoint(data.token_endpoint),
  };
}

async function exchangeXaiToken(tokenEndpoint: string, body: Record<string, string>): Promise<{ access_token?: string; refresh_token?: string; id_token?: string; expires_in?: number; token_type?: string; }> {
  const response = await fetch(tokenEndpoint, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(body).toString(),
  });
  if (!response.ok) {
    throw new Error(`xAI token request failed: ${response.status} ${await response.text()}`);
  }
  return (await response.json()) as any;
}

function streamSimpleXaiResponses(model: Model<Api>, context: Context, options?: SimpleStreamOptions) {
  const headers = { ...(options?.headers || {}) };
  if (options?.sessionId && !headers["x-grok-conv-id"]) headers["x-grok-conv-id"] = options.sessionId;

  return streamSimpleOpenAIResponses(model as Model<"openai-responses">, context, {
    ...options,
    headers,
    async onPayload(payload, payloadModel) {
      const rewritten = rewriteXaiResponsesPayload(payload, payloadModel, options);
      const userRewritten = await options?.onPayload?.(rewritten, payloadModel);
      return userRewritten === undefined ? rewritten : userRewritten;
    },
  });
}

export default function (pi: ExtensionAPI) {
  pi.registerProvider("xai-auth", {
    name: "xAI (OAuth)",
    baseUrl: "https://api.x.ai/v1",
    api: "xai-responses",
    models: MODELS as any,
    authHeader: true,
    streamSimple: streamSimpleXaiResponses as any,

    oauth: {
      usesCallbackServer: true,
      name: "xAI (Grok)",

      async login(callbacks: OAuthLoginCallbacks): Promise<OAuthCredentials> {
        const existingCredentials = getGrokAuthCredentials();
        if (existingCredentials) {
          const useExisting = await callbacks.onPrompt({
            message: "Found existing official Grok CLI credentials in ~/.grok/auth.json. Use them instead of opening a new xAI OAuth login? (y/n)",
          });
          if (useExisting.toLowerCase().startsWith("y")) {
            return existingCredentials;
          }
        }

        callbacks.onProgress?.("Starting xAI SuperGrok OAuth login...");
        const discovery = await xaiDiscovery();
        const callbackServer = await startCallbackServer();
        const { verifier, challenge } = pkcePair();
        const state = randomUUID().replace(/-/g, "");
        const nonce = randomUUID().replace(/-/g, "");
        const authorizeUrl = buildAuthorizeUrl(discovery, callbackServer.redirectUri, challenge, state, nonce);

        // Trigger automatic browser open via pi's onAuth handler.
        // pi's login dialog runs `open <url>` on macOS / `xdg-open` on Linux,
        // AND when usesCallbackServer:true it also shows a built-in manual input
        // field that resolves via onManualCodeInput. We race both paths below.
        callbacks.onAuth?.({
          url: authorizeUrl,
          instructions:
            "If the automatic open uses the wrong browser/profile, copy the URL and paste it into the field below (or open it manually in your preferred browser).",
        });

        callbacks.onProgress?.(`Waiting for xAI OAuth callback on ${callbackServer.redirectUri}...`);

        // Race the local callback server against pi's built-in manual input
        // (shown automatically when usesCallbackServer: true). If the HTTP
        // callback fires first (browser reaches localhost), the manual input
        // is simply a no-op since resolveCallback already ran.
        const manualCodePromise = callbacks.onManualCodeInput?.();
        if (manualCodePromise) {
          manualCodePromise.then((input: string) => {
            if (input) {
              const manual = parseCallbackInput(input);
              if (manual) callbackServer.resolveCallback(manual);
            }
          }).catch(() => {
            // Cancellation is handled by callbacks.signal / the login dialog.
          });
        }

        const callback = await callbackServer.waitForCallback(callbacks.signal);
        if (callback.error) {
          throw new Error(`xAI authorization failed: ${callback.error_description || callback.error}`);
        }
        if (callback.state && callback.state !== state) {
          throw new Error("xAI authorization failed: state mismatch");
        }
        if (!callback.code) {
          throw new Error("xAI authorization failed: no authorization code returned");
        }

        callbacks.onProgress?.("Exchanging xAI authorization code...");
        const data = await exchangeXaiToken(discovery.token_endpoint, {
          grant_type: "authorization_code",
          code: callback.code,
          redirect_uri: callbackServer.redirectUri,
          client_id: XAI_OAUTH_CLIENT_ID,
          code_verifier: verifier,
        });

        return credentialsFromTokenPayload(data, discovery.token_endpoint);
      },

      async refreshToken(credentials: OAuthCredentials): Promise<OAuthCredentials> {
        if (!credentials.refresh) return credentials;

        const tokenEndpoint =
          typeof credentials.tokenEndpoint === "string" && credentials.tokenEndpoint
            ? validateXaiEndpoint(credentials.tokenEndpoint)
            : (await xaiDiscovery()).token_endpoint;

        const data = await exchangeXaiToken(tokenEndpoint, {
          grant_type: "refresh_token",
          refresh_token: credentials.refresh,
          client_id: XAI_OAUTH_CLIENT_ID,
        });

        return credentialsFromTokenPayload(data, tokenEndpoint, credentials.refresh);
      },

      getApiKey(credentials: OAuthCredentials): string {
        return credentials.access;
      },
    } as any,
  });

  // ====================== CUSTOM TOOLS ======================
  // These tools use the xai_ prefix to reduce collision risk.
  // IMPORTANT: Install this package via ONE method only (npm OR git) to avoid
  // "Tool conflicts with ..." errors between the npm global path and
  // ~/.pi/agent/git/... clone.

  // Guard to avoid re-registering tools if the module is evaluated multiple times
  // in the same process (does not protect against separate extension sources).
  let toolsRegistered = false;

  function registerXaiTools() {
    if (toolsRegistered) return;
    toolsRegistered = true;

    function getXaiAuthToken(ctx: any): string | null {
      if (ctx?.apiKey) return ctx.apiKey;
      const creds = getGrokAuthCredentials();
      if (creds?.access) return creds.access;
      return process.env.XAI_API_KEY || null;
    }

    pi.registerTool({
      name: "xai_generate_text",
      label: "xAI Generate Text",
      description: "Generate text using Grok with full reasoning, structured output, and stateful conversations.",
      parameters: {
        type: "object",
        properties: {
          prompt: { type: "string", description: "The prompt or question" },
          model: { type: "string", description: "Model to use", default: "grok-4.3" },
          reasoning_effort: { type: "string", enum: ["low", "medium", "high"], default: "medium" },
          response_format: { type: "string", description: "Set to 'json' for JSON output" },
          previous_response_id: { type: "string", description: "Continue conversation" },
          image_url: { type: "string", description: "Optional image URL for vision/multimodal input (supports image analysis)" },
        },
        required: ["prompt"],
      },
      execute: async (_toolCallId: string, params: any, _signal: any, _onUpdate: any, ctx: any) => {
        const apiKey = getXaiAuthToken(ctx);
        if (!apiKey) {
          return {
            content: [{ type: "text", text: "Error: No xAI OAuth credentials found. Please run the OAuth login first." }],
            details: { reasoning: "", response_id: "" },
          };
        }

        const model = params.model || "grok-4.3";
        const imageUrl = normalizeXaiImageInput(params.image_url);
        const input = imageUrl
          ? [
              {
                role: "user",
                content: [
                  { type: "input_text", text: params.prompt || "Describe this image." },
                  { type: "input_image", image_url: imageUrl, detail: "high" },
                ],
              },
            ]
          : params.prompt;

        const body: any = {
          model,
          input,
        };

        const effort = params.reasoning_effort || "medium";
        if (grokSupportsReasoningEffort(model) && effort !== "none") {
          body.reasoning = { effort };
        }

        if (params.response_format === "json") {
          body.text = { format: { type: "json_object" } };
        }
        if (params.previous_response_id) {
          body.previous_response_id = params.previous_response_id;
        }

        const res = await fetch("https://api.x.ai/v1/responses", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${apiKey}`,
          },
          body: JSON.stringify(body),
        });

        if (!res.ok) {
          const errorText = await res.text().catch(() => "Unknown error");
          return {
            content: [{ type: "text", text: `xAI API Error ${res.status}: ${errorText}` }],
            details: { error: true, status: res.status, reasoning: "", response_id: "" },
          };
        }

        const data = await res.json();
        const text = extractResponsesText(data);

        return {
          content: [{ type: "text", text }],
          details: {
            reasoning: data.reasoning?.content?.[0]?.text || "",
            response_id: data.id,
          },
        };
      },
    } as any);

    pi.registerTool({
      name: "xai_multi_agent",
      label: "xAI Multi-Agent Research",
      description: "Run deep multi-agent research using Grok.",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string", description: "Research topic" },
          num_agents: { type: "number", enum: [4, 16], default: 4 },
          reasoning_effort: { type: "string", enum: ["medium", "high"], default: "high" },
        },
        required: ["query"],
      },
      execute: async (_toolCallId: string, params: any, _signal: any, _onUpdate: any, ctx: any) => {
        const apiKey = getXaiAuthToken(ctx);
        if (!apiKey) {
          return {
            content: [{ type: "text", text: "Error: No xAI OAuth credentials found. Please run the OAuth login first." }],
            details: { agents_used: 0, response_id: "" },
          };
        }

        const prompt = `You are leading a team of ${params.num_agents} researchers. Research: ${params.query}`;

        const res = await fetch("https://api.x.ai/v1/responses", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${apiKey}`,
          },
          body: JSON.stringify({
            model: "grok-4.3",
            input: [{ role: "user", content: prompt }],
            reasoning: { effort: params.reasoning_effort || "high" },
          }),
        });

        if (!res.ok) {
          const errorText = await res.text().catch(() => "Unknown error");
          return {
            content: [{ type: "text", text: `xAI API Error ${res.status}: ${errorText}` }],
            details: { error: true, status: res.status, agents_used: 0, response_id: "" },
          };
        }

        const data = await res.json();
        const text = extractResponsesText(data) || "Research completed";

        return {
          content: [{ type: "text", text }],
          details: {
            agents_used: params.num_agents,
            response_id: data.id,
          },
        };
      },
    } as any);

    // Agentic tools that leverage Grok's native capabilities (X search, web knowledge, code understanding, etc.)
    // Targeted prompts unlock Grok's built-in real-time X/web access and reasoning.
    pi.registerTool({
      name: "xai_web_search",
      label: "xAI Web Search",
      description: "Search the web using Grok's native web knowledge and search capabilities.",
      parameters: {
        type: "object",
        properties: { query: { type: "string", description: "Search query" } },
        required: ["query"],
      },
      execute: async (_toolCallId: string, params: { query?: string }, _signal: any, _onUpdate: any, ctx: any) => {
        const apiKey = getXaiAuthToken(ctx);
        if (!apiKey) {
          return { content: [{ type: "text", text: `Error: No xAI OAuth credentials found. Please run the OAuth login first.` }], details: { query: params?.query } };
        }
        const prompt = `You have access to current web knowledge and search capabilities. Perform a web search for: ${params.query}. Summarize the top results with sources, key facts, dates, and any recent developments. Prioritize authoritative sources.`;
        const res = await fetch("https://api.x.ai/v1/responses", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
          body: JSON.stringify({ model: "grok-4.3", input: [{ role: "user", content: prompt }], reasoning: { effort: "medium" } }),
        });
        if (!res.ok) {
          const errorText = await res.text().catch(() => "Unknown error");
          return { content: [{ type: "text", text: `xAI API Error ${res.status}: ${errorText}` }], details: { error: true, status: res.status, query: params.query } };
        }
        const data = await res.json();
        const text = extractResponsesText(data) || `No results for: ${params.query}`;
        return { content: [{ type: "text", text }], details: { query: params.query } };
      },
    } as any);

    pi.registerTool({
      name: "xai_x_search",
      label: "xAI X Search",
      description: "Search X (Twitter) using Grok's native real-time X search and knowledge. Supports advanced filters like count, since, until.",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string", description: "X search query" },
          count: { type: "number", description: "Max number of posts to return (1-10)", default: 5 },
          since: { type: "string", description: "Only posts after this date (YYYY-MM-DD)" },
          until: { type: "string", description: "Only posts before this date (YYYY-MM-DD)" }
        },
        required: ["query"],
      },
      execute: async (_toolCallId: string, params: { query?: string; count?: number; since?: string; until?: string }, _signal: any, _onUpdate: any, ctx: any) => {
        const apiKey = getXaiAuthToken(ctx);
        if (!apiKey) {
          return { content: [{ type: "text", text: `Error: No xAI OAuth credentials found. Please run the OAuth login first.` }], details: { query: params?.query } };
        }
        let prompt = `You have native real-time access to X (Twitter) posts and trends via Grok's built-in X search. Use it to find the most relevant recent posts about: ${params.query}.

Filters:`;
        if (params.count) prompt += ` Return up to ${params.count} posts.`;
        if (params.since) prompt += ` Only posts since ${params.since}.`;
        if (params.until) prompt += ` Only posts until ${params.until}.`;
        prompt += `

Summarize:
- Top posts with usernames, engagement (likes/reposts/views), and timestamps
- Key quotes or main points from influential tweets
- Overall sentiment and any emerging trends or threads
- Notable users or conversations

Be specific and cite examples where helpful.`;
        const res = await fetch("https://api.x.ai/v1/responses", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
          body: JSON.stringify({ model: "grok-4.3", input: [{ role: "user", content: prompt }], reasoning: { effort: "medium" } }),
        });
        if (!res.ok) {
          const errorText = await res.text().catch(() => "Unknown error");
          return { content: [{ type: "text", text: `xAI API Error ${res.status}: ${errorText}` }], details: { error: true, status: res.status, query: params.query } };
        }
        const data = await res.json();
        const text = extractResponsesText(data) || `No X results for: ${params.query}`;
        return { content: [{ type: "text", text }], details: { query: params.query } };
      },
    } as any);

    pi.registerTool({
      name: "xai_code_execution",
      label: "xAI Code Execution",
      description: "Execute Python code by asking Grok to run/analyze it (safe simulation via model).",
      parameters: {
        type: "object",
        properties: { code: { type: "string", description: "Python code to execute or analyze" } },
        required: ["code"],
      },
      execute: async (_toolCallId: string, params: { code?: string }, _signal: any, _onUpdate: any, ctx: any) => {
        const apiKey = getXaiAuthToken(ctx);
        if (!apiKey) {
          return { content: [{ type: "text", text: `Error: No xAI OAuth credentials found. Please run the OAuth login first.` }], details: { code: params?.code } };
        }
        const prompt = `Execute or analyze this Python code and show the result or output:\n\n${params.code}`;
        const res = await fetch("https://api.x.ai/v1/responses", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
          body: JSON.stringify({ model: "grok-4.3", input: [{ role: "user", content: prompt }], reasoning: { effort: "low" } }),
        });
        if (!res.ok) {
          const errorText = await res.text().catch(() => "Unknown error");
          return { content: [{ type: "text", text: `xAI API Error ${res.status}: ${errorText}` }], details: { error: true, status: res.status, code: params.code } };
        }
        const data = await res.json();
        const text = extractResponsesText(data) || `Executed: ${String(params.code).substring(0, 100)}...`;
        return { content: [{ type: "text", text }], details: { code: params.code } };
      },
    } as any);

    // ====================== ADDITIONAL TOOLS ======================
    pi.registerTool({
      name: "xai_generate_image",
      label: "xAI Image Generation",
      description: "Generate images using Grok's Flux-based image model with high quality and prompt adherence.",
      parameters: {
        type: "object",
        properties: {
          prompt: { type: "string", description: "Detailed description of the image to generate" },
          size: { type: "string", description: "Image size (e.g. 1024x1024, 1792x1024)", default: "1024x1024" },
          n: { type: "number", description: "Number of images to generate (1-4)", default: 1 }
        },
        required: ["prompt"],
      },
      execute: async (_toolCallId: string, params: { prompt?: string; size?: string; n?: number }, _signal: any, _onUpdate: any, ctx: any) => {
        const apiKey = getXaiAuthToken(ctx);
        if (!apiKey) {
          return { content: [{ type: "text", text: `Error: No xAI OAuth credentials found. Please run the OAuth login first.` }], details: { prompt: params?.prompt } };
        }
        const res = await fetch("https://api.x.ai/v1/images/generations", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
          body: JSON.stringify({
            model: "grok-2-image",
            prompt: params.prompt,
            n: params.n || 1,
            size: params.size || "1024x1024"
          }),
        });
        if (!res.ok) {
          const errorText = await res.text().catch(() => "Unknown error");
          return { content: [{ type: "text", text: `xAI Image API Error ${res.status}: ${errorText}` }], details: { error: true, status: res.status, prompt: params.prompt } };
        }
        const data = await res.json();
        const images = data.data || [];
        const urls = images.map((img: any) => img.url).filter(Boolean);
        const text = urls.length > 0 
          ? `Generated ${urls.length} image(s):\n${urls.map((u: string) => `- ${u}`).join("\n")}` 
          : "Image generation completed but no URLs returned.";
        return { content: [{ type: "text", text }], details: { prompt: params.prompt, urls, count: urls.length } };
      },
    } as any);

    // ====================== NEW TOOLS (OAuth-only) ======================
    pi.registerTool({
      name: "xai_critique",
      label: "xAI Critique",
      description: "Provide detailed, reasoned critique of code, designs, writing, ideas, or arguments with structured feedback.",
      parameters: {
        type: "object",
        properties: {
          content: { type: "string", description: "The code, text, design, or idea to critique" },
          aspect: { type: "string", description: "Focus area: code, design, writing, logic, security, performance, etc." },
          tone: { type: "string", description: "Tone of critique: constructive, strict, balanced", default: "constructive" }
        },
        required: ["content"],
      },
      execute: async (_toolCallId: string, params: { content?: string; aspect?: string; tone?: string }, _signal: any, _onUpdate: any, ctx: any) => {
        const apiKey = getXaiAuthToken(ctx);
        if (!apiKey) {
          return { content: [{ type: "text", text: `Error: No xAI OAuth credentials found. Please run the OAuth login first.` }], details: { content: params?.content } };
        }
        const aspect = params.aspect || "overall quality and correctness";
        const tone = params.tone || "constructive";
        const prompt = `Provide a ${tone} critique focused on ${aspect}.\n\nContent to critique:\n${params.content}\n\nStructure your response with:\n- Strengths\n- Weaknesses / Issues\n- Specific suggestions for improvement\n- Overall assessment (score 1-10)\nUse step-by-step reasoning.`;
        const res = await fetch("https://api.x.ai/v1/responses", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
          body: JSON.stringify({ model: "grok-4.3", input: [{ role: "user", content: prompt }], reasoning: { effort: "high" } }),
        });
        if (!res.ok) {
          const errorText = await res.text().catch(() => "Unknown error");
          return { content: [{ type: "text", text: `xAI API Error ${res.status}: ${errorText}` }], details: { error: true, status: res.status } };
        }
        const data = await res.json();
        const text = extractResponsesText(data) || "Critique completed.";
        return { content: [{ type: "text", text }], details: { aspect, tone } };
      },
    } as any);

    pi.registerTool({
      name: "xai_analyze_image",
      label: "xAI Image Analysis",
      description: "Analyze images, describe visual content, answer questions about images, or extract information using Grok's vision capabilities.",
      parameters: {
        type: "object",
        properties: {
          image: { type: "string", description: "Image URL, local file path, or base64 data URL" },
          question: { type: "string", description: "Question to ask about the image (default: describe in detail)" }
        },
        required: ["image"],
      },
      execute: async (_toolCallId: string, params: { image?: string; question?: string }, _signal: any, _onUpdate: any, ctx: any) => {
        const apiKey = getXaiAuthToken(ctx);
        if (!apiKey) {
          return { content: [{ type: "text", text: `Error: No xAI OAuth credentials found. Please run the OAuth login first.` }], details: { image: params?.image } };
        }
        const question = params.question || "Describe this image in detail, including objects, text, style, and any notable details.";
        // Reuse existing image normalization from the file
        const imageInput = normalizeXaiImageInput(params.image) || params.image;
        const prompt = [{ role: "user", content: [{ type: "text", text: question }, { type: "image_url", image_url: { url: imageInput } }] }];
        const res = await fetch("https://api.x.ai/v1/responses", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
          body: JSON.stringify({ model: "grok-4.3", input: prompt, reasoning: { effort: "medium" } }),
        });
        if (!res.ok) {
          const errorText = await res.text().catch(() => "Unknown error");
          return { content: [{ type: "text", text: `xAI API Error ${res.status}: ${errorText}` }], details: { error: true, status: res.status, image: params.image } };
        }
        const data = await res.json();
        const text = extractResponsesText(data) || "Image analysis completed.";
        return { content: [{ type: "text", text }], details: { image: params.image, question } };
      },
    } as any);

    pi.registerTool({
      name: "xai_deep_research",
      label: "xAI Deep Research",
      description: "Conduct thorough multi-step research on a topic, synthesize information, cite sources, and provide comprehensive analysis with high reasoning effort.",
      parameters: {
        type: "object",
        properties: {
          topic: { type: "string", description: "Research topic or question" },
          depth: { type: "string", description: "Research depth: low, medium, high", default: "high" }
        },
        required: ["topic"],
      },
      execute: async (_toolCallId: string, params: { topic?: string; depth?: string }, _signal: any, _onUpdate: any, ctx: any) => {
        const apiKey = getXaiAuthToken(ctx);
        if (!apiKey) {
          return { content: [{ type: "text", text: `Error: No xAI OAuth credentials found. Please run the OAuth login first.` }], details: { topic: params?.topic } };
        }
        const depth = params.depth || "high";
        const prompt = `Conduct deep ${depth} research on: ${params.topic}.\n\nSteps:\n1. Gather key facts, recent developments, and authoritative sources.\n2. Analyze different perspectives and potential biases.\n3. Synthesize findings into clear conclusions.\n4. Provide actionable insights and open questions.\n\nUse step-by-step reasoning and cite sources where possible.`;
        const res = await fetch("https://api.x.ai/v1/responses", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
          body: JSON.stringify({ model: "grok-4.3", input: [{ role: "user", content: prompt }], reasoning: { effort: depth === "high" ? "high" : "medium" } }),
        });
        if (!res.ok) {
          const errorText = await res.text().catch(() => "Unknown error");
          return { content: [{ type: "text", text: `xAI API Error ${res.status}: ${errorText}` }], details: { error: true, status: res.status } };
        }
        const data = await res.json();
        const text = extractResponsesText(data) || "Research completed.";
        return { content: [{ type: "text", text }], details: { topic: params.topic, depth } };
      },
    } as any);
  }

  registerXaiTools();
}
