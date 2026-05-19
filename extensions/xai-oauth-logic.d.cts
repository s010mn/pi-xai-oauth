declare const xaiLogic: {
  XAI_OAUTH_ISSUER: string;
  XAI_OAUTH_CLIENT_ID: string;
  XAI_OAUTH_SCOPE: string;
  XAI_OAUTH_REDIRECT_HOST: string;
  XAI_OAUTH_REDIRECT_PORT: number;
  XAI_OAUTH_REDIRECT_PATH: string;
  XAI_OAUTH_REFRESH_SKEW_MS: number;
  XAI_GROK_CLI_AUTH_SCOPE_KEY: string;
  XAI_GROK_CLI_LEGACY_AUTH_SCOPE_KEY: string;
  parseExpiry(value: unknown): number | undefined;
  getGrokAuthCredentials(): any;
  pkcePair(): { verifier: string; challenge: string };
  validateXaiEndpoint(url: string): string;
  callbackCorsOrigin(origin: string | undefined): string | undefined;
  startCallbackServer(): Promise<{
    redirectUri: string;
    waitForCallback(signal?: AbortSignal): Promise<any>;
    resolveCallback(result: any): void;
    close(): void;
  }>;
  buildAuthorizeUrl(
    discovery: { authorization_endpoint: string },
    redirectUri: string,
    challenge: string,
    state: string,
    nonce: string,
  ): string;
  parseCallbackInput(input: string): any;
  credentialsFromTokenPayload(data: any, tokenEndpoint: string, fallbackRefresh?: string): any;
  stripShellQuotes(value: string): string;
  unescapeShellPath(value: string): string;
  imageMimeTypeForPath(path: string): string;
  resolveLocalImagePath(value: string): string | undefined;
  normalizeXaiImageInput(value: unknown): string | undefined;
  extractResponsesText(data: any): string;
  grokSupportsReasoningEffort(modelId: string): boolean;
  textFromResponsesContent(content: unknown): string;
  normalizeResponsesImageParts(value: unknown): unknown;
  isResponsesInputImagePart(value: unknown): value is Record<string, any>;
  textForFunctionCallOutput(output: unknown): string;
  normalizeXaiResponsesInput(input: unknown[], model: { input?: unknown[] }): unknown[];
  rewriteXaiResponsesPayload(payload: unknown, model: { id?: string; input?: unknown[] }, options?: { sessionId?: string }): unknown;
};

export default xaiLogic;
