import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createHash, randomBytes } from "node:crypto";
import http from "node:http";
import { z } from "zod";

const API_BASE_URL = (
  process.env.FAMILY_TREE_API_BASE_URL ||
  process.env.IB_FAMILY_API_BASE_URL ||
  "https://api.family.local.imaginebest.com"
).replace(/\/+$/, "");

const API_TOKEN =
  process.env.FAMILY_TREE_API_TOKEN || process.env.IB_FAMILY_API_TOKEN;

const OIDC_ISSUER = (
  process.env.FAMILY_TREE_OIDC_ISSUER ||
  process.env.IB_FAMILY_OIDC_ISSUER ||
  "https://auth.local.imaginebest.com/realms/ib"
).replace(/\/+$/, "");
const OIDC_CLIENT_ID =
  process.env.FAMILY_TREE_OIDC_CLIENT_ID ||
  process.env.IB_FAMILY_OIDC_CLIENT_ID ||
  "ib-family-mcp";
const OIDC_SCOPE =
  process.env.FAMILY_TREE_OIDC_SCOPE ||
  process.env.IB_FAMILY_OIDC_SCOPE ||
  "openid profile email";
const OIDC_REDIRECT_PORT = Number(
  process.env.FAMILY_TREE_OIDC_REDIRECT_PORT ||
    process.env.IB_FAMILY_OIDC_REDIRECT_PORT ||
    8765
);
const OIDC_REDIRECT_URI = `http://127.0.0.1:${OIDC_REDIRECT_PORT}/callback`;

const server = new McpServer({
  name: "ib-family-mcp",
  version: "0.1.0",
});

type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

type ApiRequestOptions = {
  method?: string;
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  requireAuth?: boolean;
};

type OidcMetadata = {
  authorization_endpoint: string;
  token_endpoint: string;
  end_session_endpoint?: string;
};

type LoginState = {
  state: string;
  codeVerifier: string;
  authorizationUrl: string;
  code?: string;
  error?: string;
  server?: http.Server;
};

type TokenSet = {
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
  tokenType?: string;
};

let oidcMetadata: OidcMetadata | undefined;
let loginState: LoginState | undefined;
let tokenSet: TokenSet | undefined;

function base64Url(input: Buffer): string {
  return input
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function requireOidcIssuer(): string {
  if (!OIDC_ISSUER) {
    throw new Error(
      "Missing OIDC issuer. Start this MCP server with FAMILY_TREE_OIDC_ISSUER or IB_FAMILY_OIDC_ISSUER set."
    );
  }

  return OIDC_ISSUER;
}

async function getOidcMetadata(): Promise<OidcMetadata> {
  if (oidcMetadata) {
    return oidcMetadata;
  }

  const issuer = requireOidcIssuer();
  const response = await fetch(`${issuer}/.well-known/openid-configuration`, {
    headers: { Accept: "application/json" },
  });

  if (!response.ok) {
    throw new Error(
      `Failed to read OIDC discovery metadata: ${response.status} ${response.statusText}`
    );
  }

  oidcMetadata = (await response.json()) as OidcMetadata;
  return oidcMetadata;
}

async function getAccessToken(): Promise<string> {
  if (API_TOKEN) {
    return API_TOKEN;
  }

  if (!tokenSet?.accessToken) {
    throw new Error(
      "Not logged in. Use start_user_login, open the returned authorizationUrl, then call complete_user_login."
    );
  }

  if (tokenSet.expiresAt && tokenSet.expiresAt - 30 <= Date.now() / 1000) {
    await refreshAccessToken();
  }

  if (!tokenSet?.accessToken) {
    throw new Error("Login token is unavailable after refresh.");
  }

  return tokenSet.accessToken;
}

async function refreshAccessToken() {
  if (!tokenSet?.refreshToken) {
    tokenSet = undefined;
    throw new Error("Login expired and no refresh token is available.");
  }

  const metadata = await getOidcMetadata();
  const params = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: OIDC_CLIENT_ID,
    refresh_token: tokenSet.refreshToken,
  });

  const response = await fetch(metadata.token_endpoint, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params,
  });

  const payload = await response.json();
  if (!response.ok) {
    tokenSet = undefined;
    throw new Error(
      `Token refresh failed: ${response.status} ${JSON.stringify(payload)}`
    );
  }

  tokenSet = tokenSetFromPayload(payload);
}

function tokenSetFromPayload(payload: any): TokenSet {
  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token,
    expiresAt:
      typeof payload.expires_in === "number"
        ? Math.floor(Date.now() / 1000) + payload.expires_in
        : undefined,
    tokenType: payload.token_type,
  };
}

async function stopLoginServer() {
  const server = loginState?.server;
  if (!server) {
    return;
  }

  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });

  if (loginState) {
    loginState.server = undefined;
  }
}

function buildUrl(path: string, query?: ApiRequestOptions["query"]): URL {
  if (!path.startsWith("/")) {
    throw new Error("API path must start with '/'.");
  }

  const url = new URL(`${API_BASE_URL}${path}`);
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined) {
      url.searchParams.set(key, String(value));
    }
  }

  return url;
}

async function apiRequest({
  method = "GET",
  path,
  query,
  body,
  requireAuth = true,
}: ApiRequestOptions) {
  const headers: Record<string, string> = {
    Accept: "application/json",
  };

  if (requireAuth) {
    headers.Authorization = `Bearer ${await getAccessToken()}`;
  }

  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(buildUrl(path, query), {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  const contentType = response.headers.get("content-type") ?? "";
  const payload = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    return {
      ok: false,
      status: response.status,
      statusText: response.statusText,
      payload,
    };
  }

  return {
    ok: true,
    status: response.status,
    statusText: response.statusText,
    payload,
  };
}

function textResult(value: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(value, null, 2),
      },
    ],
  };
}

function operationRows(openapi: any) {
  return Object.entries(openapi.paths ?? {}).flatMap(([path, methods]) =>
    Object.entries(methods as Record<string, any>).map(([method, operation]) => ({
      tag: operation.tags?.[0] ?? "Untagged",
      method: method.toUpperCase(),
      path,
      summary: operation.summary ?? "",
      requiresAuth: Boolean(operation.security?.length),
    }))
  );
}

server.registerTool(
  "start_user_login",
  {
    title: "Start Family API user login",
    description:
      "Starts an OIDC authorization-code + PKCE login for the MCP server and returns the URL the user should open.",
  },
  async () => {
    await stopLoginServer();

    const metadata = await getOidcMetadata();
    const state = base64Url(randomBytes(24));
    const codeVerifier = base64Url(randomBytes(32));
    const codeChallenge = base64Url(
      createHash("sha256").update(codeVerifier).digest()
    );

    const authorizationUrl = new URL(metadata.authorization_endpoint);
    authorizationUrl.searchParams.set("client_id", OIDC_CLIENT_ID);
    authorizationUrl.searchParams.set("redirect_uri", OIDC_REDIRECT_URI);
    authorizationUrl.searchParams.set("response_type", "code");
    authorizationUrl.searchParams.set("scope", OIDC_SCOPE);
    authorizationUrl.searchParams.set("state", state);
    authorizationUrl.searchParams.set("code_challenge", codeChallenge);
    authorizationUrl.searchParams.set("code_challenge_method", "S256");

    const callbackServer = http.createServer((request, response) => {
      const requestUrl = new URL(request.url ?? "/", OIDC_REDIRECT_URI);

      if (requestUrl.pathname !== "/callback") {
        response.writeHead(404, { "Content-Type": "text/plain" });
        response.end("Not found");
        return;
      }

      if (requestUrl.searchParams.get("state") !== state) {
        loginState = {
          ...loginState!,
          error: "OIDC callback state did not match.",
        };
        response.writeHead(400, { "Content-Type": "text/plain" });
        response.end("Login failed: state mismatch.");
        return;
      }

      const error = requestUrl.searchParams.get("error");
      const code = requestUrl.searchParams.get("code");
      if (error) {
        loginState = { ...loginState!, error };
        response.writeHead(400, { "Content-Type": "text/plain" });
        response.end(`Login failed: ${error}`);
        return;
      }

      if (!code) {
        loginState = { ...loginState!, error: "Missing authorization code." };
        response.writeHead(400, { "Content-Type": "text/plain" });
        response.end("Login failed: missing authorization code.");
        return;
      }

      loginState = { ...loginState!, code };
      response.writeHead(200, { "Content-Type": "text/plain" });
      response.end("Login complete. You can return to Codex.");
    });

    await new Promise<void>((resolve, reject) => {
      callbackServer.once("error", reject);
      callbackServer.listen(OIDC_REDIRECT_PORT, "127.0.0.1", () => {
        callbackServer.off("error", reject);
        resolve();
      });
    });

    loginState = {
      state,
      codeVerifier,
      authorizationUrl: authorizationUrl.toString(),
      server: callbackServer,
    };

    return textResult({
      oidcIssuer: OIDC_ISSUER,
      clientId: OIDC_CLIENT_ID,
      redirectUri: OIDC_REDIRECT_URI,
      authorizationUrl: authorizationUrl.toString(),
      nextStep:
        "Open authorizationUrl, complete login, then call complete_user_login.",
    });
  }
);

server.registerTool(
  "complete_user_login",
  {
    title: "Complete Family API user login",
    description:
      "Exchanges the captured OIDC authorization code for tokens after the user completes browser login.",
  },
  async () => {
    if (!loginState) {
      return textResult({
        ok: false,
        error: "No login in progress. Call start_user_login first.",
      });
    }

    if (loginState.error) {
      await stopLoginServer();
      return textResult({ ok: false, error: loginState.error });
    }

    if (!loginState.code) {
      return textResult({
        ok: false,
        pending: true,
        authorizationUrl: loginState.authorizationUrl,
      });
    }

    const metadata = await getOidcMetadata();
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: OIDC_CLIENT_ID,
      code: loginState.code,
      redirect_uri: OIDC_REDIRECT_URI,
      code_verifier: loginState.codeVerifier,
    });

    const response = await fetch(metadata.token_endpoint, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params,
    });
    const payload = await response.json();

    await stopLoginServer();
    loginState = undefined;

    if (!response.ok) {
      return textResult({
        ok: false,
        status: response.status,
        payload,
      });
    }

    tokenSet = tokenSetFromPayload(payload);
    return textResult({
      ok: true,
      tokenType: tokenSet.tokenType,
      expiresAt: tokenSet.expiresAt,
      hasRefreshToken: Boolean(tokenSet.refreshToken),
    });
  }
);

server.registerTool(
  "auth_status",
  {
    title: "Read Family API auth status",
    description: "Reports whether this MCP server has an env token or user login token.",
  },
  async () =>
    textResult({
      apiBaseUrl: API_BASE_URL,
      oidcIssuer: OIDC_ISSUER || null,
      clientId: OIDC_CLIENT_ID,
      redirectUri: OIDC_REDIRECT_URI,
      hasEnvToken: Boolean(API_TOKEN),
      hasLoginToken: Boolean(tokenSet?.accessToken),
      loginTokenExpiresAt: tokenSet?.expiresAt,
      loginInProgress: Boolean(loginState),
    })
);

server.registerTool(
  "logout_user",
  {
    title: "Forget Family API login",
    description:
      "Clears the in-memory user login token held by this MCP server.",
  },
  async () => {
    await stopLoginServer();
    loginState = undefined;
    tokenSet = undefined;
    return textResult({ ok: true });
  }
);

server.registerTool(
  "api_status",
  {
    title: "Read Family API status",
    description:
      "Checks the configured Family API base URL and reports whether an API token is configured.",
  },
  async () => {
    const health = await apiRequest({
      path: "/health",
      requireAuth: false,
    });

    return textResult({
      apiBaseUrl: API_BASE_URL,
      hasApiToken: Boolean(API_TOKEN),
      health,
    });
  }
);

server.registerTool(
  "list_openapi_operations",
  {
    title: "List Family API operations",
    description:
      "Reads /openapi.json and returns API operations, optionally filtered by tag, method, or search text.",
    inputSchema: {
      tag: z.string().optional(),
      method: z.string().optional(),
      query: z.string().optional(),
    },
  },
  async ({ tag, method, query }) => {
    const response = await apiRequest({
      path: "/openapi.json",
      requireAuth: false,
    });

    if (!response.ok) {
      return textResult(response);
    }

    const normalizedTag = tag?.toLowerCase();
    const normalizedMethod = method?.toUpperCase();
    const normalizedQuery = query?.toLowerCase();

    const operations = operationRows(response.payload).filter((operation) => {
      if (normalizedTag && operation.tag.toLowerCase() !== normalizedTag) {
        return false;
      }

      if (normalizedMethod && operation.method !== normalizedMethod) {
        return false;
      }

      if (normalizedQuery) {
        const haystack = [
          operation.tag,
          operation.method,
          operation.path,
          operation.summary,
        ]
          .join(" ")
          .toLowerCase();

        return haystack.includes(normalizedQuery);
      }

      return true;
    });

    return textResult({
      apiBaseUrl: API_BASE_URL,
      count: operations.length,
      operations,
    });
  }
);

server.registerTool(
  "get_current_profile",
  {
    title: "Get current Family API profile",
    description: "Reads the authenticated user's Family API profile from /me.",
  },
  async () => textResult(await apiRequest({ path: "/me" }))
);

server.registerTool(
  "list_trees",
  {
    title: "List family trees",
    description: "Lists family trees available to the authenticated user.",
  },
  async () => textResult(await apiRequest({ path: "/trees" }))
);

server.registerTool(
  "get_tree",
  {
    title: "Get family tree",
    description: "Reads one family tree by ID.",
    inputSchema: {
      treeId: z.string(),
    },
  },
  async ({ treeId }) =>
    textResult(await apiRequest({ path: `/trees/${encodeURIComponent(treeId)}` }))
);

server.registerTool(
  "search_people",
  {
    title: "Search people in a family tree",
    description:
      "Fetches a tree and searches its people by id, name, date, photo caption, or other serialized person fields.",
    inputSchema: {
      treeId: z.string(),
      query: z.string(),
    },
  },
  async ({ treeId, query }) => {
    const response = await apiRequest({
      path: `/trees/${encodeURIComponent(treeId)}`,
    });

    if (!response.ok) {
      return textResult(response);
    }

    const payload = response.payload as any;
    const tree = payload.tree ?? payload.familyTree ?? payload;
    const people = tree.data?.people ?? tree.people ?? [];
    const q = query.toLowerCase().trim();
    const results = Array.isArray(people)
      ? people.filter((person) => JSON.stringify(person).toLowerCase().includes(q))
      : [];

    return textResult({
      treeId,
      query,
      count: results.length,
      results,
    });
  }
);

server.registerTool(
  "family_api_request",
  {
    title: "Call Family API endpoint",
    description:
      "Calls an arbitrary Family API endpoint. Mutating methods require confirmMutatingRequest=true.",
    inputSchema: {
      method: z.enum(["GET", "POST", "PATCH", "PUT", "DELETE"]).default("GET"),
      path: z.string().describe("API path beginning with '/', for example /me."),
      query: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
      body: z.unknown().optional(),
      requireAuth: z.boolean().default(true),
      confirmMutatingRequest: z.boolean().default(false),
    },
  },
  async ({ method, path, query, body, requireAuth, confirmMutatingRequest }) => {
    if (method !== "GET" && !confirmMutatingRequest) {
      return textResult({
        ok: false,
        error:
          "Refusing to run a mutating request without confirmMutatingRequest=true.",
      });
    }

    return textResult(
      await apiRequest({
        method,
        path,
        query,
        body: body as JsonValue,
        requireAuth,
      })
    );
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
