// server/_core/index.ts
import "dotenv/config";
import express from "express";
import { createServer } from "http";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";

// shared/const.ts
var COOKIE_NAME = "app_session_id";
var ONE_YEAR_MS = 1e3 * 60 * 60 * 24 * 365;
var AXIOS_TIMEOUT_MS = 3e4;
var UNAUTHED_ERR_MSG = "Please login (10001)";
var NOT_ADMIN_ERR_MSG = "You do not have required permission (10002)";

// server/db.ts
import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";

// drizzle/schema.ts
import { int, mysqlEnum, mysqlTable, text, timestamp, varchar } from "drizzle-orm/mysql-core";
var users = mysqlTable("users", {
  /**
   * Surrogate primary key. Auto-incremented numeric value managed by the database.
   * Use this for relations between tables.
   */
  id: int("id").autoincrement().primaryKey(),
  /** Manus OAuth identifier (openId) returned from the OAuth callback. Unique per user. */
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull()
});

// server/_core/env.ts
var ENV = {
  appId: process.env.VITE_APP_ID ?? "",
  cookieSecret: process.env.JWT_SECRET ?? "",
  databaseUrl: process.env.DATABASE_URL ?? "",
  oAuthServerUrl: process.env.OAUTH_SERVER_URL ?? "",
  ownerOpenId: process.env.OWNER_OPEN_ID ?? "",
  isProduction: process.env.NODE_ENV === "production",
  forgeApiUrl: process.env.BUILT_IN_FORGE_API_URL ?? "",
  forgeApiKey: process.env.BUILT_IN_FORGE_API_KEY ?? "",
  groqApiKey: process.env.GROQ_API_KEY ?? "",
  groqModel: process.env.GROQ_TEXT_MODEL ?? "openai/gpt-oss-120b",
  pollinationsApiKey: process.env.POLLINATIONS_API_KEY ?? "",
  pollinationsImageModel: process.env.POLLINATIONS_IMAGE_MODEL ?? "flux"
};

// server/db.ts
var _db = null;
async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}
async function upsertUser(user) {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }
  try {
    const values = {
      openId: user.openId
    };
    const updateSet = {};
    const textFields = ["name", "email", "loginMethod"];
    const assignNullable = (field) => {
      const value = user[field];
      if (value === void 0) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };
    textFields.forEach(assignNullable);
    if (user.lastSignedIn !== void 0) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== void 0) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = "admin";
      updateSet.role = "admin";
    }
    if (!values.lastSignedIn) {
      values.lastSignedIn = /* @__PURE__ */ new Date();
    }
    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = /* @__PURE__ */ new Date();
    }
    await db.insert(users).values(values).onDuplicateKeyUpdate({
      set: updateSet
    });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}
async function getUserByOpenId(openId) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get user: database not available");
    return void 0;
  }
  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);
  return result.length > 0 ? result[0] : void 0;
}

// server/_core/cookies.ts
var LOCAL_HOSTS = /* @__PURE__ */ new Set(["localhost", "127.0.0.1", "::1"]);
function isIpAddress(host) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true;
  return host.includes(":");
}
function isSecureRequest(req) {
  if (req.protocol === "https") return true;
  const forwardedProto = req.headers["x-forwarded-proto"];
  if (!forwardedProto) return false;
  const protoList = Array.isArray(forwardedProto) ? forwardedProto : forwardedProto.split(",");
  return protoList.some((proto) => proto.trim().toLowerCase() === "https");
}
function getParentDomain(hostname) {
  if (LOCAL_HOSTS.has(hostname) || isIpAddress(hostname)) {
    return void 0;
  }
  const parts = hostname.split(".");
  if (parts.length < 3) {
    return void 0;
  }
  return "." + parts.slice(-2).join(".");
}
function getSessionCookieOptions(req) {
  const hostname = req.hostname;
  const domain = getParentDomain(hostname);
  return {
    domain,
    httpOnly: true,
    path: "/",
    sameSite: "none",
    secure: isSecureRequest(req)
  };
}

// shared/_core/errors.ts
var HttpError = class extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
    this.name = "HttpError";
  }
};
var ForbiddenError = (msg) => new HttpError(403, msg);

// server/_core/sdk.ts
import axios from "axios";
import { parse as parseCookieHeader } from "cookie";
import { SignJWT, jwtVerify } from "jose";
var isNonEmptyString = (value) => typeof value === "string" && value.length > 0;
var EXCHANGE_TOKEN_PATH = `/webdev.v1.WebDevAuthPublicService/ExchangeToken`;
var GET_USER_INFO_PATH = `/webdev.v1.WebDevAuthPublicService/GetUserInfo`;
var GET_USER_INFO_WITH_JWT_PATH = `/webdev.v1.WebDevAuthPublicService/GetUserInfoWithJwt`;
var OAuthService = class {
  constructor(client) {
    this.client = client;
    console.log("[OAuth] Initialized with baseURL:", ENV.oAuthServerUrl);
    if (!ENV.oAuthServerUrl) {
      console.error(
        "[OAuth] ERROR: OAUTH_SERVER_URL is not configured! Set OAUTH_SERVER_URL environment variable."
      );
    }
  }
  decodeState(state) {
    const redirectUri = atob(state);
    return redirectUri;
  }
  async getTokenByCode(code, state) {
    const payload = {
      clientId: ENV.appId,
      grantType: "authorization_code",
      code,
      redirectUri: this.decodeState(state)
    };
    const { data } = await this.client.post(EXCHANGE_TOKEN_PATH, payload);
    return data;
  }
  async getUserInfoByToken(token) {
    const { data } = await this.client.post(GET_USER_INFO_PATH, {
      accessToken: token.accessToken
    });
    return data;
  }
};
var createOAuthHttpClient = () => axios.create({
  baseURL: ENV.oAuthServerUrl,
  timeout: AXIOS_TIMEOUT_MS
});
var SDKServer = class {
  client;
  oauthService;
  constructor(client = createOAuthHttpClient()) {
    this.client = client;
    this.oauthService = new OAuthService(this.client);
  }
  deriveLoginMethod(platforms, fallback) {
    if (fallback && fallback.length > 0) return fallback;
    if (!Array.isArray(platforms) || platforms.length === 0) return null;
    const set = new Set(platforms.filter((p) => typeof p === "string"));
    if (set.has("REGISTERED_PLATFORM_EMAIL")) return "email";
    if (set.has("REGISTERED_PLATFORM_GOOGLE")) return "google";
    if (set.has("REGISTERED_PLATFORM_APPLE")) return "apple";
    if (set.has("REGISTERED_PLATFORM_MICROSOFT") || set.has("REGISTERED_PLATFORM_AZURE"))
      return "microsoft";
    if (set.has("REGISTERED_PLATFORM_GITHUB")) return "github";
    const first = Array.from(set)[0];
    return first ? first.toLowerCase() : null;
  }
  /**
   * Exchange OAuth authorization code for access token
   * @example
   * const tokenResponse = await sdk.exchangeCodeForToken(code, state);
   */
  async exchangeCodeForToken(code, state) {
    return this.oauthService.getTokenByCode(code, state);
  }
  /**
   * Get user information using access token
   * @example
   * const userInfo = await sdk.getUserInfo(tokenResponse.accessToken);
   */
  async getUserInfo(accessToken) {
    const data = await this.oauthService.getUserInfoByToken({
      accessToken
    });
    const loginMethod = this.deriveLoginMethod(
      data?.platforms,
      data?.platform ?? data.platform ?? null
    );
    return {
      ...data,
      platform: loginMethod,
      loginMethod
    };
  }
  parseCookies(cookieHeader) {
    if (!cookieHeader) {
      return /* @__PURE__ */ new Map();
    }
    const parsed = parseCookieHeader(cookieHeader);
    return new Map(Object.entries(parsed));
  }
  getSessionSecret() {
    const secret = ENV.cookieSecret;
    return new TextEncoder().encode(secret);
  }
  /**
   * Create a session token for a Manus user openId
   * @example
   * const sessionToken = await sdk.createSessionToken(userInfo.openId);
   */
  async createSessionToken(openId, options = {}) {
    return this.signSession(
      {
        openId,
        appId: ENV.appId,
        name: options.name || ""
      },
      options
    );
  }
  async signSession(payload, options = {}) {
    const issuedAt = Date.now();
    const expiresInMs = options.expiresInMs ?? ONE_YEAR_MS;
    const expirationSeconds = Math.floor((issuedAt + expiresInMs) / 1e3);
    const secretKey = this.getSessionSecret();
    return new SignJWT({
      openId: payload.openId,
      appId: payload.appId,
      name: payload.name
    }).setProtectedHeader({ alg: "HS256", typ: "JWT" }).setExpirationTime(expirationSeconds).sign(secretKey);
  }
  async verifySession(cookieValue) {
    if (!cookieValue) {
      console.warn("[Auth] Missing session cookie");
      return null;
    }
    try {
      const secretKey = this.getSessionSecret();
      const { payload } = await jwtVerify(cookieValue, secretKey, {
        algorithms: ["HS256"]
      });
      const { openId, appId, name } = payload;
      if (!isNonEmptyString(openId) || !isNonEmptyString(appId) || !isNonEmptyString(name)) {
        console.warn("[Auth] Session payload missing required fields");
        return null;
      }
      return {
        openId,
        appId,
        name
      };
    } catch (error) {
      console.warn("[Auth] Session verification failed", String(error));
      return null;
    }
  }
  async getUserInfoWithJwt(jwtToken) {
    const payload = {
      jwtToken,
      projectId: ENV.appId
    };
    const { data } = await this.client.post(
      GET_USER_INFO_WITH_JWT_PATH,
      payload
    );
    const loginMethod = this.deriveLoginMethod(
      data?.platforms,
      data?.platform ?? data.platform ?? null
    );
    return {
      ...data,
      platform: loginMethod,
      loginMethod
    };
  }
  async authenticateRequest(req) {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    let token;
    if (typeof authHeader === "string" && authHeader.startsWith("Bearer ")) {
      token = authHeader.slice("Bearer ".length).trim();
    }
    const cookies = this.parseCookies(req.headers.cookie);
    const sessionCookie = token || cookies.get(COOKIE_NAME);
    const session = await this.verifySession(sessionCookie);
    if (!session) {
      throw ForbiddenError("Invalid session cookie");
    }
    if (session.openId.startsWith(CRON_OPEN_ID_PREFIX)) {
      const userInfo = await this.getUserInfoWithJwt(sessionCookie ?? "");
      const taskUid = userInfo.taskUid ?? null;
      if (!taskUid) {
        throw ForbiddenError("Cron session missing task_uid");
      }
      return buildCronUser(userInfo);
    }
    const sessionUserId = session.openId;
    const signedInAt = /* @__PURE__ */ new Date();
    let user = await getUserByOpenId(sessionUserId);
    if (!user) {
      try {
        const userInfo = await this.getUserInfoWithJwt(sessionCookie ?? "");
        await upsertUser({
          openId: userInfo.openId,
          name: userInfo.name || null,
          email: userInfo.email ?? null,
          loginMethod: userInfo.loginMethod ?? userInfo.platform ?? null,
          lastSignedIn: signedInAt
        });
        user = await getUserByOpenId(userInfo.openId);
      } catch (error) {
        console.error("[Auth] Failed to sync user from OAuth:", error);
        throw ForbiddenError("Failed to sync user info");
      }
    }
    if (!user) {
      throw ForbiddenError("User not found");
    }
    await upsertUser({
      openId: user.openId,
      lastSignedIn: signedInAt
    });
    return user;
  }
};
var CRON_OPEN_ID_PREFIX = "cron_";
function buildCronUser(userInfo) {
  const now = /* @__PURE__ */ new Date();
  return {
    id: -1,
    openId: userInfo.openId,
    name: userInfo.name || "Manus Scheduled Task",
    email: null,
    loginMethod: null,
    role: "user",
    createdAt: now,
    updatedAt: now,
    lastSignedIn: now,
    taskUid: userInfo.taskUid ?? void 0,
    isCron: true
  };
}
var sdk = new SDKServer();

// server/_core/oauth.ts
function getQueryParam(req, key) {
  const value = req.query[key];
  return typeof value === "string" ? value : void 0;
}
async function syncUser(userInfo) {
  if (!userInfo.openId) {
    throw new Error("openId missing from user info");
  }
  const lastSignedIn = /* @__PURE__ */ new Date();
  await upsertUser({
    openId: userInfo.openId,
    name: userInfo.name || null,
    email: userInfo.email ?? null,
    loginMethod: userInfo.loginMethod ?? userInfo.platform ?? null,
    lastSignedIn
  });
  const saved = await getUserByOpenId(userInfo.openId);
  return saved ?? {
    openId: userInfo.openId,
    name: userInfo.name,
    email: userInfo.email,
    loginMethod: userInfo.loginMethod ?? null,
    lastSignedIn
  };
}
function buildUserResponse(user) {
  return {
    id: user?.id ?? null,
    openId: user?.openId ?? null,
    name: user?.name ?? null,
    email: user?.email ?? null,
    loginMethod: user?.loginMethod ?? null,
    lastSignedIn: (user?.lastSignedIn ?? /* @__PURE__ */ new Date()).toISOString()
  };
}
function registerOAuthRoutes(app) {
  app.get("/api/oauth/callback", async (req, res) => {
    const code = getQueryParam(req, "code");
    const state = getQueryParam(req, "state");
    if (!code || !state) {
      res.status(400).json({ error: "code and state are required" });
      return;
    }
    try {
      const tokenResponse = await sdk.exchangeCodeForToken(code, state);
      const userInfo = await sdk.getUserInfo(tokenResponse.accessToken);
      await syncUser(userInfo);
      const sessionToken = await sdk.createSessionToken(userInfo.openId, {
        name: userInfo.name || "",
        expiresInMs: ONE_YEAR_MS
      });
      const cookieOptions = getSessionCookieOptions(req);
      res.cookie(COOKIE_NAME, sessionToken, { ...cookieOptions, maxAge: ONE_YEAR_MS });
      const frontendUrl = process.env.EXPO_WEB_PREVIEW_URL || process.env.EXPO_PACKAGER_PROXY_URL || "/";
      res.redirect(302, frontendUrl);
    } catch (error) {
      console.error("[OAuth] Callback failed", error);
      res.status(500).json({ error: "OAuth callback failed" });
    }
  });
  app.get("/api/oauth/mobile", async (req, res) => {
    const code = getQueryParam(req, "code");
    const state = getQueryParam(req, "state");
    if (!code || !state) {
      res.status(400).json({ error: "code and state are required" });
      return;
    }
    try {
      const tokenResponse = await sdk.exchangeCodeForToken(code, state);
      const userInfo = await sdk.getUserInfo(tokenResponse.accessToken);
      const user = await syncUser(userInfo);
      const sessionToken = await sdk.createSessionToken(userInfo.openId, {
        name: userInfo.name || "",
        expiresInMs: ONE_YEAR_MS
      });
      const cookieOptions = getSessionCookieOptions(req);
      res.cookie(COOKIE_NAME, sessionToken, { ...cookieOptions, maxAge: ONE_YEAR_MS });
      res.json({
        app_session_id: sessionToken,
        user: buildUserResponse(user)
      });
    } catch (error) {
      console.error("[OAuth] Mobile exchange failed", error);
      res.status(500).json({ error: "OAuth mobile exchange failed" });
    }
  });
  app.post("/api/auth/logout", (req, res) => {
    const cookieOptions = getSessionCookieOptions(req);
    res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
    res.json({ success: true });
  });
  app.get("/api/auth/me", async (req, res) => {
    try {
      const user = await sdk.authenticateRequest(req);
      res.json({ user: buildUserResponse(user) });
    } catch (error) {
      console.error("[Auth] /api/auth/me failed:", error);
      res.status(401).json({ error: "Not authenticated", user: null });
    }
  });
  app.post("/api/auth/session", async (req, res) => {
    try {
      const user = await sdk.authenticateRequest(req);
      const authHeader = req.headers.authorization || req.headers.Authorization;
      if (typeof authHeader !== "string" || !authHeader.startsWith("Bearer ")) {
        res.status(400).json({ error: "Bearer token required" });
        return;
      }
      const token = authHeader.slice("Bearer ".length).trim();
      const cookieOptions = getSessionCookieOptions(req);
      res.cookie(COOKIE_NAME, token, { ...cookieOptions, maxAge: ONE_YEAR_MS });
      res.json({ success: true, user: buildUserResponse(user) });
    } catch (error) {
      console.error("[Auth] /api/auth/session failed:", error);
      res.status(401).json({ error: "Invalid token" });
    }
  });
}

// server/_core/storageProxy.ts
function registerStorageProxy(app) {
  app.get("/manus-storage/*", async (req, res) => {
    const key = req.params[0];
    if (!key) {
      res.status(400).send("Missing storage key");
      return;
    }
    if (!ENV.forgeApiUrl || !ENV.forgeApiKey) {
      res.status(500).send("Storage proxy not configured");
      return;
    }
    try {
      const forgeUrl = new URL(
        "v1/storage/presign/get",
        ENV.forgeApiUrl.replace(/\/+$/, "") + "/"
      );
      forgeUrl.searchParams.set("path", key);
      const forgeResp = await fetch(forgeUrl, {
        headers: { Authorization: `Bearer ${ENV.forgeApiKey}` }
      });
      if (!forgeResp.ok) {
        const body = await forgeResp.text().catch(() => "");
        console.error(`[StorageProxy] forge error: ${forgeResp.status} ${body}`);
        res.status(502).send("Storage backend error");
        return;
      }
      const { url } = await forgeResp.json();
      if (!url) {
        res.status(502).send("Empty signed URL from backend");
        return;
      }
      res.set("Cache-Control", "no-store");
      res.redirect(307, url);
    } catch (err) {
      console.error("[StorageProxy] failed:", err);
      res.status(502).send("Storage proxy error");
    }
  });
}

// server/_core/systemRouter.ts
import { z } from "zod";

// server/_core/notification.ts
import { TRPCError } from "@trpc/server";
var TITLE_MAX_LENGTH = 1200;
var CONTENT_MAX_LENGTH = 2e4;
var trimValue = (value) => value.trim();
var isNonEmptyString2 = (value) => typeof value === "string" && value.trim().length > 0;
var buildEndpointUrl = (baseUrl) => {
  const normalizedBase = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  return new URL("webdevtoken.v1.WebDevService/SendNotification", normalizedBase).toString();
};
var validatePayload = (input) => {
  if (!isNonEmptyString2(input.title)) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: "Notification title is required."
    });
  }
  if (!isNonEmptyString2(input.content)) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: "Notification content is required."
    });
  }
  const title = trimValue(input.title);
  const content = trimValue(input.content);
  if (title.length > TITLE_MAX_LENGTH) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: `Notification title must be at most ${TITLE_MAX_LENGTH} characters.`
    });
  }
  if (content.length > CONTENT_MAX_LENGTH) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: `Notification content must be at most ${CONTENT_MAX_LENGTH} characters.`
    });
  }
  return { title, content };
};
async function notifyOwner(payload) {
  const { title, content } = validatePayload(payload);
  if (!ENV.forgeApiUrl) {
    throw new TRPCError({
      code: "INTERNAL_SERVER_ERROR",
      message: "Notification service URL is not configured."
    });
  }
  if (!ENV.forgeApiKey) {
    throw new TRPCError({
      code: "INTERNAL_SERVER_ERROR",
      message: "Notification service API key is not configured."
    });
  }
  const endpoint = buildEndpointUrl(ENV.forgeApiUrl);
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${ENV.forgeApiKey}`,
        "content-type": "application/json",
        "connect-protocol-version": "1"
      },
      body: JSON.stringify({ title, content })
    });
    if (!response.ok) {
      const detail = await response.text().catch(() => "");
      console.warn(
        `[Notification] Failed to notify owner (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`
      );
      return false;
    }
    return true;
  } catch (error) {
    console.warn("[Notification] Error calling notification service:", error);
    return false;
  }
}

// server/_core/trpc.ts
import { initTRPC, TRPCError as TRPCError2 } from "@trpc/server";
import superjson from "superjson";
var t = initTRPC.context().create({
  transformer: superjson
});
var router = t.router;
var publicProcedure = t.procedure;
var requireUser = t.middleware(async (opts) => {
  const { ctx, next } = opts;
  if (!ctx.user) {
    throw new TRPCError2({ code: "UNAUTHORIZED", message: UNAUTHED_ERR_MSG });
  }
  return next({
    ctx: {
      ...ctx,
      user: ctx.user
    }
  });
});
var protectedProcedure = t.procedure.use(requireUser);
var adminProcedure = t.procedure.use(
  t.middleware(async (opts) => {
    const { ctx, next } = opts;
    if (!ctx.user || ctx.user.role !== "admin") {
      throw new TRPCError2({ code: "FORBIDDEN", message: NOT_ADMIN_ERR_MSG });
    }
    return next({
      ctx: {
        ...ctx,
        user: ctx.user
      }
    });
  })
);

// server/_core/systemRouter.ts
var systemRouter = router({
  health: publicProcedure.input(
    z.object({
      timestamp: z.number().min(0, "timestamp cannot be negative")
    })
  ).query(() => ({
    ok: true
  })),
  notifyOwner: adminProcedure.input(
    z.object({
      title: z.string().min(1, "title is required"),
      content: z.string().min(1, "content is required")
    })
  ).mutation(async ({ input }) => {
    const delivered = await notifyOwner(input);
    return {
      success: delivered
    };
  })
});

// server/_core/llm.ts
var GroqHttpError = class extends Error {
  constructor(status, statusText, body, retryAfterSeconds) {
    super(`Groq request failed (${status} ${statusText})`);
    this.status = status;
    this.statusText = statusText;
    this.body = body;
    this.retryAfterSeconds = retryAfterSeconds;
    this.name = "GroqHttpError";
  }
};
var normalizeMessage = (message) => {
  if (typeof message.content === "string") return { role: message.role, content: message.content };
  if (Array.isArray(message.content)) return { role: message.role, content: message.content.map((part) => typeof part === "string" ? part : part.text).join("\n") };
  return { role: message.role, content: message.content.text };
};
var sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
var MAX_ATTEMPTS = 3;
var REQUEST_TIMEOUT_MS = 45e3;
async function fetchGroq(init) {
  let lastError;
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch("https://api.groq.com/openai/v1/chat/completions", { ...init, signal: controller.signal });
      clearTimeout(timeout);
      const retryable = response.status === 408 || response.status >= 500;
      if (response.ok || !retryable || attempt === MAX_ATTEMPTS - 1) return { response, attempts: attempt + 1 };
      const retryAfter = Number(response.headers.get("retry-after"));
      const delay = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1e3 : 700 * 2 ** attempt;
      await sleep(delay);
    } catch (error) {
      clearTimeout(timeout);
      lastError = error;
      if (attempt === MAX_ATTEMPTS - 1) throw error;
      await sleep(700 * 2 ** attempt);
    }
  }
  throw lastError instanceof Error ? lastError : new Error("Groq-Anfrage fehlgeschlagen");
}
async function invokeLLM(params) {
  if (!ENV.groqApiKey) throw new Error("GROQ_API_KEY ist nicht konfiguriert");
  const model = params.model ?? ENV.groqModel;
  const payload = {
    model,
    messages: params.messages.map(normalizeMessage),
    max_tokens: params.maxTokens ?? 3200,
    temperature: params.temperature ?? 0.4,
    stream: false
  };
  if (params.responseFormat) payload.response_format = params.responseFormat;
  const attempted = await fetchGroq({
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${ENV.groqApiKey}` },
    body: JSON.stringify(payload)
  });
  const response = attempted.response;
  const bodyText = await response.text();
  if (!response.ok) throw new GroqHttpError(response.status, response.statusText, bodyText, Number(response.headers.get("retry-after")) || void 0);
  let parsed;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    throw new Error("Groq lieferte keine parsebare JSON-Antwort");
  }
  const json = parsed;
  if (json.error || !Array.isArray(json.choices) || !json.choices[0]?.message?.content) {
    throw new Error("Groq lieferte keine vollst\xE4ndige Chat-Completions-Antwort");
  }
  return { ...json, httpStatus: response.status, attempts: attempted.attempts };
}

// server/storage.ts
function getForgeConfig() {
  const forgeUrl = ENV.forgeApiUrl;
  const forgeKey = ENV.forgeApiKey;
  if (!forgeUrl || !forgeKey) {
    throw new Error(
      "Storage config missing: set BUILT_IN_FORGE_API_URL and BUILT_IN_FORGE_API_KEY"
    );
  }
  return { forgeUrl: forgeUrl.replace(/\/+$/, ""), forgeKey };
}
function normalizeKey(relKey) {
  return relKey.replace(/^\/+/, "");
}
function appendHashSuffix(relKey) {
  const hash = crypto.randomUUID().replace(/-/g, "").slice(0, 8);
  const lastDot = relKey.lastIndexOf(".");
  if (lastDot === -1) return `${relKey}_${hash}`;
  return `${relKey.slice(0, lastDot)}_${hash}${relKey.slice(lastDot)}`;
}
async function storagePut(relKey, data, contentType = "application/octet-stream") {
  const { forgeUrl, forgeKey } = getForgeConfig();
  const key = appendHashSuffix(normalizeKey(relKey));
  const presignUrl = new URL("v1/storage/presign/put", forgeUrl + "/");
  presignUrl.searchParams.set("path", key);
  const presignResp = await fetch(presignUrl, {
    headers: { Authorization: `Bearer ${forgeKey}` }
  });
  if (!presignResp.ok) {
    const msg = await presignResp.text().catch(() => presignResp.statusText);
    throw new Error(`Storage presign failed (${presignResp.status}): ${msg}`);
  }
  const { url: s3Url } = await presignResp.json();
  if (!s3Url) throw new Error("Forge returned empty presign URL");
  const blob = typeof data === "string" ? new Blob([data], { type: contentType }) : new Blob([data], { type: contentType });
  const uploadResp = await fetch(s3Url, {
    method: "PUT",
    headers: { "Content-Type": contentType },
    body: blob
  });
  if (!uploadResp.ok) {
    throw new Error(`Storage upload to S3 failed (${uploadResp.status})`);
  }
  return { key, url: `/manus-storage/${key}` };
}

// server/_core/imageGeneration.ts
var PollinationsHttpError = class extends Error {
  constructor(status, body, contentType, endpoint, model, latencyMs, attempts) {
    super(`Pollinations request failed (${status})`);
    this.status = status;
    this.body = body;
    this.contentType = contentType;
    this.endpoint = endpoint;
    this.model = model;
    this.latencyMs = latencyMs;
    this.attempts = attempts;
    this.name = "PollinationsHttpError";
  }
};
var PollinationsInvalidImageError = class extends Error {
  constructor(contentType, byteLength, endpoint, model, latencyMs, attempts, body) {
    super("POLLINATIONS_INVALID_IMAGE");
    this.contentType = contentType;
    this.byteLength = byteLength;
    this.endpoint = endpoint;
    this.model = model;
    this.latencyMs = latencyMs;
    this.attempts = attempts;
    this.body = body;
    this.name = "PollinationsInvalidImageError";
  }
};
var imageCache = /* @__PURE__ */ new Map();
var sleep2 = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
var cacheKeyFor = (value) => {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16);
};
async function resolveModel() {
  const requested = ENV.pollinationsImageModel || "flux";
  try {
    const response = await fetch("https://gen.pollinations.ai/image/models", {
      headers: { authorization: `Bearer ${ENV.pollinationsApiKey}`, accept: "application/json" },
      signal: AbortSignal.timeout(8e3)
    });
    if (!response.ok) return requested;
    const models = await response.json();
    const available = models.some((model) => model.name === requested || model.aliases?.includes(requested));
    if (available) return requested;
    const fallback = models.find((model) => model.aliases?.includes("zimage") || model.name === "tongyi-mai/z-image-turbo");
    return fallback?.aliases?.[0] ?? fallback?.name ?? requested;
  } catch {
    return requested;
  }
}
async function generateImage(options) {
  if (!ENV.pollinationsApiKey) throw new Error("POLLINATIONS_NOT_CONFIGURED");
  const promptHash = cacheKeyFor(options.prompt);
  const cached = imageCache.get(promptHash);
  if (cached && cached.expiresAt > Date.now()) return cached.response;
  const model = await resolveModel();
  const query = new URLSearchParams({ model, width: options.imageType === "CHARACTER_PORTRAIT" ? "768" : "1024", height: options.imageType === "CHARACTER_PORTRAIT" ? "1024" : "768", nologo: "true" });
  const endpoint = `https://gen.pollinations.ai/image/${encodeURIComponent(options.prompt)}?${query.toString()}`;
  let lastError;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const requestStartedAt = Date.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6e4);
    try {
      const response = await fetch(endpoint, { headers: { authorization: `Bearer ${ENV.pollinationsApiKey}`, accept: "image/*, application/json", "user-agent": "AVARRA-Pollinations/1.0" }, signal: controller.signal });
      clearTimeout(timeout);
      const contentType = response.headers.get("content-type") ?? "";
      if (!response.ok) {
        const body = (await response.text().catch(() => "")).slice(0, 500);
        const error = new PollinationsHttpError(response.status, body, contentType, endpoint, model, Date.now() - requestStartedAt, attempt + 1);
        lastError = error;
        const retryable = response.status === 429 || [502, 503, 504].includes(response.status);
        if (retryable && attempt < 2) {
          await sleep2(1e3 * 2 ** attempt);
          continue;
        }
        throw error;
      }
      const raw = Buffer.from(await response.arrayBuffer());
      let image = raw;
      if (!contentType.toLowerCase().startsWith("image/")) {
        try {
          const parsed = JSON.parse(raw.toString("utf8"));
          const remoteUrl = parsed.url ?? parsed.image_url;
          if (!remoteUrl) throw new Error("missing image URL");
          const mediaResponse = await fetch(remoteUrl, { headers: { accept: "image/*" }, signal: AbortSignal.timeout(6e4) });
          const mediaContentType = mediaResponse.headers.get("content-type") ?? "";
          image = Buffer.from(await mediaResponse.arrayBuffer());
          if (!mediaResponse.ok || !mediaContentType.toLowerCase().startsWith("image/")) throw new Error(`media ${mediaResponse.status} ${mediaContentType}`);
        } catch {
          throw new PollinationsInvalidImageError(contentType, raw.byteLength, endpoint, model, Date.now() - requestStartedAt, attempt + 1, raw.toString("utf8").slice(0, 500));
        }
      }
      if (image.byteLength < 1024 || !isPlausibleImage(image, contentType)) throw new PollinationsInvalidImageError(contentType, image.byteLength, endpoint, model, Date.now() - requestStartedAt, attempt + 1, "image header or size validation failed");
      const imageId = `img-${Date.now().toString(36)}-${promptHash}`;
      const stored = await storagePut(`pollinations/${imageId}.jpg`, image, contentType);
      const result = { url: stored.url, source: "pollinations", imageId, attempts: attempt + 1, model };
      imageCache.set(promptHash, { response: result, expiresAt: Date.now() + 10 * 6e4 });
      return result;
    } catch (error) {
      clearTimeout(timeout);
      if (error instanceof PollinationsHttpError || error instanceof PollinationsInvalidImageError) throw error;
      lastError = error;
      if (attempt < 2) await sleep2(1e3 * 2 ** attempt);
    }
  }
  if (lastError instanceof Error && /abort|timeout/i.test(lastError.message)) throw new Error("POLLINATIONS_TIMEOUT");
  throw lastError instanceof Error ? lastError : new Error("POLLINATIONS_UNAVAILABLE");
}
function isPlausibleImage(image, contentType) {
  if (contentType.toLowerCase().includes("jpeg") || contentType.toLowerCase().includes("jpg")) return image.subarray(0, 3).equals(Buffer.from([255, 216, 255]));
  if (contentType.toLowerCase().includes("png")) return image.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  if (contentType.toLowerCase().includes("webp")) return image.subarray(0, 4).toString("ascii") === "RIFF" && image.subarray(8, 12).toString("ascii") === "WEBP";
  return image.byteLength >= 1024;
}

// server/_core/observability.ts
function logRequest(record) {
  console.info("AVARRA_REQUEST", record);
}
var publicMessageFor = (code) => {
  const messages = {
    DEVICE_OFFLINE: "Keine Internetverbindung.",
    BACKEND_UNREACHABLE: "Game Master momentan nicht erreichbar.",
    BACKEND_TIMEOUT: "Der Game Master antwortet zu langsam. Bitte erneut versuchen.",
    GROQ_AUTH_ERROR: "Der Game Master ist momentan nicht verf\xFCgbar.",
    GROQ_RATE_LIMIT: "Der Game Master ist momentan ausgelastet. Bitte sp\xE4ter erneut versuchen.",
    GROQ_PROVIDER_ERROR: "Der Game Master ist momentan nicht verf\xFCgbar.",
    GROQ_SCHEMA_ERROR: "Der Game Master hat keine g\xFCltige Szene geliefert.",
    POLLINATIONS_AUTH_ERROR: "Die Pollinations-Bildverbindung ist nicht autorisiert.",
    POLLINATIONS_PAYMENT_REQUIRED: "Das Pollinations-Bildbudget ist momentan nicht ausreichend.",
    POLLINATIONS_BUDGET_ERROR: "Das Pollinations-Bildbudget ist momentan nicht ausreichend.",
    POLLINATIONS_RATE_LIMIT: "Pollinations ist momentan ausgelastet. Bitte kurz warten.",
    POLLINATIONS_SERVER_ERROR: "Pollinations ist momentan nicht verf\xFCgbar.",
    POLLINATIONS_PROVIDER_ERROR: "Pollinations ist momentan nicht verf\xFCgbar.",
    POLLINATIONS_INVALID_IMAGE: "Pollinations hat kein g\xFCltiges Bild geliefert.",
    IMAGE_TIMEOUT: "Bildgenerierung dauert zu lange. Du kannst ohne Bild fortfahren.",
    INVALID_RESPONSE: "Der Game Master hat keine g\xFCltige Szene geliefert."
  };
  return messages[code];
};

// server/routers.ts
import { z as z2 } from "zod";
var GAME_MASTER_MODEL = ENV.groqModel;
var statSchema = z2.enum(["STR", "AUS", "AGI", "MAG", "WIL", "GLK"]);
var riskSchema = z2.enum(["niedrig", "mittel", "hoch"]);
var actionSchema = z2.object({
  action_id: z2.string().min(1).max(100),
  label: z2.string().min(2).max(200),
  type: z2.enum(["dialog", "explore", "travel", "craft", "combat", "risk", "observe"]).catch("explore"),
  requiresCheck: z2.boolean(),
  stat: statSchema,
  modifier: z2.number().int().min(-20).max(30).catch(0),
  dc: z2.number().int().min(1).max(35).catch(12),
  risk: riskSchema,
  consequenceHint: z2.string().min(1).max(300)
});
var eventSchema = z2.object({
  id: z2.string().min(1).max(100),
  title: z2.string().min(1).max(200),
  message: z2.string().min(1).max(1e3),
  entityId: z2.string().max(100).catch("")
});
var npcSchema = z2.object({
  npcId: z2.string().min(1).max(100),
  name: z2.string().min(1).max(120),
  agePresentation: z2.string().max(100).catch("unbestimmt"),
  role: z2.string().min(1).max(160),
  personality: z2.string().min(1).max(300),
  speechStyle: z2.string().max(200).catch("bedacht"),
  goals: z2.array(z2.string().max(200)).catch([]),
  fears: z2.array(z2.string().max(200)).catch([]),
  morality: z2.string().max(120).catch("neutral"),
  faction: z2.string().max(140).catch(""),
  relationship: z2.string().max(200).catch("neutral"),
  memories: z2.array(z2.string().max(300)).catch([])
});
var storyTurnSchema = z2.object({
  narrative: z2.string().min(40).max(6e3),
  scene: z2.object({
    location: z2.string().min(1).max(200),
    time: z2.string().min(1).max(100),
    weather: z2.string().min(1).max(140),
    situation: z2.string().min(1).max(400)
  }),
  npcs: z2.array(npcSchema).max(6).catch([]),
  normalActions: z2.array(actionSchema).max(4).catch([]),
  riskActions: z2.array(actionSchema).max(4).catch([]),
  questEvents: z2.array(eventSchema).max(4).catch([]),
  rumorEvents: z2.array(eventSchema).max(4).catch([]),
  npcEvents: z2.array(eventSchema).max(4).catch([]),
  relationshipEvents: z2.array(eventSchema).max(4).catch([]),
  worldEvents: z2.array(eventSchema).max(4).catch([]),
  inventoryEvents: z2.array(eventSchema).max(4).catch([]),
  progressionEvents: z2.array(eventSchema).max(4).catch([]),
  codexEvents: z2.array(eventSchema).max(4).catch([]),
  imageEvent: z2.object({
    requested: z2.boolean().catch(false),
    moment: z2.string().max(260).catch(""),
    encounter: z2.string().max(360).catch("")
  }).catch({ requested: false, moment: "", encounter: "" }),
  rollRequest: z2.object({
    required: z2.boolean(),
    stat: statSchema,
    modifier: z2.number().int().min(-20).max(30).catch(0),
    dc: z2.number().int().min(1).max(35).catch(14),
    risk: riskSchema,
    reason: z2.string().min(1).max(300)
  }).nullable().catch(null)
});
var ritualTraitSchema = z2.enum(["COURAGE", "EMPATHY", "CURIOSITY", "DISCIPLINE", "AMBITION", "CAUTION", "INDEPENDENCE", "LOYALTY", "CUNNING", "PRAGMATISM", "JUSTICE", "POWER_SEEKING"]);
var ritualSignalSchema = z2.object({ trait: ritualTraitSchema, weight: z2.union([z2.literal(-2), z2.literal(-1), z2.literal(1), z2.literal(2)]) });
var ritualAnswerSchema = z2.object({
  id: z2.string().min(1).max(80),
  text: z2.string().min(2).max(260),
  signals: z2.array(ritualSignalSchema).min(1).max(2)
});
var ritualQuestionSchema = z2.object({
  id: z2.string().min(1).max(80),
  question: z2.string().min(12).max(700),
  answers: z2.array(ritualAnswerSchema).length(4)
});
var ritualSchema = z2.object({
  ritualId: z2.string().min(1).max(100),
  questions: z2.array(ritualQuestionSchema).length(10)
});
var jsonSchema = (name, schema) => ({
  type: "json_schema",
  json_schema: { name, strict: true, schema }
});
var collectText = (response) => {
  return response.choices?.[0]?.message?.content ?? "";
};
async function requestStructured(args) {
  const startedAt = Date.now();
  try {
    const response = await invokeLLM({
      model: GAME_MASTER_MODEL,
      maxTokens: args.maxTokens,
      temperature: 0.35,
      responseFormat: jsonSchema(args.schemaName, args.schemaShape),
      messages: args.messages
    });
    const raw = collectText(response).trim();
    let decoded;
    try {
      decoded = JSON.parse(raw);
    } catch {
      logRequest({ requestId: args.requestId, turnId: args.turnId, route: args.schemaName, provider: "groq", model: response.model, httpStatus: response.httpStatus, latencyMs: Date.now() - startedAt, retryCount: Math.max(0, response.attempts - 1), inputTokens: response.usage?.prompt_tokens, outputTokens: response.usage?.completion_tokens, errorCode: "INVALID_RESPONSE" });
      return { ok: false, errorCode: "INVALID_RESPONSE", message: publicMessageFor("INVALID_RESPONSE") };
    }
    const parsed = args.schema.safeParse(decoded);
    if (!parsed.success) {
      logRequest({ requestId: args.requestId, turnId: args.turnId, route: args.schemaName, provider: "groq", model: response.model, httpStatus: response.httpStatus, latencyMs: Date.now() - startedAt, retryCount: Math.max(0, response.attempts - 1), inputTokens: response.usage?.prompt_tokens, outputTokens: response.usage?.completion_tokens, errorCode: "GROQ_SCHEMA_ERROR" });
      return { ok: false, errorCode: "INVALID_RESPONSE", message: publicMessageFor("GROQ_SCHEMA_ERROR") };
    }
    logRequest({ requestId: args.requestId, turnId: args.turnId, route: args.schemaName, provider: "groq", model: response.model, httpStatus: response.httpStatus, latencyMs: Date.now() - startedAt, retryCount: Math.max(0, response.attempts - 1), inputTokens: response.usage?.prompt_tokens, outputTokens: response.usage?.completion_tokens });
    return { ok: true, value: parsed.data, model: response.model };
  } catch (error) {
    const status = error instanceof GroqHttpError ? error.status : void 0;
    const message = error instanceof Error ? error.message : String(error);
    const code = status === 401 || status === 403 ? "GROQ_AUTH_ERROR" : status === 429 ? "GROQ_RATE_LIMIT" : /abort|timeout/i.test(message) ? "BACKEND_TIMEOUT" : "GROQ_PROVIDER_ERROR";
    logRequest({ requestId: args.requestId, turnId: args.turnId, route: args.schemaName, provider: "groq", model: GAME_MASTER_MODEL, httpStatus: status, latencyMs: Date.now() - startedAt, retryCount: 0, errorCode: code });
    return { ok: false, errorCode: code === "BACKEND_TIMEOUT" ? "TIMEOUT" : code === "GROQ_RATE_LIMIT" ? "INSUFFICIENT_QUOTA" : "CONNECTION_ERROR", message: publicMessageFor(code) };
  }
}
var strictObject = (properties, required = Object.keys(properties)) => ({ type: "object", additionalProperties: false, properties, required });
var arrayOf = (items) => ({ type: "array", items });
var stringArray = () => ({ type: "array", items: { type: "string" } });
var actionJsonShape = strictObject({ action_id: { type: "string" }, label: { type: "string" }, type: { type: "string" }, requiresCheck: { type: "boolean" }, stat: { type: "string", enum: ["STR", "AUS", "AGI", "MAG", "WIL", "GLK"] }, modifier: { type: "integer" }, dc: { type: "integer" }, risk: { type: "string", enum: ["niedrig", "mittel", "hoch"] }, consequenceHint: { type: "string" } });
var eventJsonShape = strictObject({ id: { type: "string" }, title: { type: "string" }, message: { type: "string" }, entityId: { type: "string" } });
var npcJsonShape = strictObject({ npcId: { type: "string" }, name: { type: "string" }, agePresentation: { type: "string" }, role: { type: "string" }, personality: { type: "string" }, speechStyle: { type: "string" }, goals: stringArray(), fears: stringArray(), morality: { type: "string" }, faction: { type: "string" }, relationship: { type: "string" }, memories: stringArray() });
var sceneJsonShape = strictObject({ location: { type: "string" }, time: { type: "string" }, weather: { type: "string" }, situation: { type: "string" } });
var imageEventJsonShape = strictObject({ requested: { type: "boolean" }, type: { type: "string", enum: ["NONE", "NPC_REVEAL", "BOSS_REVEAL", "MYTHIC_LOCATION", "MAJOR_DISCOVERY"] }, importance: { type: "number" }, reason: { type: "string" }, moment: { type: "string" }, encounter: { type: "string" } });
var rollRequestJsonShape = strictObject({ required: { type: "boolean" }, stat: { type: "string", enum: ["STR", "AUS", "AGI", "MAG", "WIL", "GLK"] }, modifier: { type: "integer" }, dc: { type: "integer" }, risk: { type: "string", enum: ["niedrig", "mittel", "hoch"] }, reason: { type: "string" } });
var storyJsonShape = strictObject({
  narrative: { type: "string" },
  scene: sceneJsonShape,
  npcs: arrayOf(npcJsonShape),
  normalActions: arrayOf(actionJsonShape),
  riskActions: arrayOf(actionJsonShape),
  questEvents: arrayOf(eventJsonShape),
  rumorEvents: arrayOf(eventJsonShape),
  npcEvents: arrayOf(eventJsonShape),
  relationshipEvents: arrayOf(eventJsonShape),
  worldEvents: arrayOf(eventJsonShape),
  inventoryEvents: arrayOf(eventJsonShape),
  progressionEvents: arrayOf(eventJsonShape),
  codexEvents: arrayOf(eventJsonShape),
  imageEvent: imageEventJsonShape,
  rollRequest: { anyOf: [rollRequestJsonShape, { type: "null" }] }
});
var ritualAnswerJsonShape = {
  type: "object",
  additionalProperties: false,
  properties: {
    id: { type: "string" },
    text: { type: "string" },
    signals: { type: "array", minItems: 1, maxItems: 2, items: strictObject({ trait: { type: "string", enum: ["COURAGE", "EMPATHY", "CURIOSITY", "DISCIPLINE", "AMBITION", "CAUTION", "INDEPENDENCE", "LOYALTY", "CUNNING", "PRAGMATISM", "JUSTICE", "POWER_SEEKING"] }, weight: { type: "integer", enum: [-2, -1, 1, 2] } }) }
  },
  required: ["id", "text", "signals"]
};
var ritualQuestionJsonShape = {
  type: "object",
  additionalProperties: false,
  properties: {
    id: { type: "string" },
    question: { type: "string" },
    // Groq reliably enforces object shape in strict mode, while array cardinality
    // is validated in the technical Zod pass below. Keeping the decoder's array
    // grammar unconstrained prevents a provider-side failed_generation response.
    answers: { type: "array", items: ritualAnswerJsonShape }
  },
  required: ["id", "question", "answers"]
};
var ritualJsonShape = {
  type: "object",
  additionalProperties: false,
  properties: {
    ritualId: { type: "string" },
    questions: { type: "array", items: ritualQuestionJsonShape }
  },
  required: ["ritualId", "questions"]
};
var oneRitualQuestionSchema = z2.object({ ritualId: z2.string().min(1).max(100), questions: z2.array(ritualQuestionSchema).length(1) });
var ritualContentReason = (ritual) => {
  const ritualIds = /* @__PURE__ */ new Set();
  const questionTexts = /* @__PURE__ */ new Set();
  for (const [questionIndex, question] of ritual.questions.entries()) {
    const questionId = question.id.trim().toLocaleLowerCase("de-DE");
    const questionText = question.question.trim().toLocaleLowerCase("de-DE");
    if (!questionId) return `question[${questionIndex}].id leer`;
    if (ritualIds.has(questionId)) return `question[${questionIndex}].id doppelt`;
    if (questionTexts.has(questionText)) return `question[${questionIndex}].question doppelt`;
    ritualIds.add(questionId);
    questionTexts.add(questionText);
    if (!/[a-zäöüß]/i.test(question.question) || /(klasse|klassenauswahl|wähle eine klasse)/i.test(question.question)) return `question[${questionIndex}] inhaltlich ungeeignet`;
    const answerIds = /* @__PURE__ */ new Set();
    const answerTexts = /* @__PURE__ */ new Set();
    for (const [answerIndex, answer] of question.answers.entries()) {
      const id = answer.id.trim().toLocaleLowerCase("de-DE");
      const text2 = answer.text.trim().toLocaleLowerCase("de-DE");
      if (!text2 || !/[a-zäöüß]/i.test(answer.text)) return `answer[${questionIndex}][${answerIndex}].text leer`;
      if (answerIds.has(id)) return `answer[${questionIndex}][${answerIndex}].id doppelt`;
      if (answerTexts.has(text2)) return `answer[${questionIndex}][${answerIndex}].text doppelt`;
      if (/^\s*(magier|krieger|dieb|heiler|klasse)\s*$/i.test(answer.text)) return `answer[${questionIndex}][${answerIndex}] nennt eine Klasse`;
      answerIds.add(id);
      answerTexts.add(text2);
    }
  }
  return null;
};
var diagnosticFromZod = (error) => error.issues.slice(0, 3).map((issue) => `${issue.path.join(".") || "root"}: ${issue.message}`).join("; ");
var classifyRitualError = (error) => {
  const message = error instanceof Error ? error.message : String(error);
  const upstream = error instanceof GroqHttpError ? error.body.replace(/Bearer\s+[^\s"']+/gi, "Bearer <redacted>").slice(0, 500) : "";
  const status = error instanceof GroqHttpError ? error.status : void 0;
  if (status === 401 || status === 403) return { ok: false, errorCode: "AUTH_ERROR", message: "Das Ritual ist momentan nicht verf\xFCgbar.", diagnostic: `Groq HTTP ${status}` };
  if (status === 429 || /rate limit|429/i.test(message)) return { ok: false, errorCode: "RATE_LIMIT", message: "Das Ritual ist momentan ausgelastet. Bitte erneut versuchen.", diagnostic: `Groq HTTP ${status ?? "429"}` };
  if (/abort|timeout|408|504/i.test(message)) return { ok: false, errorCode: "TIMEOUT", message: "Das Ritual antwortet zu langsam. Bitte erneut versuchen.", diagnostic: message.slice(0, 220) };
  if (status === 400 && /schema|json|failed_generation/i.test(message)) return { ok: false, errorCode: "SCHEMA_ERROR", message: "Das Ritual konnte nicht g\xFCltig vorbereitet werden.", diagnostic: message.slice(0, 300) };
  return { ok: false, errorCode: "PROVIDER_ERROR", message: "Das Ritual ist momentan nicht verf\xFCgbar.", diagnostic: `${message.slice(0, 220)}${upstream ? `; upstream=${upstream}` : ""}` };
};
async function requestStrictRitual(args) {
  try {
    const response = await invokeLLM({
      model: GAME_MASTER_MODEL,
      maxTokens: args.maxTokens,
      temperature: 0.2,
      responseFormat: jsonSchema(args.schemaName, args.schemaShape),
      messages: args.messages
    });
    const raw = collectText(response).trim();
    logRequest({ requestId: args.requestId, route: `ritual:${args.label}`, provider: "groq", model: response.model, httpStatus: response.httpStatus ?? 200, latencyMs: 0, retryCount: Math.max(0, response.attempts - 1), inputTokens: response.usage?.prompt_tokens, outputTokens: response.usage?.completion_tokens });
    if (!raw) {
      console.warn("RITUAL_INVALID_JSON", { label: args.label, reason: "response body empty" });
      return { ok: false, errorCode: "INVALID_JSON", message: "Das Ritual konnte nicht g\xFCltig vorbereitet werden.", diagnostic: "response body empty" };
    }
    let parsedJson;
    try {
      parsedJson = JSON.parse(raw);
    } catch {
      console.warn("RITUAL_INVALID_JSON", { label: args.label, reason: "JSON.parse failed", responseCharacters: raw.length });
      return { ok: false, errorCode: "INVALID_JSON", message: "Das Ritual konnte nicht g\xFCltig vorbereitet werden.", diagnostic: "JSON.parse failed" };
    }
    const parsed = args.schema.safeParse(parsedJson);
    if (!parsed.success) {
      const reason = diagnosticFromZod(parsed.error);
      console.warn("RITUAL_SCHEMA_FAILED", { label: args.label, reason });
      return { ok: false, errorCode: "SCHEMA_ERROR", message: "Das Ritual konnte nicht g\xFCltig vorbereitet werden.", diagnostic: reason };
    }
    return { ok: true, value: parsed.data, model: response.model };
  } catch (error) {
    const failure = classifyRitualError(error);
    logRequest({ requestId: args.requestId, route: `ritual:${args.label}`, provider: "groq", model: GAME_MASTER_MODEL, latencyMs: 0, retryCount: 0, errorCode: failure.errorCode === "AUTH_ERROR" ? "GROQ_AUTH_ERROR" : failure.errorCode === "RATE_LIMIT" ? "GROQ_RATE_LIMIT" : failure.errorCode === "TIMEOUT" ? "BACKEND_TIMEOUT" : failure.errorCode === "SCHEMA_ERROR" ? "GROQ_SCHEMA_ERROR" : "GROQ_PROVIDER_ERROR" });
    return failure;
  }
}
var ritualMessages = (input, purpose) => [
  { role: "system", content: `Du erzeugst das g\xF6ttliche Klassenritual f\xFCr das Fantasy-RPG AVARRA. Deine einzige Aufgabe ist, exakt 10 neue deutsche Entscheidungsfragen zu erstellen, mit denen Pers\xF6nlichkeit, Instinkte, Werte und Probleml\xF6sungsweisen erfasst werden. Jede Frage ist eine konkrete, leicht verst\xE4ndliche Fantasy-Situation mit 25 bis 60 W\xF6rtern und endet mit einer nat\xFCrlichen Entscheidungsaufforderung. Die Fragen d\xFCrfen nicht wie Pers\xF6nlichkeitstests klingen und d\xFCrfen keine Klassen, R\xE4nge, Stats, Waffen, Magieschulen, R\xFCstungen, Kampfstile, Meta-Begriffe, Systeme oder Tests erw\xE4hnen. Jede Frage hat exakt vier glaubw\xFCrdige Handlungen mit 4 bis 18 W\xF6rtern; keine ist offensichtlich richtig oder falsch. Jede Antwort erh\xE4lt 1 bis 2 Signale aus COURAGE, EMPATHY, CURIOSITY, DISCIPLINE, AMBITION, CAUTION, INDEPENDENCE, LOYALTY, CUNNING, PRAGMATISM, JUSTICE, POWER_SEEKING mit Gewicht -2, -1, 1 oder 2. Mische Antwortpositionen und Situationen. Verrate niemals die Seltenheitsstufe, keine Prophezeiungen und keine Sonderbehandlung. Gib ausschlie\xDFlich JSON zur\xFCck. ${purpose === "repair" ? "Ersetze genau die fehlerhafte Frage und halte alle Mengenregeln ein." : purpose === "fresh" ? "Erzeuge vollst\xE4ndig neue Situationen." : "Vermeide die genannten recentThemes."}` },
  { role: "user", content: JSON.stringify({ ritualSeed: input.ritualSeed, hiddenRarityBand: input.hiddenRarityBand, language: "de", recentThemes: input.recentThemes.slice(-4) }) }
];
async function createValidatedRitual(input) {
  const first = await requestStrictRitual({ label: "initial", requestId: input.requestId, schema: ritualSchema, schemaName: "avarra_ritual", schemaShape: ritualJsonShape, maxTokens: 3e3, messages: ritualMessages(input, "initial") });
  if (first.ok) {
    const contentReason = ritualContentReason(first.value);
    if (!contentReason) return first;
    return { ok: false, errorCode: "CONTENT_VALIDATION_ERROR", message: "Das Ritual konnte nicht sinnvoll vorbereitet werden. Bitte erneut versuchen.", diagnostic: contentReason };
  }
  return first;
}
var validateNarrative = (story) => story.narrative.length >= 40 && !/<[^>]+>|\b(DEBUG|PLAN|META|TODO)\b/i.test(story.narrative);
var responseCache = /* @__PURE__ */ new Map();
var CACHE_TTL_MS = 5 * 6e4;
function fromCache(key) {
  const cached = responseCache.get(key);
  if (!cached) return null;
  if (cached.expiresAt < Date.now()) {
    responseCache.delete(key);
    return null;
  }
  return cached.value;
}
function remember(key, value) {
  responseCache.set(key, { expiresAt: Date.now() + CACHE_TTL_MS, value });
  if (responseCache.size > 300) {
    const oldest = responseCache.keys().next().value;
    if (oldest) responseCache.delete(oldest);
  }
  return value;
}
var clipPromptContext = (value, max, fallback = "noch leer") => {
  const normalized = value?.replace(/\s+/g, " ").trim();
  if (!normalized) return fallback;
  return normalized.length <= max ? normalized : `${normalized.slice(-max)} \u2026`;
};
var appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query((opts) => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return { success: true };
    })
  }),
  game: router({
    ritual: publicProcedure.input(z2.object({ ritualSeed: z2.number().int(), hiddenRarityBand: z2.enum(["NORMAL", "UNUSUAL", "RARE", "LEGENDARY", "SSSS"]), recentThemes: z2.array(z2.string().max(80)).max(4).default([]), requestId: z2.string().min(8).max(120).optional() })).mutation(async ({ input }) => {
      const requestId = input.requestId ?? crypto.randomUUID();
      const cached = fromCache(`ritual:${requestId}`);
      if (cached) return cached;
      const result = await createValidatedRitual({ ...input, requestId });
      if (!result.ok) return result;
      return remember(`ritual:${requestId}`, { ok: true, ritualId: result.value.ritualId, questions: result.value.questions, model: result.model });
    }),
    generate: publicProcedure.input(z2.object({
      playerName: z2.string().min(1).max(40),
      className: z2.string().min(1).max(60),
      action: z2.string().min(1).max(800),
      chapter: z2.number().int().min(1),
      recentLog: z2.string().max(3200),
      partyContext: z2.string().max(7e3).optional(),
      originContext: z2.string().max(7e3).optional(),
      worldMemory: z2.string().max(12e3).optional(),
      gender: z2.string().max(30).optional(),
      roll: z2.object({ die: z2.number().int().min(1).max(20), total: z2.number().int(), dc: z2.number().int(), success: z2.boolean(), critical: z2.boolean(), fumble: z2.boolean() }).optional(),
      purpose: z2.enum(["prologue", "turn", "retry"]).default("turn"),
      requestId: z2.string().min(8).max(120).optional(),
      turnId: z2.string().min(8).max(120).optional()
    })).mutation(async ({ input }) => {
      const requestId = input.requestId ?? crypto.randomUUID();
      const turnId = input.turnId ?? crypto.randomUUID();
      const cached = fromCache(`story:${turnId}`);
      if (cached) return cached;
      const systemPrompt = `Du bist der deutschsprachige AI Game Master des Fantasy-Text-RPGs Avarra, angetrieben von Groq.
Du erz\xE4hlst lebendig, atmosph\xE4risch und konsequent. Die mobile App verwaltet Regeln, Savegame, Inventar und W20-Proben.
Antworte ausschlie\xDFlich mit einem validen JSON-Objekt nach folgendem Format:
{
  "narrative": "100-250 W\xF6rter deutscher Erz\xE4hltext in 2. Person (du). Beschreibe konkrete Sinneseindr\xFCcke, Konsequenzen und Dialoge.",
  "scene": { "location": "Ort", "time": "Morgen|Tag|Abend|Nacht", "weather": "Wetter", "situation": "Kurzbeschreibung der Lage" },
  "npcs": [{ "npcId": "id", "name": "Name", "agePresentation": "Alter", "role": "Rolle", "personality": "Charakter", "speechStyle": "Art", "goals": ["Ziel"], "fears": ["Angst"], "morality": "Moral", "faction": "Gilde", "relationship": "Beziehung", "memories": ["Erinnerung"] }],
  "normalActions": [{ "action_id": "a1", "label": "Konkrete Handlung", "type": "explore|dialog|travel|craft|observe", "requiresCheck": false, "stat": "GLK", "modifier": 0, "dc": 10, "risk": "niedrig", "consequenceHint": "Hinweis" }],
  "riskActions": [{ "action_id": "r1", "label": "Riskante Probe", "type": "combat|risk|explore", "requiresCheck": true, "stat": "STR|AUS|AGI|MAG|WIL|GLK", "modifier": 2, "dc": 14, "risk": "mittel|hoch", "consequenceHint": "Was auf dem Spiel steht" }],
  "questEvents": [],
  "rumorEvents": [],
  "npcEvents": [],
  "relationshipEvents": [],
  "worldEvents": [],
  "inventoryEvents": [],
  "progressionEvents": [],
  "codexEvents": [],
  "imageEvent": { "requested": false, "type": "NONE", "importance": 0, "reason": "", "moment": "", "encounter": "" },
  "rollRequest": null
}
Wenn eine W20-Information \xFCbergeben wurde, beschreibe deren Konsequenz direkt in narrative und setze rollRequest auf null.
imageEvent.requested wird nur bei echten H\xF6hepunkten wahr (z.B. schwerer Kampf, Ankunft an mythologischem Ort). Setze type auf NONE und importance auf 0, wenn kein Bild begr\xFCndet ist. requested=true ist nur mit importance >= 0.8 und einer konkreten reason erlaubt.`;
      const result = await requestStructured({
        schema: storyTurnSchema,
        schemaName: "avarra_story_turn",
        schemaShape: storyJsonShape,
        maxTokens: 3800,
        requestId,
        turnId,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: `Zweck: ${input.purpose}
CHARACTER SUMMARY: Name ${input.playerName}; Klasse ${input.className}; Kapitel ${input.chapter}; Geschlecht/Anrede ${input.gender ?? "nicht festgelegt"}
CURRENT LOCATION: ${clipPromptContext(input.originContext, 1200, "unbekannt")}
ACTIVE QUESTS AND RELEVANT NPC MEMORIES: ${clipPromptContext(input.worldMemory, 2400)}
IMPORTANT WORLD STATE: ${clipPromptContext(input.partyContext, 1800)}
LAST RELEVANT EVENTS: ${clipPromptContext(input.recentLog, 2200)}
Lokaler W20-Ausgang: ${input.roll ? JSON.stringify(input.roll) : "kein Wurf"}
PLAYER ACTION: ${clipPromptContext(input.action, 800)}
Keine vollst\xE4ndige Klassenliste, keine komplette Chronik und keine unbest\xE4tigten Regelwerte verwenden.` }
        ]
      });
      if (!result.ok) return result;
      if (!validateNarrative(result.value)) {
        return { ok: false, errorCode: "INVALID_RESPONSE", message: "Der Game Master hat keine g\xFCltige Szene geliefert." };
      }
      const story = {
        ...result.value,
        suggestions: [...result.value.normalActions, ...result.value.riskActions].slice(0, 5),
        consequences: [
          ...result.value.questEvents.map((event) => ({ type: "quest", message: event.message, entityId: event.entityId })),
          ...result.value.rumorEvents.map((event) => ({ type: "world", message: event.message, entityId: event.entityId })),
          ...result.value.npcEvents.map((event) => ({ type: "npc", message: event.message, entityId: event.entityId })),
          ...result.value.relationshipEvents.map((event) => ({ type: "relationship", message: event.message, entityId: event.entityId })),
          ...result.value.worldEvents.map((event) => ({ type: "world", message: event.message, entityId: event.entityId })),
          ...result.value.inventoryEvents.map((event) => ({ type: "inventory", message: event.message, entityId: event.entityId })),
          ...result.value.progressionEvents.map((event) => ({ type: "trait", message: event.message, entityId: event.entityId })),
          ...result.value.codexEvents.map((event) => ({ type: "world", message: event.message, entityId: event.entityId }))
        ].slice(0, 12)
      };
      return remember(`story:${turnId}`, { ok: true, text: story.narrative, generated: true, story, model: result.model });
    }),
    generateImage: publicProcedure.input(z2.object({
      kind: z2.enum(["portrait", "scene"]),
      playerName: z2.string().max(40),
      className: z2.string().max(80),
      gender: z2.string().max(30).optional(),
      hair: z2.string().max(120).optional(),
      expression: z2.string().max(120).optional(),
      feature: z2.string().max(120).optional(),
      description: z2.string().max(800).optional(),
      requestId: z2.string().min(8).max(120).optional(),
      eventId: z2.string().min(8).max(120).optional(),
      moment: z2.string().max(220).optional(),
      encounter: z2.string().max(320).optional()
    })).mutation(async ({ input }) => {
      const requestId = input.requestId ?? crypto.randomUUID();
      const eventId = input.eventId ?? crypto.randomUUID();
      const cached = fromCache(`image:${eventId}`);
      if (cached) return cached;
      const prompt = input.kind === "portrait" ? `Original fantasy RPG character bust portrait, chest-up composition with the entire head, hair, both eyes, complete face, neck, shoulders and upper torso fully visible; centered person, medium camera distance, generous space above the hair, never an extreme close-up, never crop forehead, eyes, chin or shoulders. Character name ${input.playerName}, gender/presentation: ${input.gender ?? "unspecified"}, class ${input.className}, hair: ${input.hair ?? "dark practical hair"}, expression: ${input.expression ?? "focused"}, distinctive feature: ${input.feature ?? "subtle rune scar"}, ${input.description ?? "travel-worn cloak"}. High-quality colored shonen manga style with strong ink lines, refined cel shading, expressive face, cinematic indigo and amber light, clean fantasy background, no text, no logos.` : `Cinematic original fantasy scene in Avarra, moment: ${input.moment ?? "a dangerous revelation"}, encounter: ${input.encounter ?? "no separate encounter; focus on the environment"}, protagonist ${input.playerName} of class ${input.className}, colored shonen manga style, bold ink lines, polished cel shading, dramatic lighting and composition, no text, no logos.`;
      const startedAt = Date.now();
      try {
        const result = await generateImage({ prompt, steps: 4, requestId, imageType: input.kind === "portrait" ? "CHARACTER_PORTRAIT" : "SCENE_ART" });
        logRequest({ requestId, turnId: eventId, route: "generateImage", provider: "backend", model: result.model, httpStatus: 200, latencyMs: Date.now() - startedAt, retryCount: Math.max(0, result.attempts - 1) });
        return result.url ? remember(`image:${eventId}`, { ok: true, status: "SUCCESS", url: result.url, imageId: result.imageId }) : { ok: false, status: "INVALID_IMAGE", url: null };
      } catch (error) {
        const status = error instanceof PollinationsHttpError ? error.status : void 0;
        const message = error instanceof Error ? error.message : String(error);
        const code = error instanceof PollinationsInvalidImageError ? "POLLINATIONS_INVALID_IMAGE" : status === 401 || status === 403 ? "POLLINATIONS_AUTH_ERROR" : status === 402 ? "POLLINATIONS_BUDGET_ERROR" : status === 429 ? "POLLINATIONS_RATE_LIMIT" : status !== void 0 && status >= 500 ? "POLLINATIONS_PROVIDER_ERROR" : /timeout|abort/i.test(message) ? "IMAGE_TIMEOUT" : "POLLINATIONS_SERVER_ERROR";
        const details = error instanceof PollinationsHttpError || error instanceof PollinationsInvalidImageError ? { endpoint: error.endpoint, contentType: error instanceof PollinationsHttpError ? error.contentType : error.contentType, upstreamBody: error.body.slice(0, 500), upstreamLatencyMs: error.latencyMs, upstreamAttempts: error.attempts } : void 0;
        console.warn("POLLINATIONS_DIAGNOSTIC", { requestId, model: ENV.pollinationsImageModel, status, message, ...details });
        logRequest({ requestId, turnId: eventId, route: "generateImage", provider: "backend", model: ENV.pollinationsImageModel, httpStatus: status, latencyMs: Date.now() - startedAt, retryCount: details?.upstreamAttempts ? Math.max(0, details.upstreamAttempts - 1) : 0, errorCode: code });
        return { ok: false, status: code, message: publicMessageFor(code), url: null };
      }
    })
  })
});

// server/_core/context.ts
async function createContext(opts) {
  let user = null;
  try {
    user = await sdk.authenticateRequest(opts.req);
  } catch (error) {
    user = null;
  }
  return {
    req: opts.req,
    res: opts.res,
    user
  };
}

// server/_core/provider-health.ts
var latest = {
  checkedAt: null,
  groqConfigured: false,
  pollinationsConfigured: false,
  groqModel: ENV.groqModel,
  imageModel: ENV.pollinationsImageModel,
  groqModelVerified: null,
  imageModelVerified: null
};
async function verifyProviderHealth() {
  const groqConfigured = Boolean(ENV.groqApiKey);
  const pollinationsConfigured = Boolean(ENV.pollinationsApiKey);
  let groqModelVerified = null;
  let imageModelVerified = null;
  if (groqConfigured) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8e3);
    try {
      const response = await fetch("https://api.groq.com/openai/v1/models", { headers: { authorization: `Bearer ${ENV.groqApiKey}` }, signal: controller.signal });
      if (response.ok) {
        const body = await response.json();
        groqModelVerified = Boolean(body.data?.some((model) => model.id === ENV.groqModel));
      } else groqModelVerified = false;
    } catch {
      groqModelVerified = null;
    } finally {
      clearTimeout(timeout);
    }
  }
  if (pollinationsConfigured) {
    try {
      const response = await fetch("https://gen.pollinations.ai/image/models", { headers: { authorization: `Bearer ${ENV.pollinationsApiKey}`, accept: "application/json" }, signal: AbortSignal.timeout(8e3) });
      if (response.ok) {
        const models = await response.json();
        imageModelVerified = models.some((model) => model.name === ENV.pollinationsImageModel || model.aliases?.includes(ENV.pollinationsImageModel));
      } else imageModelVerified = false;
    } catch {
      imageModelVerified = null;
    }
  }
  latest = { checkedAt: (/* @__PURE__ */ new Date()).toISOString(), groqConfigured, pollinationsConfigured, groqModel: ENV.groqModel, imageModel: ENV.pollinationsImageModel, groqModelVerified, imageModelVerified };
  console.info("AVARRA_PROVIDER_CONFIG", { groqConfigured, pollinationsConfigured, groqModel: ENV.groqModel, imageModel: ENV.pollinationsImageModel, groqModelVerified, imageModelVerified });
  return latest;
}

// server/_core/request-guard.ts
var buckets = /* @__PURE__ */ new Map();
var WINDOW_MS = 6e4;
var TURN_LIMIT = 12;
var IMAGE_LIMIT = 4;
var MAX_BUCKETS = 2e3;
var clientKey = (request) => (request.ip || "anonymous").trim();
var routeKind = (request) => {
  const body = JSON.stringify(request.body ?? "");
  return body.includes("generateImage") ? "image" : "turn";
};
function pruneBuckets(now) {
  if (buckets.size < MAX_BUCKETS) return;
  for (const [key, bucket] of buckets) {
    if (now - bucket.touchedAt > WINDOW_MS * 2) buckets.delete(key);
  }
  while (buckets.size > MAX_BUCKETS) {
    const oldest = buckets.keys().next().value;
    if (!oldest) return;
    buckets.delete(oldest);
  }
}
function guardGameRequests(request, response, next) {
  if (request.method !== "POST") return next();
  const kind = routeKind(request);
  const key = `${kind}:${clientKey(request)}`;
  const now = Date.now();
  const current = buckets.get(key);
  const active = current && now - current.startedAt < WINDOW_MS ? current : { startedAt: now, count: 0, touchedAt: now };
  active.count += 1;
  active.touchedAt = now;
  buckets.set(key, active);
  pruneBuckets(now);
  const limit = kind === "image" ? IMAGE_LIMIT : TURN_LIMIT;
  if (active.count > limit) {
    response.setHeader("Retry-After", String(Math.max(1, Math.ceil((WINDOW_MS - (now - active.startedAt)) / 1e3))));
    response.status(429).json({ error: { code: "TOO_MANY_REQUESTS", message: "Bitte kurz warten und erneut versuchen." } });
    return;
  }
  next();
}

// server/_core/index.ts
function isPortAvailable(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(port, () => server.close(() => resolve(true)));
    server.on("error", () => resolve(false));
  });
}
async function findAvailablePort(startPort = 3e3) {
  for (let port = startPort; port < startPort + 20; port += 1) if (await isPortAvailable(port)) return port;
  throw new Error(`No available port found starting from ${startPort}`);
}
var allowedOrigins = new Set(
  [process.env.WEB_ORIGIN, process.env.EXPO_PUBLIC_WEB_ORIGIN].filter((value) => Boolean(value?.startsWith("https://"))).map((value) => value.replace(/\/$/, ""))
);
function createApp() {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", 1);
  app.use((req, res, next) => {
    const origin = req.headers.origin?.replace(/\/$/, "");
    if (origin && (allowedOrigins.has(origin) || !ENV.isProduction && origin.startsWith("https://"))) {
      res.header("Access-Control-Allow-Origin", origin);
      res.header("Vary", "Origin");
      res.header("Access-Control-Allow-Credentials", "true");
    }
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-Id, X-Turn-Id");
    if (req.method === "OPTIONS") return res.sendStatus(204);
    return next();
  });
  app.use(express.json({ limit: "256kb" }));
  app.use(express.urlencoded({ limit: "32kb", extended: false }));
  registerStorageProxy(app);
  registerOAuthRoutes(app);
  app.get("/api/health", async (_req, res) => {
    const health = await verifyProviderHealth();
    res.status(200).json({
      backend: "ok",
      service: "avarra-game-master",
      buildVersion: process.env.BUILD_VERSION ?? "1.0.0",
      environment: ENV.isProduction ? "production" : "development",
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      groqConfigured: health.groqConfigured,
      pollinationsConfigured: health.pollinationsConfigured,
      groqModel: health.groqModel,
      textModel: health.groqModel,
      imageModel: health.imageModel,
      imageProvider: "pollinations",
      groqModelVerified: health.groqModelVerified,
      imageModelVerified: health.imageModelVerified
    });
  });
  app.use("/api/trpc", guardGameRequests, createExpressMiddleware({ router: appRouter, createContext }));
  void verifyProviderHealth();
  return app;
}
async function startServer() {
  const app = createApp();
  const server = createServer(app);
  const preferredPort = Number.parseInt(process.env.PORT || "3000", 10);
  const port = await findAvailablePort(preferredPort);
  server.listen(port, "0.0.0.0", () => console.log(`[api] server listening on port ${port}`));
  return server;
}
if (process.env.VERCEL !== "1") startServer().catch((error) => {
  console.error("API bootstrap failed", error);
  process.exitCode = 1;
});
export {
  createApp,
  startServer
};
