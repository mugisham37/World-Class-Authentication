import dotenv from "dotenv"
import path from "path"
import { validateConfig } from "../../utils/validation"
import { z } from "zod"

// Load environment variables from .env file
dotenv.config({ path: path.resolve(process.cwd(), ".env") })

// Define OAuth config schema with Zod
const oauthConfigSchema = z.object({
  clientSecretSalt: z.string().default("default-salt"),
  server: z.object({
    issuer: z.string().default("https://auth.example.com"),
    authorizationEndpoint: z.string().default("/oauth/authorize"),
    tokenEndpoint: z.string().default("/oauth/token"),
    jwksEndpoint: z.string().default("/.well-known/jwks.json"),
    userinfoEndpoint: z.string().default("/oauth/userinfo"),
    revocationEndpoint: z.string().default("/oauth/revoke"),
    introspectionEndpoint: z.string().default("/oauth/introspect"),
    endSessionEndpoint: z.string().default("/oauth/logout"),
    registrationEndpoint: z.string().optional(),
    discoveryEndpoint: z.string().default("/.well-known/openid-configuration"),
  }),
  tokens: z.object({
    accessToken: z.object({
      expiresIn: z.number().int().positive().default(3600), // 1 hour
      algorithm: z.enum(["RS256", "HS256"]).default("RS256"),
      privateKey: z.string().optional(),
      publicKey: z.string().optional(),
      secret: z.string().optional(),
    }),
    refreshToken: z.object({
      expiresIn: z.number().int().positive().default(2592000), // 30 days
      length: z.number().int().positive().default(64),
      rotationEnabled: z.boolean().default(true),
      rotationWindow: z.number().int().positive().default(86400), // 1 day
    }),
    idToken: z.object({
      expiresIn: z.number().int().positive().default(3600), // 1 hour
      algorithm: z.enum(["RS256", "HS256"]).default("RS256"),
    }),
    authorizationCode: z.object({
      expiresIn: z.number().int().positive().default(60), // 1 minute
      length: z.number().int().positive().default(32),
    }),
  }),
  clients: z.object({
    dynamicRegistration: z.boolean().default(false),
    allowWildcardRedirectUris: z.boolean().default(false),
    requirePkce: z.boolean().default(true),
    defaultScopes: z.array(z.string()).default(["openid", "profile", "email"]),
    allowedScopes: z.array(z.string()).default(["openid", "profile", "email", "address", "phone", "offline_access"]),
    allowedGrantTypes: z.array(z.string()).default(["authorization_code", "refresh_token", "client_credentials"]),
    allowedResponseTypes: z.array(z.string()).default(["code", "token", "id_token"]),
  }),
  features: z.object({
    pkce: z.object({
      enabled: z.boolean().default(true),
      forcePkceForPublicClients: z.boolean().default(true),
    }),
    jwtAccessTokens: z.boolean().default(true),
    refreshTokenRotation: z.boolean().default(true),
    introspection: z.boolean().default(true),
    revocation: z.boolean().default(true),
    deviceFlow: z.boolean().default(false),
    clientCredentials: z.boolean().default(true),
    implicitFlow: z.boolean().default(false),
  }),
  oidc: z.object({
    enabled: z.boolean().default(true),
    subjectTypes: z.array(z.enum(["public", "pairwise"])).default(["public"]),
    defaultAcrValues: z.array(z.string()).default([]),
    supportedClaims: z
      .array(z.string())
      .default([
        "sub",
        "name",
        "given_name",
        "family_name",
        "middle_name",
        "nickname",
        "preferred_username",
        "profile",
        "picture",
        "website",
        "email",
        "email_verified",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "phone_number",
        "phone_number_verified",
        "address",
        "updated_at",
      ]),
    idTokenSigningAlgs: z.array(z.string()).default(["RS256"]),
  }),
  consent: z.object({
    enabled: z.boolean().default(true),
    expiration: z
      .number()
      .int()
      .positive()
      .default(30 * 24 * 60 * 60), // 30 days
    implicitForFirstParty: z.boolean().default(true),
  }),
  session: z.object({
    cookieName: z.string().default("oauth_session"),
    cookieMaxAge: z
      .number()
      .int()
      .positive()
      .default(24 * 60 * 60 * 1000), // 24 hours
    cookieSecure: z.boolean().default(true),
    cookieHttpOnly: z.boolean().default(true),
    cookieSameSite: z.enum(["strict", "lax", "none"]).default("lax"),
  }),
})

// Parse and validate environment variables
const rawConfig = {
  clientSecretSalt: process.env["OAUTH_CLIENT_SECRET_SALT"],
  server: {
    issuer: process.env["OAUTH_ISSUER"],
    authorizationEndpoint: process.env["OAUTH_AUTHORIZATION_ENDPOINT"],
    tokenEndpoint: process.env["OAUTH_TOKEN_ENDPOINT"],
    jwksEndpoint: process.env["OAUTH_JWKS_ENDPOINT"],
    userinfoEndpoint: process.env["OAUTH_USERINFO_ENDPOINT"],
    revocationEndpoint: process.env["OAUTH_REVOCATION_ENDPOINT"],
    introspectionEndpoint: process.env["OAUTH_INTROSPECTION_ENDPOINT"],
    endSessionEndpoint: process.env["OAUTH_END_SESSION_ENDPOINT"],
    registrationEndpoint: process.env["OAUTH_REGISTRATION_ENDPOINT"],
    discoveryEndpoint: process.env["OAUTH_DISCOVERY_ENDPOINT"],
  },
  tokens: {
    accessToken: {
      expiresIn: Number(process.env["OAUTH_ACCESS_TOKEN_EXPIRES_IN"]),
      algorithm: process.env["OAUTH_ACCESS_TOKEN_ALGORITHM"] as "RS256" | "HS256",
      privateKey: process.env["OAUTH_PRIVATE_KEY"],
      publicKey: process.env["OAUTH_PUBLIC_KEY"],
      secret: process.env["OAUTH_TOKEN_SECRET"],
    },
    refreshToken: {
      expiresIn: Number(process.env["OAUTH_REFRESH_TOKEN_EXPIRES_IN"]),
      length: Number(process.env["OAUTH_REFRESH_TOKEN_LENGTH"]),
      rotationEnabled: process.env["OAUTH_REFRESH_TOKEN_ROTATION_ENABLED"] === "true",
      rotationWindow: Number(process.env["OAUTH_REFRESH_TOKEN_ROTATION_WINDOW"]),
    },
    idToken: {
      expiresIn: Number(process.env["OAUTH_ID_TOKEN_EXPIRES_IN"]),
      algorithm: process.env["OAUTH_ID_TOKEN_ALGORITHM"] as "RS256" | "HS256",
    },
    authorizationCode: {
      expiresIn: Number(process.env["OAUTH_AUTHORIZATION_CODE_EXPIRES_IN"]),
      length: Number(process.env["OAUTH_AUTHORIZATION_CODE_LENGTH"]),
    },
  },
  clients: {
    dynamicRegistration: process.env["OAUTH_DYNAMIC_REGISTRATION"] === "true",
    allowWildcardRedirectUris: process.env["OAUTH_ALLOW_WILDCARD_REDIRECT_URIS"] === "true",
    requirePkce: process.env["OAUTH_REQUIRE_PKCE"] !== "false",
    defaultScopes: process.env["OAUTH_DEFAULT_SCOPES"]?.split(","),
    allowedScopes: process.env["OAUTH_ALLOWED_SCOPES"]?.split(","),
    allowedGrantTypes: process.env["OAUTH_ALLOWED_GRANT_TYPES"]?.split(","),
    allowedResponseTypes: process.env["OAUTH_ALLOWED_RESPONSE_TYPES"]?.split(","),
  },
  features: {
    pkce: {
      enabled: process.env["OAUTH_PKCE_ENABLED"] !== "false",
      forcePkceForPublicClients: process.env["OAUTH_FORCE_PKCE_FOR_PUBLIC_CLIENTS"] !== "false",
    },
    jwtAccessTokens: process.env["OAUTH_JWT_ACCESS_TOKENS"] !== "false",
    refreshTokenRotation: process.env["OAUTH_REFRESH_TOKEN_ROTATION"] !== "false",
    introspection: process.env["OAUTH_INTROSPECTION_ENABLED"] !== "false",
    revocation: process.env["OAUTH_REVOCATION_ENABLED"] !== "false",
    deviceFlow: process.env["OAUTH_DEVICE_FLOW_ENABLED"] === "true",
    clientCredentials: process.env["OAUTH_CLIENT_CREDENTIALS_ENABLED"] !== "false",
    implicitFlow: process.env["OAUTH_IMPLICIT_FLOW_ENABLED"] === "true",
  },
  oidc: {
    enabled: process.env["OIDC_ENABLED"] !== "false",
    subjectTypes: process.env["OIDC_SUBJECT_TYPES"]?.split(",") as ("public" | "pairwise")[],
    defaultAcrValues: process.env["OIDC_DEFAULT_ACR_VALUES"]?.split(","),
    supportedClaims: process.env["OIDC_SUPPORTED_CLAIMS"]?.split(","),
    idTokenSigningAlgs: process.env["OIDC_ID_TOKEN_SIGNING_ALGS"]?.split(","),
  },
  consent: {
    enabled: process.env["OAUTH_CONSENT_ENABLED"] !== "false",
    expiration: Number(process.env["OAUTH_CONSENT_EXPIRATION"]),
    implicitForFirstParty: process.env["OAUTH_IMPLICIT_CONSENT_FOR_FIRST_PARTY"] !== "false",
  },
  session: {
    cookieName: process.env["OAUTH_SESSION_COOKIE_NAME"],
    cookieMaxAge: Number(process.env["OAUTH_SESSION_COOKIE_MAX_AGE"]),
    cookieSecure: process.env["OAUTH_SESSION_COOKIE_SECURE"] !== "false",
    cookieHttpOnly: process.env["OAUTH_SESSION_COOKIE_HTTP_ONLY"] !== "false",
    cookieSameSite: process.env["OAUTH_SESSION_COOKIE_SAME_SITE"] as "strict" | "lax" | "none",
  },
}

// Validate and export config
export const oauthConfig = validateConfig(oauthConfigSchema, rawConfig)

// Export config type
export type OAuthConfig = typeof oauthConfig
