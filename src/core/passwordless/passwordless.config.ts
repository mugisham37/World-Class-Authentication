import dotenv from "dotenv"
import path from "path"
import { validateConfig } from "../../utils/validation"
import { z } from "zod"

// Load environment variables from .env file
dotenv.config({ path: path.resolve(process.cwd(), ".env") })

// Define passwordless config schema with Zod
const passwordlessConfigSchema = z.object({
  webauthn: z.object({
    enabled: z.boolean().default(true),
    rpName: z.string().default("Auth System"),
    rpId: z.string().optional(),
    origin: z.string().optional(),
    challengeSize: z.number().int().positive().default(32),
    timeout: z.number().int().positive().default(60000), // 1 minute
    attestation: z.enum(["none", "indirect", "direct"]).default("none"),
    authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
    userVerification: z.enum(["required", "preferred", "discouraged"]).default("preferred"),
    credentialTimeout: z
      .number()
      .int()
      .positive()
      .default(60 * 60 * 24 * 90), // 90 days
  }),
  magicLink: z.object({
    enabled: z.boolean().default(true),
    tokenLength: z.number().int().positive().default(32),
    tokenExpiration: z
      .number()
      .int()
      .positive()
      .default(15 * 60), // 15 minutes
    deliveryMethod: z.enum(["email", "sms", "both"]).default("email"),
    allowedDomains: z.array(z.string()).default([]),
    maxTokensPerUser: z.number().int().positive().default(3),
    reuseWindow: z.number().int().nonnegative().default(60), // 1 minute
    requireVerifiedEmail: z.boolean().default(false),
  }),
  emailOtp: z.object({
    enabled: z.boolean().default(true),
    codeLength: z.number().int().min(4).max(8).default(6),
    codeExpiration: z
      .number()
      .int()
      .positive()
      .default(15 * 60), // 15 minutes
    codeType: z.enum(["numeric", "alphanumeric"]).default("numeric"),
    maxAttempts: z.number().int().positive().default(5),
    requireVerifiedEmail: z.boolean().default(true),
    rateLimit: z.object({
      window: z
        .number()
        .int()
        .positive()
        .default(60 * 60), // 1 hour
      max: z.number().int().positive().default(5),
    }),
  }),
  smsOtp: z.object({
    enabled: z.boolean().default(true),
    codeLength: z.number().int().min(4).max(8).default(6),
    codeExpiration: z
      .number()
      .int()
      .positive()
      .default(15 * 60), // 15 minutes
    codeType: z.enum(["numeric", "alphanumeric"]).default("numeric"),
    maxAttempts: z.number().int().positive().default(5),
    requireVerifiedPhone: z.boolean().default(true),
    rateLimit: z.object({
      window: z
        .number()
        .int()
        .positive()
        .default(60 * 60), // 1 hour
      max: z.number().int().positive().default(5),
    }),
    providers: z.array(z.enum(["twilio", "aws-sns", "custom"])).default(["twilio"]),
  }),
  certificateAuth: z.object({
    enabled: z.boolean().default(false),
    trustedCAs: z.array(z.string()).default([]),
    subjectDNPattern: z.string().optional(),
    issuerDNPattern: z.string().optional(),
    verifyRevocation: z.boolean().default(true),
    allowSelfSigned: z.boolean().default(false),
  }),
  biometric: z.object({
    enabled: z.boolean().default(true),
    // This is essentially WebAuthn, but with platform authenticator
    requireResidentKey: z.boolean().default(true),
    timeout: z.number().int().positive().default(60000), // 60 seconds
    userVerification: z.enum(["required", "preferred", "discouraged"]).default("required"),
    authenticatorAttachment: z.enum(["platform", "cross-platform"]).default("platform"),
    attestation: z.enum(["none", "indirect", "direct"]).default("none"),
  }),
  session: z.object({
    cookieName: z.string().default("passwordless_session"),
    cookieMaxAge: z
      .number()
      .int()
      .positive()
      .default(15 * 60 * 1000), // 15 minutes
    cookieSecure: z.boolean().default(true),
    cookieHttpOnly: z.boolean().default(true),
    cookieSameSite: z.enum(["strict", "lax", "none"]).default("lax"),
    duration: z.number().int().positive().default(24 * 60 * 60), // 24 hours
  }),
})

// Parse and validate environment variables
const rawConfig = {
  webauthn: {
    enabled: process.env["PASSWORDLESS_WEBAUTHN_ENABLED"] !== "false",
    rpName: process.env["PASSWORDLESS_WEBAUTHN_RP_NAME"],
    rpId: process.env["PASSWORDLESS_WEBAUTHN_RP_ID"],
    origin: process.env["PASSWORDLESS_WEBAUTHN_ORIGIN"],
    challengeSize: Number(process.env["PASSWORDLESS_WEBAUTHN_CHALLENGE_SIZE"]),
    timeout: Number(process.env["PASSWORDLESS_WEBAUTHN_TIMEOUT"]),
    attestation: process.env["PASSWORDLESS_WEBAUTHN_ATTESTATION"] as "none" | "indirect" | "direct",
    authenticatorAttachment: process.env["PASSWORDLESS_WEBAUTHN_AUTHENTICATOR_ATTACHMENT"] as
      | "platform"
      | "cross-platform"
      | undefined,
    userVerification: process.env["PASSWORDLESS_WEBAUTHN_USER_VERIFICATION"] as "required" | "preferred" | "discouraged",
    credentialTimeout: Number(process.env["PASSWORDLESS_WEBAUTHN_CREDENTIAL_TIMEOUT"]),
  },
  magicLink: {
    enabled: process.env["PASSWORDLESS_MAGIC_LINK_ENABLED"] !== "false",
    tokenLength: Number(process.env["PASSWORDLESS_MAGIC_LINK_TOKEN_LENGTH"]),
    tokenExpiration: Number(process.env["PASSWORDLESS_MAGIC_LINK_TOKEN_EXPIRATION"]),
    deliveryMethod: process.env["PASSWORDLESS_MAGIC_LINK_DELIVERY_METHOD"] as "email" | "sms" | "both",
    allowedDomains: process.env["PASSWORDLESS_MAGIC_LINK_ALLOWED_DOMAINS"]?.split(","),
    maxTokensPerUser: Number(process.env["PASSWORDLESS_MAGIC_LINK_MAX_TOKENS_PER_USER"]),
    reuseWindow: Number(process.env["PASSWORDLESS_MAGIC_LINK_REUSE_WINDOW"]),
    requireVerifiedEmail: process.env["PASSWORDLESS_MAGIC_LINK_REQUIRE_VERIFIED_EMAIL"] !== "false",
  },
  emailOtp: {
    enabled: process.env["PASSWORDLESS_EMAIL_OTP_ENABLED"] !== "false",
    codeLength: Number(process.env["PASSWORDLESS_EMAIL_OTP_CODE_LENGTH"]),
    codeExpiration: Number(process.env["PASSWORDLESS_EMAIL_OTP_CODE_EXPIRATION"]),
    codeType: process.env["PASSWORDLESS_EMAIL_OTP_CODE_TYPE"] as "numeric" | "alphanumeric",
    maxAttempts: Number(process.env["PASSWORDLESS_EMAIL_OTP_MAX_ATTEMPTS"]),
    requireVerifiedEmail: process.env["PASSWORDLESS_EMAIL_OTP_REQUIRE_VERIFIED_EMAIL"] !== "false",
    rateLimit: {
      window: Number(process.env["PASSWORDLESS_EMAIL_OTP_RATE_LIMIT_WINDOW"]),
      max: Number(process.env["PASSWORDLESS_EMAIL_OTP_RATE_LIMIT_MAX"]),
    },
  },
  smsOtp: {
    enabled: process.env["PASSWORDLESS_SMS_OTP_ENABLED"] !== "false",
    codeLength: Number(process.env["PASSWORDLESS_SMS_OTP_CODE_LENGTH"]),
    codeExpiration: Number(process.env["PASSWORDLESS_SMS_OTP_CODE_EXPIRATION"]),
    codeType: process.env["PASSWORDLESS_SMS_OTP_CODE_TYPE"] as "numeric" | "alphanumeric",
    maxAttempts: Number(process.env["PASSWORDLESS_SMS_OTP_MAX_ATTEMPTS"]),
    requireVerifiedPhone: process.env["PASSWORDLESS_SMS_OTP_REQUIRE_VERIFIED_PHONE"] !== "false",
    rateLimit: {
      window: Number(process.env["PASSWORDLESS_SMS_OTP_RATE_LIMIT_WINDOW"]),
      max: Number(process.env["PASSWORDLESS_SMS_OTP_RATE_LIMIT_MAX"]),
    },
    providers: process.env["PASSWORDLESS_SMS_OTP_PROVIDERS"]?.split(",") as ("twilio" | "aws-sns" | "custom")[],
  },
  certificateAuth: {
    enabled: process.env["PASSWORDLESS_CERTIFICATE_AUTH_ENABLED"] === "true",
    trustedCAs: process.env["PASSWORDLESS_CERTIFICATE_AUTH_TRUSTED_CAS"]?.split(","),
    subjectDNPattern: process.env["PASSWORDLESS_CERTIFICATE_AUTH_SUBJECT_DN_PATTERN"],
    issuerDNPattern: process.env["PASSWORDLESS_CERTIFICATE_AUTH_ISSUER_DN_PATTERN"],
    verifyRevocation: process.env["PASSWORDLESS_CERTIFICATE_AUTH_VERIFY_REVOCATION"] !== "false",
    allowSelfSigned: process.env["PASSWORDLESS_CERTIFICATE_AUTH_ALLOW_SELF_SIGNED"] === "true",
  },
  biometric: {
    enabled: process.env["PASSWORDLESS_BIOMETRIC_ENABLED"] !== "false",
    requireResidentKey: process.env["PASSWORDLESS_BIOMETRIC_REQUIRE_RESIDENT_KEY"] !== "false",
    timeout: Number(process.env["PASSWORDLESS_BIOMETRIC_TIMEOUT"]),
    userVerification: process.env["PASSWORDLESS_BIOMETRIC_USER_VERIFICATION"] as "required" | "preferred" | "discouraged",
    authenticatorAttachment: process.env["PASSWORDLESS_BIOMETRIC_AUTHENTICATOR_ATTACHMENT"] as "platform" | "cross-platform",
    attestation: process.env["PASSWORDLESS_BIOMETRIC_ATTESTATION"] as "none" | "indirect" | "direct",
  },
  session: {
    cookieName: process.env["PASSWORDLESS_SESSION_COOKIE_NAME"],
    cookieMaxAge: Number(process.env["PASSWORDLESS_SESSION_COOKIE_MAX_AGE"]),
    cookieSecure: process.env["PASSWORDLESS_SESSION_COOKIE_SECURE"] !== "false",
    cookieHttpOnly: process.env["PASSWORDLESS_SESSION_COOKIE_HTTP_ONLY"] !== "false",
    cookieSameSite: process.env["PASSWORDLESS_SESSION_COOKIE_SAME_SITE"] as "strict" | "lax" | "none",
    duration: Number(process.env["PASSWORDLESS_SESSION_DURATION"]),
  },
}

// Validate and export config
export const passwordlessConfig = validateConfig(passwordlessConfigSchema, rawConfig)

// Export config type
export type PasswordlessConfig = typeof passwordlessConfig
