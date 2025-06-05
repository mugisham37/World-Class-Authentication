import { z } from "zod"

/**
 * OAuth client types
 */
export enum ClientType {
  CONFIDENTIAL = "confidential",
  PUBLIC = "public",
}

/**
 * OAuth client authentication methods
 */
export enum ClientAuthMethod {
  CLIENT_SECRET_BASIC = "client_secret_basic",
  CLIENT_SECRET_POST = "client_secret_post",
  CLIENT_SECRET_JWT = "client_secret_jwt",
  PRIVATE_KEY_JWT = "private_key_jwt",
  NONE = "none",
}

/**
 * OAuth client schema
 */
export const clientSchema = z.object({
  id: z.string().min(1),
  secret: z.string().optional(),
  secretHash: z.string().optional(),
  name: z.string().min(1),
  description: z.string().optional(),
  clientType: z.nativeEnum(ClientType),
  authMethod: z.nativeEnum(ClientAuthMethod),
  redirectUris: z.array(z.string().url()).default([]),
  postLogoutRedirectUris: z.array(z.string().url()).default([]),
  allowedGrantTypes: z.array(z.string()).default([]),
  allowedResponseTypes: z.array(z.string()).default([]),
  allowedScopes: z.array(z.string()).default([]),
  defaultScopes: z.array(z.string()).default([]),
  requirePkce: z.boolean().default(false),
  requireSignedRequestObject: z.boolean().default(false),
  requireUserConsent: z.boolean().default(true),
  isFirstParty: z.boolean().default(false),
  jwksUri: z.string().url().optional(),
  jwks: z.record(z.any()).optional(),
  logoUri: z.string().url().optional(),
  policyUri: z.string().url().optional(),
  tosUri: z.string().url().optional(),
  contacts: z.array(z.string().email()).default([]),
  subjectType: z.enum(["public", "pairwise"]).default("public"),
  idTokenSignedResponseAlg: z.string().default("RS256"),
  idTokenEncryptedResponseAlg: z.string().optional(),
  idTokenEncryptedResponseEnc: z.string().optional(),
  userinfoSignedResponseAlg: z.string().optional(),
  userinfoEncryptedResponseAlg: z.string().optional(),
  userinfoEncryptedResponseEnc: z.string().optional(),
  requestObjectSigningAlg: z.string().optional(),
  requestObjectEncryptionAlg: z.string().optional(),
  requestObjectEncryptionEnc: z.string().optional(),
  tokenEndpointAuthSigningAlg: z.string().optional(),
  defaultMaxAge: z.number().int().positive().optional(),
  requireAuthTime: z.boolean().default(false),
  defaultAcrValues: z.array(z.string()).default([]),
  initiateLoginUri: z.string().url().optional(),
  softwareId: z.string().optional(),
  softwareVersion: z.string().optional(),
  isActive: z.boolean().default(true),
  createdAt: z.date().default(() => new Date()),
  updatedAt: z.date().default(() => new Date()),
  metadata: z.record(z.any()).optional(),
})

/**
 * OAuth client type
 */
export type Client = z.infer<typeof clientSchema>

/**
 * Create client input schema
 */
export const createClientSchema = clientSchema.omit({
  id: true,
  createdAt: true,
  updatedAt: true,
})

/**
 * Create client input type
 */
export type CreateClientInput = z.infer<typeof createClientSchema>

/**
 * Update client input schema
 */
export const updateClientSchema = createClientSchema.partial()

/**
 * Update client input type
 */
export type UpdateClientInput = z.infer<typeof updateClientSchema>
