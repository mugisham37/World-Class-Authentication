import { z } from 'zod';

/**
 * Token type enum
 */
export enum TokenType {
  ACCESS_TOKEN = 'access_token',
  REFRESH_TOKEN = 'refresh_token',
  ID_TOKEN = 'id_token',
  AUTHORIZATION_CODE = 'authorization_code',
  DEVICE_CODE = 'device_code',
}

/**
 * Token schema
 */
export const tokenSchema = z.object({
  id: z.string().min(1),
  clientId: z.string().min(1),
  userId: z.string().optional(),
  type: z.nativeEnum(TokenType),
  value: z.string().min(1),
  scopes: z.array(z.string()).default([]),
  expiresAt: z.date(),
  issuedAt: z.date().default(() => new Date()),
  revokedAt: z.date().optional(),
  previousToken: z.string().optional(),
  authTime: z.date().optional(),
  nonce: z.string().optional(),
  audience: z.array(z.string()).default([]),
  codeChallenge: z.string().optional(),
  codeChallengeMethod: z.enum(['plain', 'S256']).optional(),
  redirectUri: z.string().optional(),
  deviceCode: z.string().optional(),
  userCode: z.string().optional(),
  metadata: z.record(z.any()).optional(),
});

/**
 * Token type
 */
export type Token = z.infer<typeof tokenSchema>;

/**
 * Create token input schema
 */
export const createTokenSchema = tokenSchema.omit({
  id: true,
  issuedAt: true,
});

/**
 * Create token input type
 */
export type CreateTokenInput = z.infer<typeof createTokenSchema>;

/**
 * Update token input schema
 */
export const updateTokenSchema = z.object({
  revokedAt: z.date().optional(),
  metadata: z.record(z.any()).optional(),
});

/**
 * Update token input type
 */
export type UpdateTokenInput = z.infer<typeof updateTokenSchema>;
