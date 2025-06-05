import { z } from "zod"

/**
 * Consent schema
 */
export const consentSchema = z.object({
  id: z.string().min(1),
  userId: z.string().min(1),
  clientId: z.string().min(1),
  scopes: z.array(z.string()).default([]),
  expiresAt: z.date(),
  createdAt: z.date().default(() => new Date()),
  updatedAt: z.date().default(() => new Date()),
})

/**
 * Consent type
 */
export type Consent = z.infer<typeof consentSchema>

/**
 * Create consent input schema
 */
export const createConsentSchema = consentSchema.omit({
  id: true,
  createdAt: true,
  updatedAt: true,
})

/**
 * Create consent input type
 */
export type CreateConsentInput = z.infer<typeof createConsentSchema>

/**
 * Update consent input schema
 */
export const updateConsentSchema = z.object({
  scopes: z.array(z.string()).optional(),
  expiresAt: z.date().optional(),
})

/**
 * Update consent input type
 */
export type UpdateConsentInput = z.infer<typeof updateConsentSchema>
