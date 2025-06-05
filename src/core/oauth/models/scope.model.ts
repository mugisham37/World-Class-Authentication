import { z } from "zod"

/**
 * Scope schema
 */
export const scopeSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  displayName: z.string().min(1),
  description: z.string().optional(),
  iconUrl: z.string().url().optional(),
  claims: z.array(z.string()).default([]),
  isDefault: z.boolean().default(false),
  isOpenId: z.boolean().default(false),
  createdAt: z.date().default(() => new Date()),
  updatedAt: z.date().default(() => new Date()),
})

/**
 * Scope type
 */
export type Scope = z.infer<typeof scopeSchema>

/**
 * Create scope input schema
 */
export const createScopeSchema = scopeSchema.omit({
  id: true,
  createdAt: true,
  updatedAt: true,
})

/**
 * Create scope input type
 */
export type CreateScopeInput = z.infer<typeof createScopeSchema>

/**
 * Update scope input schema
 */
export const updateScopeSchema = createScopeSchema.partial()

/**
 * Update scope input type
 */
export type UpdateScopeInput = z.infer<typeof updateScopeSchema>
