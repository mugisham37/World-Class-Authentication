import {
  PrismaClient,
  Credential as PrismaCredential,
  AdminApproval as PrismaAdminApproval,
  AuditLog as PrismaAuditLog,
  MfaChallenge as PrismaMfaChallenge,
  MfaFactor as PrismaMfaFactor,
} from '@prisma/client';

/**
 * Type guard for PrismaCredential
 * Checks if an object is a valid PrismaCredential
 * @param obj The object to check
 * @returns True if the object is a PrismaCredential, false otherwise
 */
export function isPrismaCredential(obj: any): obj is PrismaCredential {
  return (
    obj &&
    typeof obj === 'object' &&
    typeof obj.id === 'string' &&
    typeof obj.userId === 'string' &&
    typeof obj.type === 'string'
  );
}

/**
 * Type guard for PrismaAdminApproval
 * Checks if an object is a valid PrismaAdminApproval
 * @param obj The object to check
 * @returns True if the object is a PrismaAdminApproval, false otherwise
 */
export function isPrismaAdminApproval(obj: any): obj is PrismaAdminApproval {
  return (
    obj &&
    typeof obj === 'object' &&
    typeof obj.id === 'string' &&
    typeof obj.recoveryRequestId === 'string' &&
    typeof obj.adminId === 'string'
  );
}

/**
 * Type guard for PrismaAuditLog
 * Checks if an object is a valid PrismaAuditLog
 * @param obj The object to check
 * @returns True if the object is a PrismaAuditLog, false otherwise
 */
export function isPrismaAuditLog(obj: any): obj is PrismaAuditLog {
  return (
    obj && typeof obj === 'object' && typeof obj.id === 'string' && typeof obj.action === 'string'
  );
}

/**
 * Type guard for PrismaMfaChallenge
 * Checks if an object is a valid PrismaMfaChallenge
 * @param obj The object to check
 * @returns True if the object is a PrismaMfaChallenge, false otherwise
 */
export function isPrismaMfaChallenge(obj: any): obj is PrismaMfaChallenge {
  return (
    obj &&
    typeof obj === 'object' &&
    typeof obj.id === 'string' &&
    typeof obj.factorId === 'string' &&
    typeof obj.challenge === 'string'
  );
}

/**
 * Type guard for PrismaMfaFactor
 * Checks if an object is a valid PrismaMfaFactor
 * @param obj The object to check
 * @returns True if the object is a PrismaMfaFactor, false otherwise
 */
export function isPrismaMfaFactor(obj: any): obj is PrismaMfaFactor {
  return (
    obj &&
    typeof obj === 'object' &&
    typeof obj.id === 'string' &&
    typeof obj.userId === 'string' &&
    typeof obj.type === 'string' &&
    typeof obj.name === 'string'
  );
}

/**
 * Extended Prisma Client type that preserves all model properties
 * This ensures TypeScript recognizes all Prisma models
 */
export interface ExtendedPrismaClient {
  adminApproval: PrismaClient['adminApproval'];
  auditLog: PrismaClient['auditLog'];
  credential: PrismaClient['credential'];
  mfaChallenge: PrismaClient['mfaChallenge'];
  mfaFactor: PrismaClient['mfaFactor'];
  passwordHistory: PrismaClient['passwordHistory'];
  user: PrismaClient['user']; // Explicitly define user property
  session: PrismaClient['session']; // Add session property for completeness
  userProfile: PrismaClient['userProfile']; // Add userProfile property for completeness

  // Transaction method
  $transaction<R>(
    fn: (prisma: ExtendedPrismaClient) => Promise<R>,
    options?: {
      maxWait?: number;
      timeout?: number;
      isolationLevel?: 'ReadUncommitted' | 'ReadCommitted' | 'RepeatableRead' | 'Serializable';
    }
  ): Promise<R>;

  // Basic PrismaClient methods
  $connect(): Promise<void>;
  $disconnect(): Promise<void>;

  // Allow any other property or method
  [key: string]: any;
}
