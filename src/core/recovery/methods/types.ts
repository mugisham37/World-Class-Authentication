/**
 * Types for security questions recovery service
 */

/**
 * Security question interface
 */
export interface SecurityQuestion {
  question: string;
  answer: string;
}

/**
 * Encrypted security question interface
 */
export interface EncryptedSecurityQuestion {
  question: string;
  answer: string; // Encrypted answer
  createdAt: string;
}

/**
 * Security questions setup response
 */
export interface SecurityQuestionsSetupResponse {
  success: boolean;
  count: number;
}

/**
 * User profile interface
 */
export interface UserProfile {
  userId: string;
  metadata: Record<string, any>;
}

/**
 * Verification data for security questions
 */
export interface SecurityQuestionsVerificationData {
  userId: string;
  selectedIndices: number[];
  attempts: number;
  expiresAt: Date;
}

/**
 * Selected question for recovery
 */
export interface SelectedQuestion {
  index: number;
  question: string;
}

/**
 * Options for recovery operations
 */
export interface RecoveryOptions {
  adminId?: string;
  reason?: string;
  [key: string]: any;
}

/**
 * Verification data for admin recovery
 */
export interface AdminRecoveryVerificationData {
  adminId: string;
  adminCode?: string;
  confirmationCode?: string;
}

/**
 * Stored verification data for recovery requests
 */
export interface StoredVerificationData {
  userId: string;
  adminId: string;
  reason: string;
  expiresAt: Date;
}
