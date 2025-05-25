/**
 * Security question model interface
 * Represents a security question in the system
 */
export interface SecurityQuestion {
  id: string;
  userId: string;
  question: string;
  answerHash: string;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Create security question data interface
 * Represents the data needed to create a new security question
 */
export interface CreateSecurityQuestionData {
  userId: string;
  question: string;
  answerHash: string;
}

/**
 * Update security question data interface
 * Represents the data needed to update an existing security question
 */
export interface UpdateSecurityQuestionData {
  question?: string;
  answerHash?: string;
}

/**
 * Security question filter options interface
 * Represents the options for filtering security questions
 */
export interface SecurityQuestionFilterOptions {
  id?: string;
  userId?: string;
  createdAtBefore?: Date;
  createdAtAfter?: Date;
  updatedAtBefore?: Date;
  updatedAtAfter?: Date;
}

/**
 * Security question verification result interface
 * Represents the result of verifying a security question answer
 */
export interface SecurityQuestionVerificationResult {
  success: boolean;
  message?: string;
}
