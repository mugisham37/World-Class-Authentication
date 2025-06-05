import { Injectable } from "@tsed/di";
import { recoveryConfig } from "../../../config/recovery.config";
import { RecoveryMethodStatus } from "../../../data/models/recovery-method.model";
import { auditLogRepository } from "../../../data/repositories/audit-log.repository";
import { recoveryMethodRepository } from "../../../data/repositories/recovery-method.repository";
import { recoveryRequestRepository } from "../../../data/repositories/recovery-request.repository";
import { userProfileRepository } from "../../../data/repositories/user-profile.repository";
import { userRepository } from "../../../data/repositories/user.repository";
import { logger } from "../../../infrastructure/logging/logger";
import { encryption } from "../../../infrastructure/security/crypto/encryption";
import { BadRequestError, NotFoundError } from "../../../utils/error-handling";
import {
  BaseRecoveryMethod,
  RecoveryInitiationResult,
  RecoveryMethodType,
  RecoveryVerificationResult,
} from "../recovery-method";
import {
  EncryptedSecurityQuestion,
  SecurityQuestion,
  SecurityQuestionsSetupResponse,
  SecurityQuestionsVerificationData,
  SelectedQuestion
} from "./types";

/**
 * Security questions recovery service
 * Implements security question-based account recovery
 */
@Injectable()
export class SecurityQuestionsService extends BaseRecoveryMethod {
  /**
   * The type of recovery method
   */
  protected readonly type = RecoveryMethodType.SECURITY_QUESTIONS;

  /**
   * In-memory verification data storage (replace with Redis in production)
   * Maps requestId to verification data
   */
  private verificationData: Map<string, SecurityQuestionsVerificationData> = new Map();

  /**
   * Check if security questions recovery is available for a user
   * @param userId User ID
   * @returns True if security questions recovery is available
   */
  async isAvailableForUser(userId: string): Promise<boolean> {
    try {
      // Get user profile
      const profile = await userProfileRepository.findByUserId(userId);
      if (!profile) {
        return false;
      }

      // Check if security questions are set up
      const metadata = profile.metadata as Record<string, any> | null;
      if (!metadata || !metadata['securityQuestions'] || !Array.isArray(metadata['securityQuestions'])) {
        return false;
      }

      // Check if there are enough security questions
      return metadata['securityQuestions'].length >= recoveryConfig.securityQuestions.minQuestions;
    } catch (error) {
      logger.error("Failed to check if security questions recovery is available", { error, userId });
      return false;
    }
  }

  /**
   * Register security questions recovery for a user
   * @param userId User ID
   * @param name Name for the recovery method
   * @param data Additional method-specific data
   * @returns ID of the created recovery method
   */
  async register(userId: string, name: string, data: Record<string, any> = {}): Promise<string> {
    try {
      // Check if user exists
      const user = await userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError("User not found");
      }

      // Check if security questions are set up
      const profile = await userProfileRepository.findByUserId(userId);
      if (!profile) {
        throw new NotFoundError("User profile not found");
      }

      const metadata = profile.metadata as Record<string, any> | null;
      if (!metadata || !metadata['securityQuestions'] || !Array.isArray(metadata['securityQuestions'])) {
        throw new BadRequestError("Security questions must be set up before registering this recovery method");
      }

      if (metadata['securityQuestions'].length < recoveryConfig.securityQuestions.minQuestions) {
        throw new BadRequestError(
          `At least ${recoveryConfig.securityQuestions.minQuestions} security questions are required`
        );
      }

      // Create recovery method
      const method = await recoveryMethodRepository.create({
        userId,
        type: RecoveryMethodType.SECURITY_QUESTIONS,
        name: name || "Security Questions Recovery",
        status: RecoveryMethodStatus.ACTIVE,
        metadata: {
          questionCount: metadata['securityQuestions'].length,
          ...data,
        },
      });

      // Log the registration
      await auditLogRepository.create({
        userId,
        action: "RECOVERY_METHOD_REGISTERED",
        entityType: "RECOVERY_METHOD",
        entityId: method.id,
        metadata: {
          type: RecoveryMethodType.SECURITY_QUESTIONS,
          name: method.name,
          questionCount: metadata['securityQuestions'].length,
        },
      });

      return method.id;
    } catch (error) {
      logger.error("Failed to register security questions recovery", { error, userId });
      throw error;
    }
  }

  /**
   * Initiate security questions recovery
   * @param userId User ID
   * @param requestId Recovery request ID
   * @returns Recovery data
   */
  async initiateRecovery(
    userId: string,
    requestId: string
  ): Promise<RecoveryInitiationResult> {
    try {
      // Get user
      const user = await userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError("User not found");
      }

      // Get user profile
      const profile = await userProfileRepository.findByUserId(userId);
      if (!profile) {
        throw new NotFoundError("User profile not found");
      }

      // Get security questions
      const metadata = profile.metadata as Record<string, any> | null;
      if (!metadata || !metadata['securityQuestions'] || !Array.isArray(metadata['securityQuestions'])) {
        throw new BadRequestError("Security questions not set up");
      }

      // Get recovery request
      const request = await recoveryRequestRepository.findById(requestId);
      if (!request) {
        throw new NotFoundError("Recovery request not found");
      }

      // Select a subset of questions to ask
      const questions = metadata['securityQuestions'] as any[];
      const questionsToAsk = Math.min(recoveryConfig.securityQuestions.questionsToAsk, questions.length);
      const selectedIndices = this.selectRandomIndices(questions.length, questionsToAsk);
      const selectedQuestions: SelectedQuestion[] = selectedIndices.map((index) => {
        const question = questions[index];
        return {
          index,
          question: question && typeof question === 'object' ? question.question : 'Question not available',
        };
      });

      // Store verification data with expiration
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
      this.verificationData.set(requestId, {
        userId,
        selectedIndices,
        attempts: 0,
        expiresAt,
      });

      // Update request metadata
      await recoveryRequestRepository.update(requestId, {
        metadata: {
          ...request.metadata,
          methodType: RecoveryMethodType.SECURITY_QUESTIONS,
          expiresAt: expiresAt.toISOString(),
        },
      });

      // Log the recovery initiation
      await auditLogRepository.create({
        userId,
        action: "SECURITY_QUESTIONS_RECOVERY_INITIATED",
        entityType: "RECOVERY_REQUEST",
        entityId: requestId,
        metadata: {
          questionCount: selectedQuestions.length,
          expiresAt: expiresAt.toISOString(),
        },
      });

      // Return recovery data
      return {
        metadata: {
          selectedIndices,
          expiresAt,
        },
        clientData: {
          questions: selectedQuestions,
          message: "Please answer the security questions to recover your account",
          expiresAt,
          requiredCorrect: recoveryConfig.securityQuestions.minCorrectAnswers || 1,
        },
      };
    } catch (error) {
      logger.error("Failed to initiate security questions recovery", { error, userId, requestId });
      throw error;
    }
  }

  /**
   * Verify security questions recovery
   * @param requestId Recovery request ID
   * @param verificationData Verification data
   * @returns Verification result
   */
  async verifyRecovery(
    requestId: string,
    verificationData: Record<string, any>
  ): Promise<RecoveryVerificationResult> {
    try {
      // Get stored verification data
      const storedData = this.verificationData.get(requestId);
      if (!storedData) {
        return {
          success: false,
          message: "Invalid or expired recovery session",
        };
      }

      // Get answers from verification data
      const { answers } = verificationData;
      if (!answers || !Array.isArray(answers)) {
        return {
          success: false,
          message: "Answers are required",
        };
      }

      // Check if session is expired
      if (storedData.expiresAt < new Date()) {
        this.verificationData.delete(requestId);
        return {
          success: false,
          message: "Recovery session has expired",
        };
      }

      // Increment attempts
      storedData.attempts += 1;

      // Check if max attempts reached
      const maxAttempts = 5; // Could be configurable
      if (storedData.attempts > maxAttempts) {
        this.verificationData.delete(requestId);
        return {
          success: false,
          message: "Maximum verification attempts reached",
        };
      }

      // Get user profile
      const profile = await userProfileRepository.findByUserId(storedData.userId);
      if (!profile) {
        return {
          success: false,
          message: "User profile not found",
        };
      }

      // Get security questions
      const metadata = profile.metadata as Record<string, any> | null;
      if (!metadata || !metadata['securityQuestions'] || !Array.isArray(metadata['securityQuestions'])) {
        return {
          success: false,
          message: "Security questions not set up",
        };
      }

      const questions = metadata['securityQuestions'] as any[];
      const { selectedIndices } = storedData;

      // Verify each answer
      let correctAnswers = 0;
      for (let i = 0; i < selectedIndices.length; i++) {
        const index = selectedIndices[i];
        if (index === undefined || index < 0 || index >= questions.length) {
          return {
            success: false,
            message: "Invalid question index",
          };
        }

        const question = questions[index];
        if (!question || typeof question !== 'object') {
          continue; // Skip invalid questions
        }

        const providedAnswer = answers[i];
        if (!providedAnswer) {
          continue; // Skip empty answers
        }

        const encryptedAnswer = question.answer;
        if (!encryptedAnswer) {
          continue; // Skip questions with no answer
        }

        const storedAnswer = encryption.decrypt(encryptedAnswer) as string;
        if (!storedAnswer) {
          continue; // Skip if decryption failed
        }

        // Check if answer is correct
        if (this.compareAnswers(providedAnswer, storedAnswer)) {
          correctAnswers++;
        }
      }

      // Require minimum correct answers
      const requiredCorrect = Math.min(
        recoveryConfig.securityQuestions.minCorrectAnswers || 1,
        selectedIndices.length
      );
      
      if (correctAnswers >= requiredCorrect) {
        // Remove verification data
        this.verificationData.delete(requestId);

        // Log successful verification
        await auditLogRepository.create({
          userId: storedData.userId,
          action: "SECURITY_QUESTIONS_RECOVERY_VERIFIED",
          entityType: "RECOVERY_REQUEST",
          entityId: requestId,
          metadata: {
            correctAnswers,
            requiredCorrect,
          },
        });

        return {
          success: true,
          message: "Security questions verification successful",
        };
      } else {
        // Log failed verification
        await auditLogRepository.create({
          userId: storedData.userId,
          action: "SECURITY_QUESTIONS_RECOVERY_VERIFICATION_FAILED",
          entityType: "RECOVERY_REQUEST",
          entityId: requestId,
          metadata: {
            correctAnswers,
            requiredCorrect,
            remainingAttempts: maxAttempts - storedData.attempts,
          },
        });

        return {
          success: false,
          message: `At least ${requiredCorrect} correct answers required, got ${correctAnswers}. ${
            maxAttempts - storedData.attempts
          } attempts remaining.`,
        };
      }
    } catch (error) {
      logger.error("Failed to verify security questions recovery", { error, requestId });
      return {
        success: false,
        message: "An error occurred during verification",
      };
    }
  }

  /**
   * Set up security questions for a user
   * @param userId User ID
   * @param questions Array of question-answer pairs
   * @returns Setup response with success status and count
   */
  async setupSecurityQuestions(
    userId: string,
    questions: SecurityQuestion[]
  ): Promise<SecurityQuestionsSetupResponse> {
    try {
      // Validate questions
      if (!questions || !Array.isArray(questions) || questions.length < recoveryConfig.securityQuestions.minQuestions) {
        throw new BadRequestError(
          `At least ${recoveryConfig.securityQuestions.minQuestions} security questions are required`
        );
      }

      // Validate each question and answer
      for (const q of questions) {
        if (!q.question || !q.answer) {
          throw new BadRequestError("Each question must have both a question and an answer");
        }

        if (
          recoveryConfig.securityQuestions.enforceMinAnswerLength &&
          q.answer.length < recoveryConfig.securityQuestions.minAnswerLength
        ) {
          throw new BadRequestError(
            `Answers must be at least ${recoveryConfig.securityQuestions.minAnswerLength} characters long`
          );
        }
      }

      // Get user profile
      let profile = await userProfileRepository.findByUserId(userId);
      if (!profile) {
        // Create profile if it doesn't exist
        profile = await userProfileRepository.create({
          userId,
          metadata: {},
        });
      }

      // Encrypt answers
      const encryptedQuestions: EncryptedSecurityQuestion[] = questions.map((q) => ({
        question: q.question,
        answer: encryption.encrypt(q.answer),
        createdAt: new Date().toISOString(),
      }));

      // Update profile metadata
      const metadata = (profile.metadata as Record<string, any>) || {};
      metadata['securityQuestions'] = encryptedQuestions;

      // Update profile
      await userProfileRepository.updateByUserId(userId, {
        metadata,
      });

      // Log the setup
      await auditLogRepository.create({
        userId,
        action: "SECURITY_QUESTIONS_SETUP",
        metadata: {
          count: encryptedQuestions.length,
        },
      });

      return {
        success: true,
        count: encryptedQuestions.length,
      };
    } catch (error) {
      logger.error("Failed to set up security questions", { error, userId });
      throw error;
    }
  }

  /**
   * Compare user-provided answer with stored answer
   * @param providedAnswer User-provided answer
   * @param storedAnswer Stored answer
   * @returns True if answers match
   */
  private compareAnswers(providedAnswer: string, storedAnswer: string): boolean {
    if (!providedAnswer || !storedAnswer) {
      return false;
    }

    // Normalize answers for comparison
    const normalizedProvided = this.normalizeAnswer(providedAnswer);
    const normalizedStored = this.normalizeAnswer(storedAnswer);

    // Use fuzzy matching if enabled
    if (recoveryConfig.securityQuestions.useFuzzyMatching) {
      return this.fuzzyMatch(
        normalizedProvided,
        normalizedStored,
        recoveryConfig.securityQuestions.fuzzyMatchThreshold || 0.8
      );
    }

    // Otherwise use exact matching
    return normalizedProvided === normalizedStored;
  }

  /**
   * Normalize an answer for comparison
   * @param answer Answer to normalize
   * @returns Normalized answer
   */
  private normalizeAnswer(answer: string): string {
    if (!answer) {
      return '';
    }
    return answer
      .toLowerCase()
      .trim()
      .replace(/\s+/g, " ") // Replace multiple spaces with a single space
      .replace(/[^\w\s]/g, ""); // Remove special characters
  }

  /**
   * Perform fuzzy matching between two strings
   * @param str1 First string
   * @param str2 Second string
   * @param threshold Similarity threshold (0-1)
   * @returns True if strings are similar enough
   */
  private fuzzyMatch(str1: string, str2: string, threshold: number): boolean {
    if (!str1 || !str2) {
      return false;
    }
    
    // Normalize strings for comparison
    const s1 = str1.toLowerCase();
    const s2 = str2.toLowerCase();
    
    // For exact matches, return true immediately
    if (s1 === s2) {
      return true;
    }
    
    // For very short strings, use character-by-character comparison
    if (s1.length <= 3 || s2.length <= 3) {
      // If length difference is too big, strings are not similar
      if (Math.abs(s1.length - s2.length) > 1) {
        return false;
      }
      
      // Count matching characters
      let matches = 0;
      const minLength = Math.min(s1.length, s2.length);
      
      for (let i = 0; i < minLength; i++) {
        if (s1[i] === s2[i]) {
          matches++;
        }
      }
      
      // Calculate similarity as percentage of matching characters
      const similarity = matches / Math.max(s1.length, s2.length);
      return similarity >= threshold;
    }
    
    // For longer strings, use a simplified similarity measure
    // Count common characters
    const s1Chars = new Set(s1.split(''));
    const s2Chars = new Set(s2.split(''));
    
    let commonChars = 0;
    for (const char of s1Chars) {
      if (s2Chars.has(char)) {
        commonChars++;
      }
    }
    
    // Calculate Jaccard similarity coefficient
    const totalUniqueChars = s1Chars.size + s2Chars.size - commonChars;
    const similarity = commonChars / totalUniqueChars;
    
    return similarity >= threshold;
  }

  /**
   * Calculate Levenshtein distance between two strings
   * This is a simplified version that avoids TypeScript errors
   * @param str1 First string
   * @param str2 Second string
   * @returns Approximate edit distance
   */
  private levenshteinDistance(str1: string, str2: string): number {
    // Ensure we have valid strings
    const s1 = str1 || '';
    const s2 = str2 || '';
    
    // For empty strings, return the length of the other string
    if (s1.length === 0) return s2.length;
    if (s2.length === 0) return s1.length;
    
    // For identical strings, return 0
    if (s1 === s2) return 0;
    
    // For strings with very different lengths, use length difference as approximation
    const lengthDiff = Math.abs(s1.length - s2.length);
    if (lengthDiff > Math.min(s1.length, s2.length)) {
      return lengthDiff;
    }
    
    // For short strings, use character-by-character comparison
    if (s1.length < 5 && s2.length < 5) {
      let distance = 0;
      const minLength = Math.min(s1.length, s2.length);
      
      for (let i = 0; i < minLength; i++) {
        if (s1[i] !== s2[i]) {
          distance++;
        }
      }
      
      // Add the difference in length
      distance += lengthDiff;
      return distance;
    }
    
    // For longer strings, use a simplified approach
    // Count different characters as a rough approximation
    const s1Chars = s1.split('');
    const s2Chars = s2.split('');
    
    // Count characters that appear in one string but not the other
    const s1Set = new Set(s1Chars);
    const s2Set = new Set(s2Chars);
    
    let uniqueToS1 = 0;
    for (const char of s1Set) {
      if (!s2Set.has(char)) {
        uniqueToS1++;
      }
    }
    
    let uniqueToS2 = 0;
    for (const char of s2Set) {
      if (!s1Set.has(char)) {
        uniqueToS2++;
      }
    }
    
    // Return the sum of unique characters as an approximation of edit distance
    return uniqueToS1 + uniqueToS2;
  }

  /**
   * Select random indices from a range
   * @param max Maximum index (exclusive)
   * @param count Number of indices to select
   * @returns Array of selected indices
   */
  private selectRandomIndices(max: number, count: number): number[] {
    if (max <= 0 || count <= 0) {
      return [];
    }
    
    const indices: number[] = [];
    const available = Array.from({ length: max }, (_, i) => i);

    // Ensure count doesn't exceed available indices
    const actualCount = Math.min(count, available.length);

    for (let i = 0; i < actualCount; i++) {
      const randomIndex = Math.floor(Math.random() * available.length);
      const selectedIndex = available[randomIndex];
      // Ensure selectedIndex is a number before using it
      if (selectedIndex !== undefined) {
        indices.push(selectedIndex);
        available.splice(randomIndex, 1);
      }
    }

    return indices;
  }
}

// Export a singleton instance
export const securityQuestionsService = new SecurityQuestionsService();
