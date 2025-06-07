import type { Request, Response } from 'express';
import { BaseController } from './base.controller';
import { sendOkResponse } from '../responses';
import { AuthenticationError, BadRequestError } from '../../utils/error-handling';
import { securityQuestionsService } from '../../core/recovery/methods/security-questions.service';

/**
 * Security Questions controller
 * Handles security questions setup and management for account recovery
 */
export class SecurityQuestionsController extends BaseController {
  /**
   * Get security questions for a user
   * @route GET /security-questions
   */
  getUserQuestions = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    // In a real implementation, we would retrieve the user's security questions
    // For now, we'll return a placeholder response
    sendOkResponse(res, 'Security questions retrieved successfully', {
      questions: [
        { id: '1', question: 'What was the name of your first pet?' },
        { id: '2', question: 'In what city were you born?' },
        { id: '3', question: 'What was the make of your first car?' },
      ],
    });
  });

  /**
   * Set up security questions for a user
   * @route POST /security-questions
   */
  setupSecurityQuestions = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    const userId = req.user.id;
    const { questions } = req.body;

    // Validate questions
    if (!questions || !Array.isArray(questions)) {
      throw new BadRequestError('Questions array is required', 'QUESTIONS_REQUIRED');
    }

    // Validate each question
    for (const question of questions) {
      if (!question.question) {
        throw new BadRequestError('Question text is required', 'QUESTION_TEXT_REQUIRED');
      }
      if (!question.answer) {
        throw new BadRequestError('Answer is required', 'ANSWER_REQUIRED');
      }
    }

    // Set up security questions
    const result = await securityQuestionsService.setupSecurityQuestions(userId, questions);

    sendOkResponse(res, 'Security questions set up successfully', {
      success: result.success,
      count: result.count,
    });
  });

  /**
   * Update security questions for a user
   * @route PUT /security-questions
   */
  updateSecurityQuestions = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    const userId = req.user.id;
    const { questions } = req.body;

    // Validate questions
    if (!questions || !Array.isArray(questions)) {
      throw new BadRequestError('Questions array is required', 'QUESTIONS_REQUIRED');
    }

    // Validate each question
    for (const question of questions) {
      if (!question.question) {
        throw new BadRequestError('Question text is required', 'QUESTION_TEXT_REQUIRED');
      }
      if (!question.answer) {
        throw new BadRequestError('Answer is required', 'ANSWER_REQUIRED');
      }
    }

    // Update security questions (uses the same method as setup)
    const result = await securityQuestionsService.setupSecurityQuestions(userId, questions);

    sendOkResponse(res, 'Security questions updated successfully', {
      success: result.success,
      count: result.count,
    });
  });

  /**
   * Verify security questions for a user
   * @route POST /security-questions/verify
   */
  verifySecurityQuestions = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const { requestId, answers } = req.body;

    // Validate required fields
    if (!requestId) {
      throw new BadRequestError('Request ID is required', 'REQUEST_ID_REQUIRED');
    }

    if (!answers || !Array.isArray(answers)) {
      throw new BadRequestError('Answers array is required', 'ANSWERS_REQUIRED');
    }

    // In a real implementation, we would verify the security questions
    // For now, we'll simulate verification using the recovery service
    const result = await securityQuestionsService.verifyRecovery(requestId, { answers });

    sendOkResponse(res, result.message || 'Verification processed', {
      success: result.success,
    });
  });
}

// Create instance
export const securityQuestionsController = new SecurityQuestionsController();
