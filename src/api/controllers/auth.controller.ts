import type { Request, Response } from 'express';
import { authService } from '../../core/authentication/auth.service';
import { emailVerificationService } from '../../core/authentication/email-verification.service';
import { passwordResetService } from '../../core/authentication/password-reset.service';
import { sessionService } from '../../core/authentication/session.service';
import { identityService } from '../../core/identity/identity.service';
import { logger } from '../../infrastructure/logging/logger';
import { AuthenticationError, BadRequestError } from '../../utils/error-handling';
import { sendCreatedResponse, sendOkResponse } from '../responses';
import { BaseController } from './base.controller';
import {
  BaseSession,
  BaseAuthUser,
  RegisterRequestDto,
  LoginRequestDto,
  ChangePasswordRequestDto,
  ResetPasswordRequestDto,
  UpdateUserProfileRequestDto,
  VerifyEmailRequestDto,
  ForgotPasswordRequestDto,
  RegisterResponseDto,
  isBaseUser,
  isBaseSession,
  isBaseAuthUser,
  isAuthenticationServiceResponse,
  isTokenRefreshServiceResponse,
  isPasswordResetServiceResponse,
  mapToUserProfileResponse,
  mapToSessionResponse,
  mapToLoginResponse,
  validateEmail,
  validatePassword,
  validateUsername,
  AUTH_ERROR_CODES,
} from './types/auth.types';

/**
 * Extended Express Request interface with typed user property
 */
export interface AuthenticatedRequest extends Request {
  user?: BaseAuthUser;
}

/**
 * Cookie configuration for different environments
 */
const getCookieConfig = (isProduction: boolean) => ({
  httpOnly: true,
  secure: isProduction,
  sameSite: 'strict' as const,
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  path: '/',
});

/**
 * Request validation helpers
 */
class RequestValidator {
  static validateRegisterRequest(body: any): RegisterRequestDto {
    const { email, password, username, firstName, lastName } = body;

    if (!email || typeof email !== 'string') {
      throw new BadRequestError('Valid email is required', AUTH_ERROR_CODES.INVALID_CREDENTIALS);
    }

    if (!validateEmail(email)) {
      throw new BadRequestError('Invalid email format', AUTH_ERROR_CODES.INVALID_CREDENTIALS);
    }

    if (!password || typeof password !== 'string') {
      throw new BadRequestError('Password is required', AUTH_ERROR_CODES.INVALID_CREDENTIALS);
    }

    if (!validatePassword(password)) {
      throw new BadRequestError(
        'Password must be at least 8 characters with uppercase, lowercase, and number',
        AUTH_ERROR_CODES.PASSWORD_TOO_WEAK
      );
    }

    if (!username || typeof username !== 'string') {
      throw new BadRequestError('Username is required', AUTH_ERROR_CODES.INVALID_CREDENTIALS);
    }

    if (!validateUsername(username)) {
      throw new BadRequestError(
        'Username must be 3-30 characters, alphanumeric and underscore only',
        AUTH_ERROR_CODES.INVALID_CREDENTIALS
      );
    }

    return {
      email: email.toLowerCase().trim(),
      password,
      username: username.trim(),
      firstName: firstName?.trim() || undefined,
      lastName: lastName?.trim() || undefined,
    };
  }

  static validateLoginRequest(body: any): LoginRequestDto {
    const { email, password } = body;

    if (!email || typeof email !== 'string') {
      throw new BadRequestError('Email is required', AUTH_ERROR_CODES.INVALID_CREDENTIALS);
    }

    if (!password || typeof password !== 'string') {
      throw new BadRequestError('Password is required', AUTH_ERROR_CODES.INVALID_CREDENTIALS);
    }

    return {
      email: email.toLowerCase().trim(),
      password,
    };
  }

  static validateChangePasswordRequest(body: any): ChangePasswordRequestDto {
    const { currentPassword, newPassword } = body;

    if (!currentPassword || typeof currentPassword !== 'string') {
      throw new BadRequestError('Current password is required', 'CURRENT_PASSWORD_REQUIRED');
    }

    if (!newPassword || typeof newPassword !== 'string') {
      throw new BadRequestError('New password is required', 'NEW_PASSWORD_REQUIRED');
    }

    if (!validatePassword(newPassword)) {
      throw new BadRequestError(
        'New password must be at least 8 characters with uppercase, lowercase, and number',
        AUTH_ERROR_CODES.PASSWORD_TOO_WEAK
      );
    }

    return { currentPassword, newPassword };
  }

  static validateUpdateProfileRequest(body: any): UpdateUserProfileRequestDto {
    const { username, firstName, lastName } = body;
    const updateData: UpdateUserProfileRequestDto = {};

    if (username !== undefined) {
      if (typeof username !== 'string' || username.trim().length === 0) {
        throw new BadRequestError('Username must be a non-empty string', 'INVALID_USERNAME');
      }
      if (!validateUsername(username.trim())) {
        throw new BadRequestError(
          'Username must be 3-30 characters, alphanumeric and underscore only',
          'INVALID_USERNAME'
        );
      }
      updateData.username = username.trim();
    }

    if (firstName !== undefined) {
      if (typeof firstName !== 'string') {
        throw new BadRequestError('First name must be a string', 'INVALID_FIRST_NAME');
      }
      updateData.firstName = firstName.trim();
    }

    if (lastName !== undefined) {
      if (typeof lastName !== 'string') {
        throw new BadRequestError('Last name must be a string', 'INVALID_LAST_NAME');
      }
      updateData.lastName = lastName.trim();
    }

    return updateData;
  }
}

/**
 * Enhanced Authentication Controller with comprehensive error handling and type safety
 */
export class AuthController extends BaseController {
  private readonly isProduction = process.env['NODE_ENV'] === 'production';
  private readonly cookieConfig = getCookieConfig(this.isProduction);

  /**
   * Extract client information from request
   */
  private extractClientInfo(req: AuthenticatedRequest) {
    return {
      ipAddress: req.ip || req.connection.remoteAddress || '',
      userAgent: req.headers['user-agent'] || '',
      deviceId: (req as any).deviceId || '',
    };
  }

  /**
   * Validate authenticated user
   */
  private validateAuthenticatedUser(req: AuthenticatedRequest): BaseAuthUser {
    if (!req.user || !isBaseAuthUser(req.user)) {
      throw new AuthenticationError('Not authenticated', AUTH_ERROR_CODES.NOT_AUTHENTICATED);
    }
    return req.user;
  }

  /**
   * Register a new user
   * @route POST /auth/register
   */
  register = this.handleAsync(async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const validatedData = RequestValidator.validateRegisterRequest(req.body);

    try {
      // Create user
      const userResult = await identityService.createUser(
        validatedData.email,
        validatedData.password,
        validatedData.username,
        validatedData.firstName,
        validatedData.lastName
      );

      // Validate service response
      if (!isBaseUser(userResult)) {
        logger.error('Invalid user data received from identity service', { userResult });
        throw new Error('Invalid user data received from identity service');
      }

      // Create email verification token
      const verificationToken = await emailVerificationService.createVerificationToken(
        userResult.id
      );

      // Log for development (remove in production)
      if (!this.isProduction) {
        logger.info('Email verification token for new user', {
          userId: userResult.id,
          email: userResult.email,
          verificationToken,
        });
      }

      // Prepare response
      const responseData: RegisterResponseDto = {
        userId: userResult.id,
        email: userResult.email,
        username: userResult.username,
        emailVerified: userResult.emailVerified,
        ...(!this.isProduction && { verificationToken }), // Only include in development
      };

      sendCreatedResponse(
        res,
        'User registered successfully. Please check your email to verify your account.',
        responseData
      );
    } catch (error) {
      logger.error('User registration failed', {
        email: validatedData.email,
        username: validatedData.username,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  });

  /**
   * Authenticate a user
   * @route POST /auth/login
   */
  login = this.handleAsync(async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const validatedData = RequestValidator.validateLoginRequest(req.body);
    const clientInfo = this.extractClientInfo(req);

    try {
      // Authenticate user
      const authResult = await authService.authenticateWithPassword(
        validatedData.email,
        validatedData.password,
        clientInfo.ipAddress,
        clientInfo.userAgent,
        clientInfo.deviceId
      );

      // Validate service response
      if (!isAuthenticationServiceResponse(authResult)) {
        logger.error('Invalid authentication response from auth service', { authResult });
        throw new Error('Invalid authentication response');
      }

      // Set refresh token cookie
      res.cookie('refreshToken', authResult.refreshToken, this.cookieConfig);

      // Prepare and send response
      const responseData = mapToLoginResponse(authResult);
      sendOkResponse(res, 'Login successful', responseData);

      // Log successful login
      logger.info('User logged in successfully', {
        userId: authResult.user.id,
        email: authResult.user.email,
        sessionId: authResult.sessionId,
        ipAddress: clientInfo.ipAddress,
      });
    } catch (error) {
      logger.warn('Login attempt failed', {
        email: validatedData.email,
        ipAddress: clientInfo.ipAddress,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  });

  /**
   * Logout current session
   * @route POST /auth/logout
   */
  logout = this.handleAsync(async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const user = this.validateAuthenticatedUser(req);
    const clientInfo = this.extractClientInfo(req);

    try {
      // Logout user
      await authService.logout(user.sessionId, user.id, clientInfo.ipAddress, clientInfo.userAgent);

      // Clear refresh token cookie
      res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: this.isProduction,
        sameSite: 'strict',
        path: '/',
      });

      sendOkResponse(res, 'Logout successful');

      // Log successful logout
      logger.info('User logged out successfully', {
        userId: user.id,
        sessionId: user.sessionId,
        ipAddress: clientInfo.ipAddress,
      });
    } catch (error) {
      logger.error('Logout failed', {
        userId: user.id,
        sessionId: user.sessionId,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  });

  /**
   * Logout from all sessions
   * @route POST /auth/logout-all
   */
  logoutAll = this.handleAsync(async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const user = this.validateAuthenticatedUser(req);
    const clientInfo = this.extractClientInfo(req);

    try {
      // Logout from all sessions
      await authService.logoutAll(user.id, clientInfo.ipAddress, clientInfo.userAgent);

      // Clear refresh token cookie
      res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: this.isProduction,
        sameSite: 'strict',
        path: '/',
      });

      sendOkResponse(res, 'Logged out from all sessions successfully');

      // Log successful logout from all sessions
      logger.info('User logged out from all sessions', {
        userId: user.id,
        ipAddress: clientInfo.ipAddress,
      });
    } catch (error) {
      logger.error('Logout all failed', {
        userId: user.id,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  });

  /**
   * Verify current token
   * @route GET /auth/verify
   */
  verifyToken = this.handleAsync(
    async (req: AuthenticatedRequest, res: Response): Promise<void> => {
      const user = this.validateAuthenticatedUser(req);

      sendOkResponse(res, 'Token is valid', {
        userId: user.id,
        email: user.email,
        sessionId: user.sessionId,
      });
    }
  );

  /**
   * Refresh access token
   * @route POST /auth/refresh
   */
  refreshToken = this.handleAsync(
    async (req: AuthenticatedRequest, res: Response): Promise<void> => {
      const refreshToken = req.cookies.refreshToken || req.body.refreshToken;

      if (!refreshToken || typeof refreshToken !== 'string') {
        throw new BadRequestError('No refresh token provided', 'NO_REFRESH_TOKEN');
      }

      const clientInfo = this.extractClientInfo(req);

      try {
        // Refresh tokens
        const tokensResult = await authService.refreshTokens(
          refreshToken,
          clientInfo.ipAddress,
          clientInfo.userAgent
        );

        // Validate service response
        if (!isTokenRefreshServiceResponse(tokensResult)) {
          logger.error('Invalid token refresh response from auth service', { tokensResult });
          throw new Error('Invalid token refresh response');
        }

        // Set new refresh token cookie
        res.cookie('refreshToken', tokensResult.refreshToken, this.cookieConfig);

        sendOkResponse(res, 'Token refreshed successfully', {
          accessToken: tokensResult.accessToken,
          expiresIn: tokensResult.expiresIn,
        });
      } catch (error) {
        logger.warn('Token refresh failed', {
          ipAddress: clientInfo.ipAddress,
          error: error instanceof Error ? error.message : String(error),
        });
        throw error;
      }
    }
  );

  /**
   * Verify email with token
   * @route POST /auth/verify-email
   */
  verifyEmail = this.handleAsync(
    async (req: AuthenticatedRequest, res: Response): Promise<void> => {
      const { token } = req.body as VerifyEmailRequestDto;

      if (!token || typeof token !== 'string') {
        throw new BadRequestError('No verification token provided', 'NO_VERIFICATION_TOKEN');
      }

      try {
        const userId = await emailVerificationService.verifyEmail(token);

        sendOkResponse(res, 'Email verified successfully', { userId });

        logger.info('Email verified successfully', { userId });
      } catch (error) {
        logger.warn('Email verification failed', {
          error: error instanceof Error ? error.message : String(error),
        });
        throw error;
      }
    }
  );

  /**
   * Resend verification email
   * @route POST /auth/resend-verification
   */
  resendVerification = this.handleAsync(
    async (req: AuthenticatedRequest, res: Response): Promise<void> => {
      const user = this.validateAuthenticatedUser(req);

      try {
        const token = await emailVerificationService.resendVerificationEmail(user.id);

        // Log for development
        if (!this.isProduction) {
          logger.info('Resent email verification token', {
            userId: user.id,
            email: user.email,
            verificationToken: token,
          });
        }

        sendOkResponse(res, 'Verification email resent successfully', {
          ...(!this.isProduction && { verificationToken: token }),
        });
      } catch (error) {
        logger.error('Resend verification failed', {
          userId: user.id,
          error: error instanceof Error ? error.message : String(error),
        });
        throw error;
      }
    }
  );

  /**
   * Request password reset
   * @route POST /auth/forgot-password
   */
  forgotPassword = this.handleAsync(
    async (req: AuthenticatedRequest, res: Response): Promise<void> => {
      const { email } = req.body as ForgotPasswordRequestDto;

      if (!email || typeof email !== 'string') {
        throw new BadRequestError('Email is required', 'EMAIL_REQUIRED');
      }

      if (!validateEmail(email)) {
        throw new BadRequestError('Invalid email format', 'INVALID_EMAIL');
      }

      const normalizedEmail = email.toLowerCase().trim();

      try {
        const resetResult = await passwordResetService.createResetToken(normalizedEmail);

        // Validate service response
        if (!isPasswordResetServiceResponse(resetResult)) {
          logger.error('Invalid password reset response from service', { resetResult });
          throw new Error('Invalid password reset response');
        }

        // Log for development
        if (!this.isProduction) {
          logger.info('Password reset token created', {
            userId: resetResult.userId,
            email: normalizedEmail,
            resetToken: resetResult.token,
          });
        }

        sendOkResponse(res, 'Password reset instructions sent to your email', {
          ...(!this.isProduction && { resetToken: resetResult.token }),
        });
      } catch (error) {
        // Log error but don't expose it to client for security
        logger.warn('Password reset request failed', {
          email: normalizedEmail,
          error: error instanceof Error ? error.message : String(error),
        });

        // Always return success for security reasons
        sendOkResponse(
          res,
          'If your email is registered, you will receive password reset instructions'
        );
      }
    }
  );

  /**
   * Reset password with token
   * @route POST /auth/reset-password
   */
  resetPassword = this.handleAsync(
    async (req: AuthenticatedRequest, res: Response): Promise<void> => {
      const { token, password } = req.body as ResetPasswordRequestDto;

      if (!token || typeof token !== 'string') {
        throw new BadRequestError('Reset token is required', 'TOKEN_REQUIRED');
      }

      if (!password || typeof password !== 'string') {
        throw new BadRequestError('New password is required', 'PASSWORD_REQUIRED');
      }

      if (!validatePassword(password)) {
        throw new BadRequestError(
          'Password must be at least 8 characters with uppercase, lowercase, and number',
          AUTH_ERROR_CODES.PASSWORD_TOO_WEAK
        );
      }

      try {
        const userId = await passwordResetService.resetPassword(token, password);

        sendOkResponse(res, 'Password reset successfully', { userId });

        logger.info('Password reset successfully', { userId });
      } catch (error) {
        logger.warn('Password reset failed', {
          error: error instanceof Error ? error.message : String(error),
        });
        throw error;
      }
    }
  );

  /**
   * Change password
   * @route POST /auth/change-password
   */
  changePassword = this.handleAsync(
    async (req: AuthenticatedRequest, res: Response): Promise<void> => {
      const user = this.validateAuthenticatedUser(req);
      const validatedData = RequestValidator.validateChangePasswordRequest(req.body);

      try {
        await identityService.changePassword(
          user.id,
          validatedData.currentPassword,
          validatedData.newPassword
        );

        sendOkResponse(res, 'Password changed successfully');

        logger.info('Password changed successfully', { userId: user.id });
      } catch (error) {
        logger.warn('Password change failed', {
          userId: user.id,
          error: error instanceof Error ? error.message : String(error),
        });
        throw error;
      }
    }
  );

  /**
   * Get user sessions
   * @route GET /auth/sessions
   */
  getSessions = this.handleAsync(
    async (req: AuthenticatedRequest, res: Response): Promise<void> => {
      const user = this.validateAuthenticatedUser(req);

      try {
        const sessionsResult = await sessionService.getUserSessions(user.id);

        // Validate and filter sessions
        if (!Array.isArray(sessionsResult)) {
          logger.error('Invalid sessions data received from session service', { sessionsResult });
          throw new Error('Invalid sessions data received from session service');
        }

        const validSessions = sessionsResult.filter(isBaseSession) as BaseSession[];
        const sessionDisplays = validSessions.map(session =>
          mapToSessionResponse(session, user.sessionId)
        );

        sendOkResponse(res, 'Sessions retrieved successfully', {
          sessions: sessionDisplays,
        });
      } catch (error) {
        logger.error('Get sessions failed', {
          userId: user.id,
          error: error instanceof Error ? error.message : String(error),
        });
        throw error;
      }
    }
  );

  /**
   * Terminate a specific session
   * @route DELETE /auth/sessions/:id
   */
  terminateSession = this.handleAsync(
    async (req: AuthenticatedRequest, res: Response): Promise<void> => {
      const user = this.validateAuthenticatedUser(req);
      const sessionId = req.params['id'];

      if (!sessionId || typeof sessionId !== 'string') {
        throw new BadRequestError('Session ID is required', 'SESSION_ID_REQUIRED');
      }

      try {
        // Get session to validate ownership
        const sessionResult = await sessionService.getSessionById(sessionId);

        if (!isBaseSession(sessionResult)) {
          throw new BadRequestError('Session not found', 'SESSION_NOT_FOUND');
        }

        // Check ownership
        if (sessionResult.userId !== user.id) {
          throw new BadRequestError('Invalid session', 'INVALID_SESSION');
        }

        // Prevent terminating current session
        if (sessionResult.id === user.sessionId) {
          throw new BadRequestError(
            'Cannot terminate current session',
            'CANNOT_TERMINATE_CURRENT_SESSION'
          );
        }

        // Terminate session
        await sessionService.terminateSession(sessionId);

        sendOkResponse(res, 'Session terminated successfully');

        logger.info('Session terminated successfully', {
          userId: user.id,
          terminatedSessionId: sessionId,
        });
      } catch (error) {
        logger.warn('Session termination failed', {
          userId: user.id,
          sessionId,
          error: error instanceof Error ? error.message : String(error),
        });
        throw error;
      }
    }
  );

  /**
   * Get current user profile
   * @route GET /auth/me
   */
  getCurrentUser = this.handleAsync(
    async (req: AuthenticatedRequest, res: Response): Promise<void> => {
      const user = this.validateAuthenticatedUser(req);

      try {
        const userResult = await identityService.getUserById(user.id);

        if (!isBaseUser(userResult)) {
          throw new BadRequestError('User not found', 'USER_NOT_FOUND');
        }

        const userProfile = mapToUserProfileResponse(userResult);
        sendOkResponse(res, 'User profile retrieved successfully', userProfile);
      } catch (error) {
        logger.error('Get current user failed', {
          userId: user.id,
          error: error instanceof Error ? error.message : String(error),
        });
        throw error;
      }
    }
  );

  /**
   * Update user profile
   * @route PUT /auth/me
   */
  updateCurrentUser = this.handleAsync(
    async (req: AuthenticatedRequest, res: Response): Promise<void> => {
      const user = this.validateAuthenticatedUser(req);
      const updateData = RequestValidator.validateUpdateProfileRequest(req.body);

      // Check if there's anything to update
      if (Object.keys(updateData).length === 0) {
        throw new BadRequestError('No valid fields to update', 'NO_UPDATE_DATA');
      }

      try {
        const updatedUserResult = await identityService.updateUser(user.id, updateData);

        if (!isBaseUser(updatedUserResult)) {
          throw new BadRequestError('User not found', 'USER_NOT_FOUND');
        }

        const userProfile = mapToUserProfileResponse(updatedUserResult);
        sendOkResponse(res, 'User profile updated successfully', userProfile);

        logger.info('User profile updated successfully', {
          userId: user.id,
          updatedFields: Object.keys(updateData),
        });
      } catch (error) {
        logger.error('Update user profile failed', {
          userId: user.id,
          updateData,
          error: error instanceof Error ? error.message : String(error),
        });
        throw error;
      }
    }
  );
}

// Export singleton instance
export const authController = new AuthController();
