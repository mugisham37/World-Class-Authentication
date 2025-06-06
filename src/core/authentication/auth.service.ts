import { userRepository } from '../../data/repositories/implementations/user.repository.impl';
import { credentialRepository } from '../../data/repositories/credential.repository';
import { sessionRepository } from '../../data/repositories/session.repository';
import { auditLogRepository } from '../../data/repositories/audit-log.repository';
import { passwordHasher } from '../../infrastructure/security/crypto/password-hasher';
import {
  generateAccessToken,
  generateRefreshToken,
} from '../../infrastructure/security/crypto/token-signer';
import { logger } from '../../infrastructure/logging/logger';
import { securityConfig } from '../../config/security-config';
import { AuthenticationError, NotFoundError } from '../../utils/error-handling';
import { emitEvent } from '../events/event-bus';
import { EventType } from '../events/event-types';
import { sessionService } from './session.service';
import { riskAssessmentService } from './risk-assessment.service';
import { identityService } from '../identity/identity.service';
import { CredentialType } from '../../data/models/credential.model';

/**
 * Authentication service for handling user authentication
 */
export class AuthService {
  /**
   * Authenticate a user with email and password
   * @param email User email
   * @param password User password
   * @param ipAddress Client IP address
   * @param userAgent Client user agent
   * @param deviceId Optional device ID
   * @returns Authentication result with tokens and user info
   */
  async authenticateWithPassword(
    email: string,
    password: string,
    ipAddress: string,
    userAgent: string,
    deviceId?: string
  ): Promise<{
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
    user: {
      id: string;
      email: string;
      username: string | null;
    };
    sessionId: string;
  }> {
    // Emit login attempt event
    emitEvent(EventType.AUTH_LOGIN_ATTEMPT, {
      email,
      ipAddress,
      userAgent,
      timestamp: new Date(),
    });

    // Find user by email
    const user = await userRepository.findByEmail(email);
    if (!user) {
      // Log failed login attempt
      await auditLogRepository.create({
        action: 'login.failed',
        ipAddress,
        userAgent,
        metadata: {
          reason: 'user_not_found',
          email,
        },
      });

      // Emit login failure event
      emitEvent(EventType.AUTH_LOGIN_FAILURE, {
        email,
        ipAddress,
        userAgent,
        reason: 'user_not_found',
        timestamp: new Date(),
      });

      throw new AuthenticationError('Invalid email or password', 'INVALID_CREDENTIALS');
    }

    // Check if account is active
    if (!user.active) {
      // Log failed login attempt
      await auditLogRepository.create({
        userId: user.id,
        action: 'login.failed',
        ipAddress,
        userAgent,
        metadata: {
          reason: 'account_inactive',
          email,
        },
      });

      // Emit login failure event
      emitEvent(EventType.AUTH_LOGIN_FAILURE, {
        userId: user.id,
        email,
        ipAddress,
        userAgent,
        reason: 'account_inactive',
        timestamp: new Date(),
      });

      throw new AuthenticationError('Account is inactive', 'ACCOUNT_INACTIVE');
    }

    // Check if account is locked
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      // Log failed login attempt
      await auditLogRepository.create({
        userId: user.id,
        action: 'login.failed',
        ipAddress,
        userAgent,
        metadata: {
          reason: 'account_locked',
          email,
          lockedUntil: user.lockedUntil,
        },
      });

      // Emit login failure event
      emitEvent(EventType.AUTH_LOGIN_FAILURE, {
        userId: user.id,
        email,
        ipAddress,
        userAgent,
        reason: 'account_locked',
        timestamp: new Date(),
      });

      throw new AuthenticationError(
        `Account is locked until ${user.lockedUntil.toISOString()}`,
        'ACCOUNT_LOCKED'
      );
    }

    // Get password credential
    const credentials = await credentialRepository.findByUserIdAndType(
      user.id,
      CredentialType.PASSWORD
    );
    if (!credentials || credentials.length === 0) {
      await auditLogRepository.create({
        userId: user.id,
        action: 'login.failed',
        ipAddress,
        userAgent,
        metadata: {
          reason: 'no_password_credential',
          email,
        },
      });

      throw new AuthenticationError('Invalid email or password', 'INVALID_CREDENTIALS');
    }

    const passwordCredential = credentials[0];
    if (!passwordCredential) {
      throw new AuthenticationError('Invalid email or password', 'INVALID_CREDENTIALS');
    }

    // Verify password
    const isPasswordValid = await passwordHasher.verify(password, passwordCredential.secret);
    if (!isPasswordValid) {
      // Increment failed login attempts
      await userRepository.incrementFailedLoginAttempts(user.id);

      // Check if we should lock the account
      if (user.failedLoginAttempts + 1 >= securityConfig.security.maxFailedLoginAttempts) {
        // Lock account for configured lockout duration
        await identityService.lockAccount(
          user.id,
          securityConfig.security.accountLockoutDurationMinutes
        );

        // Log account locked
        await auditLogRepository.create({
          userId: user.id,
          action: 'account.locked',
          ipAddress,
          userAgent,
          metadata: {
            reason: 'too_many_failed_attempts',
            email,
            failedAttempts: user.failedLoginAttempts + 1,
          },
        });
      }

      // Log failed login attempt
      await auditLogRepository.create({
        userId: user.id,
        action: 'login.failed',
        ipAddress,
        userAgent,
        metadata: {
          reason: 'invalid_password',
          email,
          failedAttempts: user.failedLoginAttempts + 1,
        },
      });

      // Emit login failure event
      emitEvent(EventType.AUTH_LOGIN_FAILURE, {
        userId: user.id,
        email,
        ipAddress,
        userAgent,
        reason: 'invalid_password',
        timestamp: new Date(),
      });

      throw new AuthenticationError('Invalid email or password', 'INVALID_CREDENTIALS');
    }

    // Update credential last used time
    await credentialRepository.updateLastUsed(passwordCredential.id);

    // Reset failed login attempts
    if (user.failedLoginAttempts > 0) {
      await userRepository.resetFailedLoginAttempts(user.id);
    }

    // Update last login time
    await userRepository.updateLastLogin(user.id);

    // Perform risk assessment
    const riskAssessment = await riskAssessmentService.assessLoginRisk(
      user.id,
      ipAddress,
      userAgent
    );

    // Check if risk level requires additional verification
    if (riskAssessment.action === 'challenge') {
      // In a real implementation, we would trigger MFA or other verification
      // For now, we'll just log it
      logger.info('Risk assessment requires additional verification', {
        userId: user.id,
        riskLevel: riskAssessment.riskLevel,
        riskScore: riskAssessment.riskScore,
      });
    } else if (riskAssessment.action === 'block') {
      // Log blocked login attempt
      await auditLogRepository.create({
        userId: user.id,
        action: 'login.blocked',
        ipAddress,
        userAgent,
        metadata: {
          reason: 'high_risk',
          riskScore: riskAssessment.riskScore,
          riskLevel: riskAssessment.riskLevel,
        },
      });

      throw new AuthenticationError('Login blocked due to security concerns', 'LOGIN_BLOCKED');
    }

    // Create session
    const session = await sessionService.createSession(user.id, ipAddress, userAgent, deviceId);

    // Update risk assessment with session ID
    await riskAssessmentService.updateSessionId(riskAssessment.id, session.id);

    // Check if user email is defined
    if (!user.email) {
      throw new AuthenticationError('User email is required', 'INVALID_USER_DATA');
    }

    // Generate tokens
    const accessToken = generateAccessToken({
      sub: user.id,
      email: user.email,
      sessionId: session.id,
    });

    const refreshToken = generateRefreshToken({
      sub: user.id,
      sessionId: session.id,
    });

    // Log successful login
    await auditLogRepository.create({
      userId: user.id,
      action: 'login.success',
      ipAddress,
      userAgent,
      metadata: {
        email,
        sessionId: session.id,
      },
    });

    // Emit login success event
    emitEvent(EventType.AUTH_LOGIN_SUCCESS, {
      userId: user.id,
      email: user.email,
      ipAddress,
      userAgent,
      sessionId: session.id,
      timestamp: new Date(),
    });

    logger.info('User authenticated successfully', {
      userId: user.id,
      email: user.email,
      sessionId: session.id,
    });

    // We've already checked that user.email is defined above, but let's be explicit for TypeScript
    if (!user.email) {
      throw new AuthenticationError('User email is required', 'INVALID_USER_DATA');
    }

    return {
      accessToken,
      refreshToken,
      expiresIn: this.getAccessTokenExpirySeconds(),
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
      },
      sessionId: session.id,
    };
  }

  /**
   * Refresh authentication tokens
   * @param refreshToken Refresh token
   * @param ipAddress Client IP address
   * @param userAgent Client user agent
   * @returns New authentication tokens
   */
  async refreshTokens(
    refreshToken: string,
    ipAddress: string,
    userAgent: string
  ): Promise<{
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  }> {
    try {
      // Validate refresh token and get session
      const session = await sessionService.validateRefreshToken(refreshToken);

      // Get user
      const user = await userRepository.findById(session.userId);
      if (!user) {
        throw new NotFoundError('User not found', 'USER_NOT_FOUND');
      }

      // Check if account is active
      if (!user.active) {
        throw new AuthenticationError('Account is inactive', 'ACCOUNT_INACTIVE');
      }

      // Check if account is locked
      if (user.lockedUntil && user.lockedUntil > new Date()) {
        throw new AuthenticationError(
          `Account is locked until ${user.lockedUntil.toISOString()}`,
          'ACCOUNT_LOCKED'
        );
      }

      // Update session last active time
      await sessionRepository.updateLastActive(session.id);

      // Check if user email is defined
      if (!user.email) {
        throw new AuthenticationError('User email is required', 'INVALID_USER_DATA');
      }

      // Generate new tokens
      const newAccessToken = generateAccessToken({
        sub: user.id,
        email: user.email,
        sessionId: session.id,
      });

      const newRefreshToken = generateRefreshToken({
        sub: user.id,
        sessionId: session.id,
      });

      // Log token refresh
      await auditLogRepository.create({
        userId: user.id,
        action: 'token.refresh',
        ipAddress,
        userAgent,
        metadata: {
          sessionId: session.id,
        },
      });

      logger.info('Tokens refreshed successfully', {
        userId: user.id,
        sessionId: session.id,
      });

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresIn: this.getAccessTokenExpirySeconds(),
      };
    } catch (error) {
      // Log token refresh failure
      await auditLogRepository.create({
        action: 'token.refresh.failed',
        ipAddress,
        userAgent,
        metadata: {
          error: error instanceof Error ? error.message : 'Unknown error',
        },
      });

      throw error;
    }
  }

  /**
   * Logout a user
   * @param sessionId Session ID
   * @param userId User ID
   * @param ipAddress Client IP address
   * @param userAgent Client user agent
   */
  async logout(
    sessionId: string,
    userId: string,
    ipAddress: string,
    userAgent: string
  ): Promise<void> {
    try {
      // Terminate session
      await sessionService.terminateSession(sessionId);

      // Log logout
      await auditLogRepository.create({
        userId,
        action: 'logout',
        ipAddress,
        userAgent,
        metadata: {
          sessionId,
        },
      });

      // Emit logout event
      emitEvent(EventType.AUTH_LOGOUT, {
        userId,
        sessionId,
        ipAddress,
        userAgent,
        timestamp: new Date(),
      });

      logger.info('User logged out successfully', {
        userId,
        sessionId,
      });
    } catch (error) {
      logger.error('Logout failed', {
        error,
        userId,
        sessionId,
      });

      throw error;
    }
  }

  /**
   * Logout from all sessions
   * @param userId User ID
   * @param ipAddress Client IP address
   * @param userAgent Client user agent
   */
  async logoutAll(userId: string, ipAddress: string, userAgent: string): Promise<void> {
    try {
      // Terminate all sessions
      const count = await sessionService.terminateAllUserSessions(userId);

      // Log logout from all sessions
      await auditLogRepository.create({
        userId,
        action: 'logout.all',
        ipAddress,
        userAgent,
        metadata: {
          sessionCount: count,
        },
      });

      logger.info('User logged out from all sessions successfully', {
        userId,
        sessionCount: count,
      });
    } catch (error) {
      logger.error('Logout from all sessions failed', {
        error,
        userId,
      });

      throw error;
    }
  }

  /**
   * Validate access token
   * @param accessToken Access token
   * @returns Validated token payload
   */
  async validateAccessToken(accessToken: string): Promise<{
    userId: string;
    email: string;
    sessionId: string;
  }> {
    return await sessionService.validateAccessToken(accessToken);
  }

  /**
   * Get access token expiry in seconds
   * @returns Expiry in seconds
   */
  private getAccessTokenExpirySeconds(): number {
    const expiresIn = securityConfig.jwt.accessTokenExpiresIn;
    if (typeof expiresIn === 'number') {
      return expiresIn;
    }

    if (expiresIn.endsWith('m')) {
      return Number.parseInt(expiresIn) * 60;
    } else if (expiresIn.endsWith('h')) {
      return Number.parseInt(expiresIn) * 60 * 60;
    } else if (expiresIn.endsWith('d')) {
      return Number.parseInt(expiresIn) * 60 * 60 * 24;
    } else {
      return Number.parseInt(expiresIn);
    }
  }
}

// Export a singleton instance
export const authService = new AuthService();
