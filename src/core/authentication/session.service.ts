import { Session, CreateSessionData } from '../../data/models/session.model';
import { sessionRepository } from '../../data/repositories/session.repository';
import { logger } from '../../infrastructure/logging/logger';
import { securityConfig } from '../../config/security-config';
import { AuthenticationError, NotFoundError } from '../../utils/error-handling';
import { generateSecureToken } from '../../infrastructure/security/crypto/encryption';
import {
  verifyAccessToken,
  verifyRefreshToken,
} from '../../infrastructure/security/crypto/token-signer';
import { emitEvent } from '../events/event-bus';
import { EventType } from '../events/event-types';

/**
 * Session service for managing user sessions
 */
export class SessionService {
  /**
   * Create a new session
   * @param userId User ID
   * @param ipAddress Client IP address
   * @param userAgent Client user agent
   * @param deviceId Optional device ID
   * @returns Created session
   */
  async createSession(
    userId: string,
    ipAddress: string,
    userAgent: string,
    deviceId?: string
  ): Promise<Session> {
    try {
      // Generate session token
      const token = generateSecureToken(64);

      // Calculate expiration time
      const expiresAt = new Date(Date.now() + securityConfig.session.cookieMaxAge);

      // Create session data
      const sessionData: CreateSessionData = {
        userId,
        token,
        expiresAt,
        ipAddress,
        userAgent,
        deviceId: deviceId || null,
        location: null,
        isRevoked: false,
        user: {
          connect: {
            id: userId,
          },
        },
      };

      // Create session
      const session = await sessionRepository.create(sessionData);

      // Emit session created event
      emitEvent(EventType.SESSION_CREATED, {
        userId,
        sessionId: session.id,
        ipAddress,
        userAgent,
        deviceId,
        expiresAt,
        timestamp: new Date(),
      });

      logger.info('Session created successfully', {
        userId,
        sessionId: session.id,
      });

      return session;
    } catch (error) {
      logger.error('Failed to create session', {
        error,
        userId,
        ipAddress,
      });

      throw error;
    }
  }

  /**
   * Get a session by ID
   * @param id Session ID
   * @returns Session or null if not found
   */
  async getSessionById(id: string): Promise<Session | null> {
    return await sessionRepository.findById(id);
  }

  /**
   * Get a session by token
   * @param token Session token
   * @returns Session or null if not found
   */
  async getSessionByToken(token: string): Promise<Session | null> {
    return await sessionRepository.findByToken(token);
  }

  /**
   * Get all sessions for a user
   * @param userId User ID
   * @returns List of sessions
   */
  async getUserSessions(userId: string): Promise<Session[]> {
    return await sessionRepository.findByUserId(userId);
  }

  /**
   * Update session last active time
   * @param id Session ID
   * @returns Updated session
   */
  async updateSessionActivity(id: string): Promise<Session> {
    try {
      return await sessionRepository.updateLastActive(id);
    } catch (error) {
      logger.error('Failed to update session activity', {
        error,
        sessionId: id,
      });

      throw error;
    }
  }

  /**
   * Terminate a session
   * @param id Session ID
   * @returns Terminated session
   */
  async terminateSession(id: string): Promise<Session> {
    try {
      // Get session
      const session = await sessionRepository.findById(id);
      if (!session) {
        throw new NotFoundError('Session not found', 'SESSION_NOT_FOUND');
      }

      // Store session data before deletion
      const terminatedSession = { ...session };

      // Delete session
      const deleted = await sessionRepository.delete(id);
      if (!deleted) {
        throw new NotFoundError('Failed to delete session', 'SESSION_DELETE_FAILED');
      }

      // Emit session terminated event
      emitEvent(EventType.SESSION_TERMINATED, {
        userId: session.userId,
        sessionId: id,
        timestamp: new Date(),
      });

      logger.info('Session terminated successfully', {
        userId: session.userId,
        sessionId: id,
      });

      return terminatedSession;
    } catch (error) {
      logger.error('Failed to terminate session', {
        error,
        sessionId: id,
      });

      throw error;
    }
  }

  /**
   * Terminate all sessions for a user
   * @param userId User ID
   * @returns Number of terminated sessions
   */
  async terminateAllUserSessions(userId: string): Promise<number> {
    try {
      // Delete all sessions
      const count = await sessionRepository.deleteByUserId(userId);

      // Emit session terminated event
      emitEvent(EventType.SESSION_TERMINATED, {
        userId,
        sessionId: 'all',
        timestamp: new Date(),
      });

      logger.info('All user sessions terminated successfully', {
        userId,
        count,
      });

      return count;
    } catch (error) {
      logger.error('Failed to terminate all user sessions', {
        error,
        userId,
      });

      throw error;
    }
  }

  /**
   * Validate a refresh token
   * @param token Refresh token
   * @returns Session associated with the token
   * @throws AuthenticationError if token is invalid or session not found
   */
  async validateRefreshToken(token: string): Promise<Session> {
    try {
      // Verify token signature and expiration
      const payload = verifyRefreshToken(token);

      // Get session ID from payload
      const sessionId = payload.sessionId;
      if (!sessionId) {
        throw new AuthenticationError('Invalid refresh token', 'INVALID_REFRESH_TOKEN');
      }

      // Get session
      const session = await sessionRepository.findById(sessionId);
      if (!session) {
        throw new AuthenticationError('Session not found', 'SESSION_NOT_FOUND');
      }

      // Check if session is expired
      if (session.expiresAt < new Date()) {
        // Delete expired session
        await sessionRepository.delete(session.id);

        // Emit session expired event
        emitEvent(EventType.SESSION_EXPIRED, {
          userId: session.userId,
          sessionId: session.id,
          timestamp: new Date(),
        });

        throw new AuthenticationError('Session expired', 'SESSION_EXPIRED');
      }

      if (!session) {
        throw new AuthenticationError('Session not found', 'SESSION_NOT_FOUND');
      }

      return session;
    } catch (error) {
      logger.error('Failed to validate refresh token', {
        error,
      });

      throw new AuthenticationError('Invalid refresh token', 'INVALID_REFRESH_TOKEN');
    }
  }

  /**
   * Validate an access token
   * @param token Access token
   * @returns Validated token payload
   */
  async validateAccessToken(token: string): Promise<{
    userId: string;
    email: string;
    sessionId: string;
  }> {
    try {
      // Verify token signature and expiration
      const payload = verifyAccessToken(token);

      // Get user ID and session ID from payload
      const userId = payload.sub;
      const email = payload.email;
      const sessionId = payload.sessionId;

      if (!userId || !email || !sessionId) {
        throw new AuthenticationError('Invalid access token', 'INVALID_ACCESS_TOKEN');
      }

      // Get session
      const session = await sessionRepository.findById(sessionId);
      if (!session) {
        throw new AuthenticationError('Session not found', 'SESSION_NOT_FOUND');
      }

      // Check if session is expired
      if (session.expiresAt < new Date()) {
        // Delete expired session
        await sessionRepository.delete(session.id);

        // Emit session expired event
        emitEvent(EventType.SESSION_EXPIRED, {
          userId: session.userId,
          sessionId: session.id,
          timestamp: new Date(),
        });

        throw new AuthenticationError('Session expired', 'SESSION_EXPIRED');
      }

      // Check if session belongs to the user
      if (session.userId !== userId) {
        throw new AuthenticationError('Invalid session', 'INVALID_SESSION');
      }

      // Update session last active time
      await sessionRepository.updateLastActive(session.id);

      return {
        userId,
        email,
        sessionId,
      };
    } catch (error) {
      logger.error('Failed to validate access token', {
        error,
      });

      throw new AuthenticationError('Invalid access token', 'INVALID_ACCESS_TOKEN');
    }
  }

  /**
   * Clean up expired sessions
   * @returns Number of deleted sessions
   */
  async cleanupExpiredSessions(): Promise<number> {
    try {
      const count = await sessionRepository.deleteExpired();

      logger.info('Expired sessions cleaned up successfully', {
        count,
      });

      return count;
    } catch (error) {
      logger.error('Failed to clean up expired sessions', {
        error,
      });

      throw error;
    }
  }
}

// Export a singleton instance
export const sessionService = new SessionService();
