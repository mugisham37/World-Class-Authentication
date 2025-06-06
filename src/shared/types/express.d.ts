import { Session } from '../../core/authentication/types';

/**
 * Express namespace extensions
 * Extends Express Request interface with custom properties
 */
declare global {
  namespace Express {
    interface Request {
      /**
       * User information from authentication
       */
      user?: {
        id: string;
        email: string;
        sessionId: string;
        roles?: string[];
      };

      /**
       * Device ID from fingerprinting
       */
      deviceId?: string;

      /**
       * Custom session information
       * Using a different name to avoid conflict with Express.js session
       */
      customSession?: Session;
    }
  }
}

export {};
