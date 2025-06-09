import { Session } from '../../core/authentication/types';
import { AuthUser } from '../../api/controllers/types/auth.types';

/**
 * Express namespace extensions
 * Extends Express Request interface with custom properties
 */
declare global {
  namespace Express {
    /**
     * Extend the User interface to match AuthUser
     */
    interface User extends AuthUser {}

    interface Request {
      /**
       * User information from authentication
       */
      user?: AuthUser;

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
