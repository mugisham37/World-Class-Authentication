/**
 * Extended Session interface with isActive property
 * Extends the base Session model with additional computed properties
 */
import { Session as BaseSession } from '../../data/models/session.model';

export interface Session extends Omit<BaseSession, 'isRevoked'> {
  /**
   * Indicates if the session is active (not revoked)
   * This is a computed property based on the isRevoked flag
   */
  isActive: boolean;

  /**
   * Original isRevoked property from the base session
   */
  isRevoked: boolean;
}

/**
 * Helper function to extend a base session with computed properties
 * @param session Base session object
 * @returns Extended session with computed properties
 */
export function extendSession(session: BaseSession): Session {
  // Create a new object with all properties from the base session
  const extendedSession = { ...session } as Session;

  // Define the isActive property as a getter
  Object.defineProperty(extendedSession, 'isActive', {
    get: function () {
      return !this.isRevoked;
    },
    enumerable: true,
    configurable: true,
  });

  return extendedSession;
}
