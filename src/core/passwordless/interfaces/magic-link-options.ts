/**
 * Options for magic link operations
 */
export interface MagicLinkOptions {
  /**
   * IP address of the request
   */
  ipAddress?: string;

  /**
   * User agent of the request
   */
  userAgent?: string;

  /**
   * Origin of the request
   */
  origin?: string;

  /**
   * User ID
   */
  userId?: string;

  /**
   * Expiration time in seconds
   */
  expiresIn?: number;
}
