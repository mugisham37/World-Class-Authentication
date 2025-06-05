/**
 * Options for SMS OTP operations
 */
export interface SmsOtpOptions {
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
  
  /**
   * Additional metadata
   */
  metadata?: Record<string, unknown>;
}
