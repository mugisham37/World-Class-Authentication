/**
 * MFA Configuration
 * Configuration for Multi-Factor Authentication
 */

/**
 * MFA Configuration Type
 * Type definition for the Multi-Factor Authentication configuration
 */
export type MfaConfig = {
  general: {
    maxActiveMethods: number;
    challengeExpiration: number;
    maxFailedAttempts: number;
    adaptiveMfaEnabled: boolean;
    rememberDeviceEnabled: boolean;
    rememberDeviceDays: number;
  };
  totp: {
    issuer: string;
    secretLength: number;
    digits: number;
    stepSeconds: number;
    window: number;
    algorithm: string;
  };
  webAuthn: {
    rpName: string;
    rpID: string;
    origin: string;
    attestation: string;
    userVerification: string;
    timeout: number;
  };
  sms: {
    provider: string;
    codeLength: number;
    expiration: number;
    rateLimit: {
      max: number;
      period: number;
    };
  };
  email: {
    codeLength: number;
    expiration: number;
    rateLimit: {
      max: number;
      period: number;
    };
  };
  pushNotification: {
    provider: string;
    expiration: number;
    rateLimit: {
      max: number;
      period: number;
    };
  };
  recoveryCodes: {
    count: number;
    expireEnabled: boolean;
    expireDays: number;
  };
};

export const mfaConfig = {
  /**
   * General MFA settings
   */
  general: {
    /**
     * Maximum number of active MFA methods per user
     */
    maxActiveMethods: 5,

    /**
     * Challenge expiration time in seconds
     */
    challengeExpiration: 300, // 5 minutes

    /**
     * Maximum number of failed attempts before challenge is locked
     */
    maxFailedAttempts: 5,

    /**
     * Whether to enable adaptive MFA
     * If enabled, MFA requirements will be adjusted based on risk assessment
     */
    adaptiveMfaEnabled: true,

    /**
     * Whether to allow remembering devices
     * If enabled, users can skip MFA on trusted devices
     */
    rememberDeviceEnabled: true,

    /**
     * How long to remember devices in days
     */
    rememberDeviceDays: 30,
  },

  /**
   * TOTP settings
   */
  totp: {
    /**
     * Issuer name for TOTP
     * This will be displayed in authenticator apps
     */
    issuer: 'World-Class-Authentication',

    /**
     * Secret length in bytes
     */
    secretLength: 20,

    /**
     * Number of digits in TOTP code
     */
    digits: 6,

    /**
     * Time step in seconds
     */
    stepSeconds: 30,

    /**
     * Time window for TOTP verification
     * Number of time steps to check before and after current time
     */
    window: 1,

    /**
     * Hash algorithm for TOTP
     */
    algorithm: 'sha1', // sha1, sha256, sha512
  },

  /**
   * WebAuthn settings
   */
  webAuthn: {
    /**
     * Relying Party name
     */
    rpName: 'World-Class-Authentication',

    /**
     * Relying Party ID
     * Should be the domain name without protocol or port
     */
    rpID: 'localhost',

    /**
     * Origin for WebAuthn
     * Should be the full URL of the site
     */
    origin: 'http://localhost:3000',

    /**
     * Attestation type
     */
    attestation: 'none', // none, indirect, direct

    /**
     * User verification requirement
     */
    userVerification: 'preferred', // required, preferred, discouraged

    /**
     * Timeout in milliseconds
     */
    timeout: 60000, // 1 minute
  },

  /**
   * SMS settings
   */
  sms: {
    /**
     * SMS provider
     */
    provider: 'twilio', // twilio, aws, etc.

    /**
     * Code length
     */
    codeLength: 6,

    /**
     * Code expiration in seconds
     */
    expiration: 300, // 5 minutes

    /**
     * Rate limit for SMS sending
     * Maximum number of SMS that can be sent in a time period
     */
    rateLimit: {
      /**
       * Maximum number of SMS per period
       */
      max: 5,

      /**
       * Time period in seconds
       */
      period: 3600, // 1 hour
    },
  },

  /**
   * Email settings
   */
  email: {
    /**
     * Code length
     */
    codeLength: 6,

    /**
     * Code expiration in seconds
     */
    expiration: 300, // 5 minutes

    /**
     * Rate limit for email sending
     * Maximum number of emails that can be sent in a time period
     */
    rateLimit: {
      /**
       * Maximum number of emails per period
       */
      max: 5,

      /**
       * Time period in seconds
       */
      period: 3600, // 1 hour
    },
  },

  /**
   * Push notification settings
   */
  pushNotification: {
    /**
     * Push notification provider
     */
    provider: 'firebase', // firebase, apns, etc.

    /**
     * Challenge expiration in seconds
     */
    expiration: 60, // 1 minute

    /**
     * Rate limit for push notifications
     * Maximum number of push notifications that can be sent in a time period
     */
    rateLimit: {
      /**
       * Maximum number of push notifications per period
       */
      max: 10,

      /**
       * Time period in seconds
       */
      period: 3600, // 1 hour
    },
  },

  /**
   * Recovery codes settings
   */
  recoveryCodes: {
    /**
     * Number of recovery codes to generate
     */
    count: 10,

    /**
     * Whether to expire recovery codes
     */
    expireEnabled: false,

    /**
     * Expiration time in days
     * Only used if expireEnabled is true
     */
    expireDays: 365, // 1 year
  },
} as MfaConfig;
