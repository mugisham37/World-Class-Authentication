/**
 * Recovery configuration
 * Defines configuration options for account recovery
 */
export const recoveryConfig = {
  /**
   * General recovery settings
   */
  general: {
    /**
     * Maximum number of concurrent recovery requests per user
     */
    maxConcurrentRecoveries: 1,

    /**
     * Cooldown period between recovery requests in seconds
     */
    cooldownBetweenRecoveries: 300, // 5 minutes

    /**
     * Recovery token length in characters
     */
    recoveryTokenLength: 32,

    /**
     * Recovery token expiration in seconds
     */
    recoveryTokenExpiration: 3600, // 1 hour

    /**
     * Whether to notify the user when a recovery is initiated
     */
    notifyUserOnRecovery: true,

    /**
     * Whether to notify admins when a recovery is initiated
     */
    notifyAdminOnRecovery: true,

    /**
     * Risk threshold for requiring additional verification
     */
    riskThreshold: 0.7,
  },

  /**
   * Email recovery settings
   */
  email: {
    /**
     * Whether email recovery is enabled
     */
    enabled: true,

    /**
     * Verification code length
     */
    codeLength: 6,

    /**
     * Whether to use numeric codes only
     */
    numericCodesOnly: true,

    /**
     * Whether to use secure token for code generation
     */
    useSecureToken: false,

    /**
     * Verification code expiration in seconds
     */
    codeExpiration: 900, // 15 minutes

    /**
     * Maximum number of verification attempts
     */
    maxVerificationAttempts: 5,

    /**
     * Whether to enforce rate limiting for email recovery
     */
    enforceRateLimit: true,

    /**
     * Rate limit window in seconds
     */
    rateLimitWindow: 3600, // 1 hour

    /**
     * Maximum number of attempts within the rate limit window
     */
    rateLimitMaxAttempts: 5,
  },

  /**
   * Security questions settings
   */
  securityQuestions: {
    /**
     * Whether security questions recovery is enabled
     */
    enabled: true,

    /**
     * Minimum number of security questions required
     */
    minQuestions: 3,

    /**
     * Number of questions to ask during recovery
     */
    questionsToAsk: 3,

    /**
     * Minimum number of correct answers required
     */
    minCorrectAnswers: 2,

    /**
     * Whether to enforce minimum answer length
     */
    enforceMinAnswerLength: true,

    /**
     * Minimum answer length in characters
     */
    minAnswerLength: 3,

    /**
     * Whether to use fuzzy matching for answers
     */
    useFuzzyMatching: true,

    /**
     * Fuzzy match threshold (0-1)
     */
    fuzzyMatchThreshold: 0.8,

    /**
     * Whether to rotate questions after use
     */
    rotateQuestionsAfterUse: true,
  },

  /**
   * Trusted contacts settings
   */
  trustedContacts: {
    /**
     * Whether trusted contacts recovery is enabled
     */
    enabled: true,

    /**
     * Minimum number of trusted contacts required for recovery
     */
    minContactsForRecovery: 1,

    /**
     * Maximum number of trusted contacts per user
     */
    maxContacts: 5,

    /**
     * Recovery code length
     */
    codeLength: 8,

    /**
     * Recovery code expiration in seconds
     */
    codeExpiration: 86400, // 24 hours

    /**
     * Whether to require multiple contacts to approve recovery
     */
    requireMultipleApprovals: false,

    /**
     * Number of approvals required if multiple approvals are enabled
     */
    requiredApprovals: 2,
  },

  /**
   * Admin recovery settings
   */
  admin: {
    /**
     * Whether admin recovery is enabled
     */
    enabled: true,

    /**
     * Minimum admin role required for recovery approval
     */
    minApproverRole: "ADMIN", // "ADMIN" or "SUPER_ADMIN"

    /**
     * Whether to require a reason for admin recovery
     */
    requireReason: true,

    /**
     * Whether to require multiple admin approvals
     */
    requireMultipleApprovals: false,

    /**
     * Number of admin approvals required if multiple approvals are enabled
     */
    requiredApprovals: 2,

    /**
     * Whether to notify the user when admin recovery is initiated
     */
    notifyUserOnAdminRecovery: true,
  },

  /**
   * Recovery codes settings
   */
  recoveryCodes: {
    /**
     * Whether recovery codes are enabled
     */
    enabled: true,

    /**
     * Number of recovery codes to generate
     */
    codeCount: 10,

    /**
     * Recovery code length in characters
     */
    codeLength: 10,

    /**
     * Whether to use numeric codes only
     */
    numericCodesOnly: false,

    /**
     * Whether to enforce rate limiting for recovery codes
     */
    enforceRateLimit: true,

    /**
     * Rate limit window in seconds
     */
    rateLimitWindow: 3600, // 1 hour

    /**
     * Maximum number of attempts within the rate limit window
     */
    rateLimitMaxAttempts: 5,
  },

  /**
   * Multi-factor recovery settings
   */
  multiFactorRecovery: {
    /**
     * Whether to require multiple recovery methods for high-risk users
     */
    requireMultipleMethodsForHighRisk: true,

    /**
     * Risk score threshold for requiring multiple methods
     */
    riskThreshold: 0.7,

    /**
     * Number of methods required for high-risk users
     */
    requiredMethodCount: 2,

    /**
     * Whether to allow combining methods for progressive verification
     */
    allowProgressiveVerification: true,
  }
};
