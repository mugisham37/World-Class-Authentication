import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';
import { validateEnvVars } from '../utils/env-validator';

// Initialize environment
env.initialize();

// Define compliance config schema with Zod
const complianceConfigSchema = z.object({
  // GDPR configuration
  gdpr: z.object({
    enabled: z.boolean().default(false),
    dataRetentionPeriod: z.number().int().positive().default(730), // 2 years
    dataRetention: z.object({
      userAccounts: z
        .number()
        .int()
        .positive()
        .default(365 * 2), // 2 years
      userActivity: z.number().int().positive().default(365), // 1 year
      auditLogs: z
        .number()
        .int()
        .positive()
        .default(365 * 3), // 3 years
      backups: z.number().int().positive().default(90), // 90 days
    }),
    verificationTokenTtl: z.number().int().positive().default(86400), // 24 hours
    requireVerification: z.boolean().default(true),
    allowDataPortability: z.boolean().default(true),
    allowDataRectification: z.boolean().default(true),
    allowDataDeletion: z.boolean().default(true),
    allowDataAccess: z.boolean().default(true),
    allowObjection: z.boolean().default(true),
    allowRestriction: z.boolean().default(true),
    allowAutomatedDecisionMaking: z.boolean().default(false),
    dataProcessingAgreementUrl: z.string().default(''),
    dpoContact: z.string().email().default('dpo@example.com'),
    dpaContact: z.string().email().default('dpa@example.com'),
    dataSubjectRights: z.object({
      accessRequestEnabled: z.boolean().default(true),
      deletionRequestEnabled: z.boolean().default(true),
      rectificationRequestEnabled: z.boolean().default(true),
      restrictionRequestEnabled: z.boolean().default(true),
      portabilityRequestEnabled: z.boolean().default(true),
      objectionRequestEnabled: z.boolean().default(true),
      verificationRequired: z.boolean().default(true),
      processingTimeLimit: z.number().int().positive().default(30), // 30 days
    }),
    verification: z.object({
      tokenTtl: z
        .number()
        .int()
        .positive()
        .default(24 * 60 * 60), // 24 hours
      emailVerificationRequired: z.boolean().default(true),
      phoneVerificationEnabled: z.boolean().default(false),
    }),
    dataProtection: z.object({
      pseudonymizationEnabled: z.boolean().default(true),
      anonymizationEnabled: z.boolean().default(true),
      encryptionRequired: z.boolean().default(true),
      dataMinimizationEnabled: z.boolean().default(true),
    }),
    consent: z.object({
      required: z.boolean().default(true),
      expiration: z.number().int().nonnegative().default(365), // 1 year
      recordsRetention: z
        .number()
        .int()
        .positive()
        .default(365 * 5), // 5 years
    }),
    breach: z.object({
      notificationEnabled: z.boolean().default(true),
      notificationDeadline: z.number().int().positive().default(72), // 72 hours
      recordsRetention: z
        .number()
        .int()
        .positive()
        .default(365 * 5), // 5 years
    }),
  }),

  // CCPA configuration
  ccpa: z.object({
    enabled: z.boolean().default(false),
    dataRetentionPeriod: z.number().int().positive().default(730), // 2 years
    verificationTokenTtl: z.number().int().positive().default(86400), // 24 hours
    requireVerification: z.boolean().default(true),
    allowDataPortability: z.boolean().default(true),
    allowDataDeletion: z.boolean().default(true),
    allowDataAccess: z.boolean().default(true),
    allowOptOutOfSale: z.boolean().default(true),
    allowOptOutOfSharing: z.boolean().default(true),
    allowLimitUseOfSensitiveInfo: z.boolean().default(true),
    privacyPolicyUrl: z.string().default(''),
    privacyRightsRequestUrl: z.string().default(''),
    doNotSellEnabled: z.boolean().default(true),
    optOutEnabled: z.boolean().default(true),
    dataRetention: z.number().int().positive().default(365), // 1 year
  }),

  // HIPAA configuration
  hipaa: z.object({
    enabled: z.boolean().default(false),
    enablePhiLogging: z.boolean().default(false),
    enablePhiEncryption: z.boolean().default(true),
    enablePhiAccessControls: z.boolean().default(true),
    enablePhiAuditTrails: z.boolean().default(true),
    enableEmergencyAccess: z.boolean().default(false),
    businessAssociateAgreementUrl: z.string().default(''),
    privacyOfficerContact: z.string().email().default('privacy@example.com'),
    securityOfficerContact: z.string().email().default('security@example.com'),
    dataRetention: z
      .number()
      .int()
      .positive()
      .default(365 * 6), // 6 years
    auditRetention: z
      .number()
      .int()
      .positive()
      .default(365 * 6), // 6 years
  }),

  // PCI DSS configuration
  pciDss: z.object({
    enabled: z.boolean().default(false),
    enableCardholderDataLogging: z.boolean().default(false),
    enableCardholderDataEncryption: z.boolean().default(true),
    enableCardholderDataAccessControls: z.boolean().default(true),
    enableCardholderDataAuditTrails: z.boolean().default(true),
    complianceLevel: z.string().default('SAQ A'),
    attestationOfComplianceUrl: z.string().default(''),
    complianceOfficerContact: z.string().email().default('compliance@example.com'),
  }),

  // PCI configuration (alias for pciDss)
  pci: z.object({
    enabled: z.boolean().default(false),
    dataRetention: z.number().int().positive().default(365), // 1 year
    maskingEnabled: z.boolean().default(true),
  }),

  // SOC2 configuration
  soc2: z.object({
    enabled: z.boolean().default(false),
    enableSecurityMonitoring: z.boolean().default(true),
    enableAvailabilityMonitoring: z.boolean().default(true),
    enableProcessingIntegrityMonitoring: z.boolean().default(true),
    enableConfidentialityMonitoring: z.boolean().default(true),
    enablePrivacyMonitoring: z.boolean().default(true),
    reportUrl: z.string().default(''),
    complianceOfficerContact: z.string().email().default('compliance@example.com'),
  }),

  // Reporting configuration
  reporting: z.object({
    enabled: z.boolean().default(true),
    scheduledReports: z.boolean().default(true),
    reportRetention: z
      .number()
      .int()
      .positive()
      .default(365 * 2), // 2 years
  }),
});

// Parse and validate environment variables
const rawConfig = {
  // GDPR configuration
  gdpr: {
    enabled: env.getBoolean('GDPR_ENABLED', false),
    dataRetentionPeriod: env.getNumber('GDPR_DATA_RETENTION_PERIOD', 730),
    dataRetention: {
      userAccounts: env.getNumber('COMPLIANCE_GDPR_RETENTION_USER_ACCOUNTS', 365 * 2),
      userActivity: env.getNumber('COMPLIANCE_GDPR_RETENTION_USER_ACTIVITY', 365),
      auditLogs: env.getNumber('COMPLIANCE_GDPR_RETENTION_AUDIT_LOGS', 365 * 3),
      backups: env.getNumber('COMPLIANCE_GDPR_RETENTION_BACKUPS', 90),
    },
    verificationTokenTtl: env.getNumber('GDPR_VERIFICATION_TOKEN_TTL', 86400),
    requireVerification: env.getBoolean('GDPR_REQUIRE_VERIFICATION', true),
    allowDataPortability: env.getBoolean('GDPR_ALLOW_DATA_PORTABILITY', true),
    allowDataRectification: env.getBoolean('GDPR_ALLOW_DATA_RECTIFICATION', true),
    allowDataDeletion: env.getBoolean('GDPR_ALLOW_DATA_DELETION', true),
    allowDataAccess: env.getBoolean('GDPR_ALLOW_DATA_ACCESS', true),
    allowObjection: env.getBoolean('GDPR_ALLOW_OBJECTION', true),
    allowRestriction: env.getBoolean('GDPR_ALLOW_RESTRICTION', true),
    allowAutomatedDecisionMaking: env.getBoolean('GDPR_ALLOW_AUTOMATED_DECISION_MAKING', false),
    dataProcessingAgreementUrl: env.get('GDPR_DATA_PROCESSING_AGREEMENT_URL', ''),
    dpoContact: env.get('GDPR_DPO_CONTACT', 'dpo@example.com'),
    dpaContact: env.get('GDPR_DPA_CONTACT', 'dpa@example.com'),
    dataSubjectRights: {
      accessRequestEnabled: env.getBoolean('COMPLIANCE_GDPR_ACCESS_REQUEST_ENABLED', true),
      deletionRequestEnabled: env.getBoolean('COMPLIANCE_GDPR_DELETION_REQUEST_ENABLED', true),
      rectificationRequestEnabled: env.getBoolean(
        'COMPLIANCE_GDPR_RECTIFICATION_REQUEST_ENABLED',
        true
      ),
      restrictionRequestEnabled: env.getBoolean(
        'COMPLIANCE_GDPR_RESTRICTION_REQUEST_ENABLED',
        true
      ),
      portabilityRequestEnabled: env.getBoolean(
        'COMPLIANCE_GDPR_PORTABILITY_REQUEST_ENABLED',
        true
      ),
      objectionRequestEnabled: env.getBoolean('COMPLIANCE_GDPR_OBJECTION_REQUEST_ENABLED', true),
      verificationRequired: env.getBoolean('COMPLIANCE_GDPR_VERIFICATION_REQUIRED', true),
      processingTimeLimit: env.getNumber('COMPLIANCE_GDPR_PROCESSING_TIME_LIMIT', 30),
    },
    verification: {
      tokenTtl: env.getNumber('COMPLIANCE_GDPR_VERIFICATION_TOKEN_TTL', 24 * 60 * 60),
      emailVerificationRequired: env.getBoolean(
        'COMPLIANCE_GDPR_EMAIL_VERIFICATION_REQUIRED',
        true
      ),
      phoneVerificationEnabled: env.getBoolean('COMPLIANCE_GDPR_PHONE_VERIFICATION_ENABLED', false),
    },
    dataProtection: {
      pseudonymizationEnabled: env.getBoolean('COMPLIANCE_GDPR_PSEUDONYMIZATION_ENABLED', true),
      anonymizationEnabled: env.getBoolean('COMPLIANCE_GDPR_ANONYMIZATION_ENABLED', true),
      encryptionRequired: env.getBoolean('COMPLIANCE_GDPR_ENCRYPTION_REQUIRED', true),
      dataMinimizationEnabled: env.getBoolean('COMPLIANCE_GDPR_DATA_MINIMIZATION_ENABLED', true),
    },
    consent: {
      required: env.getBoolean('COMPLIANCE_GDPR_CONSENT_REQUIRED', true),
      expiration: env.getNumber('COMPLIANCE_GDPR_CONSENT_EXPIRATION', 365),
      recordsRetention: env.getNumber('COMPLIANCE_GDPR_CONSENT_RECORDS_RETENTION', 365 * 5),
    },
    breach: {
      notificationEnabled: env.getBoolean('COMPLIANCE_GDPR_BREACH_NOTIFICATION_ENABLED', true),
      notificationDeadline: env.getNumber('COMPLIANCE_GDPR_BREACH_NOTIFICATION_DEADLINE', 72),
      recordsRetention: env.getNumber('COMPLIANCE_GDPR_BREACH_RECORDS_RETENTION', 365 * 5),
    },
  },

  // CCPA configuration
  ccpa: {
    enabled: env.getBoolean('CCPA_ENABLED', false),
    dataRetentionPeriod: env.getNumber('CCPA_DATA_RETENTION_PERIOD', 730),
    verificationTokenTtl: env.getNumber('CCPA_VERIFICATION_TOKEN_TTL', 86400),
    requireVerification: env.getBoolean('CCPA_REQUIRE_VERIFICATION', true),
    allowDataPortability: env.getBoolean('CCPA_ALLOW_DATA_PORTABILITY', true),
    allowDataDeletion: env.getBoolean('CCPA_ALLOW_DATA_DELETION', true),
    allowDataAccess: env.getBoolean('CCPA_ALLOW_DATA_ACCESS', true),
    allowOptOutOfSale: env.getBoolean('CCPA_ALLOW_OPT_OUT_OF_SALE', true),
    allowOptOutOfSharing: env.getBoolean('CCPA_ALLOW_OPT_OUT_OF_SHARING', true),
    allowLimitUseOfSensitiveInfo: env.getBoolean('CCPA_ALLOW_LIMIT_USE_OF_SENSITIVE_INFO', true),
    privacyPolicyUrl: env.get('CCPA_PRIVACY_POLICY_URL', ''),
    privacyRightsRequestUrl: env.get('CCPA_PRIVACY_RIGHTS_REQUEST_URL', ''),
    doNotSellEnabled: env.getBoolean('COMPLIANCE_CCPA_DO_NOT_SELL_ENABLED', true),
    optOutEnabled: env.getBoolean('COMPLIANCE_CCPA_OPT_OUT_ENABLED', true),
    dataRetention: env.getNumber('COMPLIANCE_CCPA_DATA_RETENTION', 365),
  },

  // HIPAA configuration
  hipaa: {
    enabled: env.getBoolean('HIPAA_ENABLED', false),
    enablePhiLogging: env.getBoolean('HIPAA_ENABLE_PHI_LOGGING', false),
    enablePhiEncryption: env.getBoolean('HIPAA_ENABLE_PHI_ENCRYPTION', true),
    enablePhiAccessControls: env.getBoolean('HIPAA_ENABLE_PHI_ACCESS_CONTROLS', true),
    enablePhiAuditTrails: env.getBoolean('HIPAA_ENABLE_PHI_AUDIT_TRAILS', true),
    enableEmergencyAccess: env.getBoolean('HIPAA_ENABLE_EMERGENCY_ACCESS', false),
    businessAssociateAgreementUrl: env.get('HIPAA_BUSINESS_ASSOCIATE_AGREEMENT_URL', ''),
    privacyOfficerContact: env.get('HIPAA_PRIVACY_OFFICER_CONTACT', 'privacy@example.com'),
    securityOfficerContact: env.get('HIPAA_SECURITY_OFFICER_CONTACT', 'security@example.com'),
    dataRetention: env.getNumber('COMPLIANCE_HIPAA_DATA_RETENTION', 365 * 6),
    auditRetention: env.getNumber('COMPLIANCE_HIPAA_AUDIT_RETENTION', 365 * 6),
  },

  // PCI DSS configuration
  pciDss: {
    enabled: env.getBoolean('PCI_DSS_ENABLED', false),
    enableCardholderDataLogging: env.getBoolean('PCI_DSS_ENABLE_CARDHOLDER_DATA_LOGGING', false),
    enableCardholderDataEncryption: env.getBoolean(
      'PCI_DSS_ENABLE_CARDHOLDER_DATA_ENCRYPTION',
      true
    ),
    enableCardholderDataAccessControls: env.getBoolean(
      'PCI_DSS_ENABLE_CARDHOLDER_DATA_ACCESS_CONTROLS',
      true
    ),
    enableCardholderDataAuditTrails: env.getBoolean(
      'PCI_DSS_ENABLE_CARDHOLDER_DATA_AUDIT_TRAILS',
      true
    ),
    complianceLevel: env.get('PCI_DSS_COMPLIANCE_LEVEL', 'SAQ A'),
    attestationOfComplianceUrl: env.get('PCI_DSS_ATTESTATION_OF_COMPLIANCE_URL', ''),
    complianceOfficerContact: env.get(
      'PCI_DSS_COMPLIANCE_OFFICER_CONTACT',
      'compliance@example.com'
    ),
  },

  // PCI configuration (alias for pciDss)
  pci: {
    enabled: env.getBoolean('COMPLIANCE_PCI_ENABLED', false),
    dataRetention: env.getNumber('COMPLIANCE_PCI_DATA_RETENTION', 365),
    maskingEnabled: env.getBoolean('COMPLIANCE_PCI_MASKING_ENABLED', true),
  },

  // SOC2 configuration
  soc2: {
    enabled: env.getBoolean('SOC2_ENABLED', false),
    enableSecurityMonitoring: env.getBoolean('SOC2_ENABLE_SECURITY_MONITORING', true),
    enableAvailabilityMonitoring: env.getBoolean('SOC2_ENABLE_AVAILABILITY_MONITORING', true),
    enableProcessingIntegrityMonitoring: env.getBoolean(
      'SOC2_ENABLE_PROCESSING_INTEGRITY_MONITORING',
      true
    ),
    enableConfidentialityMonitoring: env.getBoolean('SOC2_ENABLE_CONFIDENTIALITY_MONITORING', true),
    enablePrivacyMonitoring: env.getBoolean('SOC2_ENABLE_PRIVACY_MONITORING', true),
    reportUrl: env.get('SOC2_REPORT_URL', ''),
    complianceOfficerContact: env.get('SOC2_COMPLIANCE_OFFICER_CONTACT', 'compliance@example.com'),
  },

  // Reporting configuration
  reporting: {
    enabled: env.getBoolean('COMPLIANCE_REPORTING_ENABLED', true),
    scheduledReports: env.getBoolean('COMPLIANCE_SCHEDULED_REPORTS_ENABLED', true),
    reportRetention: env.getNumber('COMPLIANCE_REPORT_RETENTION', 365 * 2),
  },
};

// Define critical environment variables that must be present
const requiredEnvVars: string[] = [];

// Define optional environment variables
const optionalEnvVars: string[] = [
  'GDPR_ENABLED',
  'GDPR_DATA_RETENTION_PERIOD',
  'GDPR_VERIFICATION_TOKEN_TTL',
  'GDPR_REQUIRE_VERIFICATION',
  'GDPR_ALLOW_DATA_PORTABILITY',
  'GDPR_ALLOW_DATA_RECTIFICATION',
  'GDPR_ALLOW_DATA_DELETION',
  'GDPR_ALLOW_DATA_ACCESS',
  'GDPR_ALLOW_OBJECTION',
  'GDPR_ALLOW_RESTRICTION',
  'GDPR_ALLOW_AUTOMATED_DECISION_MAKING',
  'GDPR_DATA_PROCESSING_AGREEMENT_URL',
  'GDPR_DPO_CONTACT',
  'GDPR_DPA_CONTACT',
  'CCPA_ENABLED',
  'CCPA_DATA_RETENTION_PERIOD',
  'CCPA_VERIFICATION_TOKEN_TTL',
  'CCPA_REQUIRE_VERIFICATION',
  'CCPA_ALLOW_DATA_PORTABILITY',
  'CCPA_ALLOW_DATA_DELETION',
  'CCPA_ALLOW_DATA_ACCESS',
  'CCPA_ALLOW_OPT_OUT_OF_SALE',
  'CCPA_ALLOW_OPT_OUT_OF_SHARING',
  'CCPA_ALLOW_LIMIT_USE_OF_SENSITIVE_INFO',
  'CCPA_PRIVACY_POLICY_URL',
  'CCPA_PRIVACY_RIGHTS_REQUEST_URL',
  'HIPAA_ENABLED',
  'HIPAA_ENABLE_PHI_LOGGING',
  'HIPAA_ENABLE_PHI_ENCRYPTION',
  'HIPAA_ENABLE_PHI_ACCESS_CONTROLS',
  'HIPAA_ENABLE_PHI_AUDIT_TRAILS',
  'HIPAA_ENABLE_EMERGENCY_ACCESS',
  'HIPAA_BUSINESS_ASSOCIATE_AGREEMENT_URL',
  'HIPAA_PRIVACY_OFFICER_CONTACT',
  'HIPAA_SECURITY_OFFICER_CONTACT',
  'PCI_DSS_ENABLED',
  'PCI_DSS_ENABLE_CARDHOLDER_DATA_LOGGING',
  'PCI_DSS_ENABLE_CARDHOLDER_DATA_ENCRYPTION',
  'PCI_DSS_ENABLE_CARDHOLDER_DATA_ACCESS_CONTROLS',
  'PCI_DSS_ENABLE_CARDHOLDER_DATA_AUDIT_TRAILS',
  'PCI_DSS_COMPLIANCE_LEVEL',
  'PCI_DSS_ATTESTATION_OF_COMPLIANCE_URL',
  'PCI_DSS_COMPLIANCE_OFFICER_CONTACT',
  'SOC2_ENABLED',
  'SOC2_ENABLE_SECURITY_MONITORING',
  'SOC2_ENABLE_AVAILABILITY_MONITORING',
  'SOC2_ENABLE_PROCESSING_INTEGRITY_MONITORING',
  'SOC2_ENABLE_CONFIDENTIALITY_MONITORING',
  'SOC2_ENABLE_PRIVACY_MONITORING',
  'SOC2_REPORT_URL',
  'SOC2_COMPLIANCE_OFFICER_CONTACT',
  'COMPLIANCE_GDPR_RETENTION_USER_ACCOUNTS',
  'COMPLIANCE_GDPR_RETENTION_USER_ACTIVITY',
  'COMPLIANCE_GDPR_RETENTION_AUDIT_LOGS',
  'COMPLIANCE_GDPR_RETENTION_BACKUPS',
  'COMPLIANCE_GDPR_ACCESS_REQUEST_ENABLED',
  'COMPLIANCE_GDPR_DELETION_REQUEST_ENABLED',
  'COMPLIANCE_GDPR_RECTIFICATION_REQUEST_ENABLED',
  'COMPLIANCE_GDPR_RESTRICTION_REQUEST_ENABLED',
  'COMPLIANCE_GDPR_PORTABILITY_REQUEST_ENABLED',
  'COMPLIANCE_GDPR_OBJECTION_REQUEST_ENABLED',
  'COMPLIANCE_GDPR_VERIFICATION_REQUIRED',
  'COMPLIANCE_GDPR_PROCESSING_TIME_LIMIT',
  'COMPLIANCE_GDPR_VERIFICATION_TOKEN_TTL',
  'COMPLIANCE_GDPR_EMAIL_VERIFICATION_REQUIRED',
  'COMPLIANCE_GDPR_PHONE_VERIFICATION_ENABLED',
  'COMPLIANCE_GDPR_PSEUDONYMIZATION_ENABLED',
  'COMPLIANCE_GDPR_ANONYMIZATION_ENABLED',
  'COMPLIANCE_GDPR_ENCRYPTION_REQUIRED',
  'COMPLIANCE_GDPR_DATA_MINIMIZATION_ENABLED',
  'COMPLIANCE_GDPR_CONSENT_REQUIRED',
  'COMPLIANCE_GDPR_CONSENT_EXPIRATION',
  'COMPLIANCE_GDPR_CONSENT_RECORDS_RETENTION',
  'COMPLIANCE_GDPR_BREACH_NOTIFICATION_ENABLED',
  'COMPLIANCE_GDPR_BREACH_NOTIFICATION_DEADLINE',
  'COMPLIANCE_GDPR_BREACH_RECORDS_RETENTION',
  'COMPLIANCE_CCPA_DO_NOT_SELL_ENABLED',
  'COMPLIANCE_CCPA_OPT_OUT_ENABLED',
  'COMPLIANCE_CCPA_DATA_RETENTION',
  'COMPLIANCE_HIPAA_DATA_RETENTION',
  'COMPLIANCE_HIPAA_AUDIT_RETENTION',
  'COMPLIANCE_PCI_ENABLED',
  'COMPLIANCE_PCI_DATA_RETENTION',
  'COMPLIANCE_PCI_MASKING_ENABLED',
  'COMPLIANCE_REPORTING_ENABLED',
  'COMPLIANCE_SCHEDULED_REPORTS_ENABLED',
  'COMPLIANCE_REPORT_RETENTION',
];

// Validate environment variables
validateEnvVars(requiredEnvVars, optionalEnvVars);

// Validate and export config
export const complianceConfig = validateConfig(complianceConfigSchema, rawConfig);

// Export config type
export type ComplianceConfig = typeof complianceConfig;

// Export for backward compatibility
export { complianceConfig as complianceConfiguration };
