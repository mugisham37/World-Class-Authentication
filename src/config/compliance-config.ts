import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();

// Define compliance config schema with Zod
const complianceConfigSchema = z.object({
  gdpr: z.object({
    enabled: z.boolean().default(false),
    dataRetentionPeriod: z.number().int().positive().default(730), // 2 years
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
  }),
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
  }),
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
  }),
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
});

// Parse and validate environment variables
const rawConfig = {
  gdpr: {
    enabled: env.getBoolean('GDPR_ENABLED'),
    dataRetentionPeriod: env.getNumber('GDPR_DATA_RETENTION_PERIOD'),
    verificationTokenTtl: env.getNumber('GDPR_VERIFICATION_TOKEN_TTL'),
    requireVerification: env.getBoolean('GDPR_REQUIRE_VERIFICATION'),
    allowDataPortability: env.getBoolean('GDPR_ALLOW_DATA_PORTABILITY'),
    allowDataRectification: env.getBoolean('GDPR_ALLOW_DATA_RECTIFICATION'),
    allowDataDeletion: env.getBoolean('GDPR_ALLOW_DATA_DELETION'),
    allowDataAccess: env.getBoolean('GDPR_ALLOW_DATA_ACCESS'),
    allowObjection: env.getBoolean('GDPR_ALLOW_OBJECTION'),
    allowRestriction: env.getBoolean('GDPR_ALLOW_RESTRICTION'),
    allowAutomatedDecisionMaking: env.getBoolean('GDPR_ALLOW_AUTOMATED_DECISION_MAKING'),
    dataProcessingAgreementUrl: env.get('GDPR_DATA_PROCESSING_AGREEMENT_URL'),
    dpoContact: env.get('GDPR_DPO_CONTACT'),
    dpaContact: env.get('GDPR_DPA_CONTACT'),
  },
  ccpa: {
    enabled: env.getBoolean('CCPA_ENABLED'),
    dataRetentionPeriod: env.getNumber('CCPA_DATA_RETENTION_PERIOD'),
    verificationTokenTtl: env.getNumber('CCPA_VERIFICATION_TOKEN_TTL'),
    requireVerification: env.getBoolean('CCPA_REQUIRE_VERIFICATION'),
    allowDataPortability: env.getBoolean('CCPA_ALLOW_DATA_PORTABILITY'),
    allowDataDeletion: env.getBoolean('CCPA_ALLOW_DATA_DELETION'),
    allowDataAccess: env.getBoolean('CCPA_ALLOW_DATA_ACCESS'),
    allowOptOutOfSale: env.getBoolean('CCPA_ALLOW_OPT_OUT_OF_SALE'),
    allowOptOutOfSharing: env.getBoolean('CCPA_ALLOW_OPT_OUT_OF_SHARING'),
    allowLimitUseOfSensitiveInfo: env.getBoolean('CCPA_ALLOW_LIMIT_USE_OF_SENSITIVE_INFO'),
    privacyPolicyUrl: env.get('CCPA_PRIVACY_POLICY_URL'),
    privacyRightsRequestUrl: env.get('CCPA_PRIVACY_RIGHTS_REQUEST_URL'),
  },
  hipaa: {
    enabled: env.getBoolean('HIPAA_ENABLED'),
    enablePhiLogging: env.getBoolean('HIPAA_ENABLE_PHI_LOGGING'),
    enablePhiEncryption: env.getBoolean('HIPAA_ENABLE_PHI_ENCRYPTION'),
    enablePhiAccessControls: env.getBoolean('HIPAA_ENABLE_PHI_ACCESS_CONTROLS'),
    enablePhiAuditTrails: env.getBoolean('HIPAA_ENABLE_PHI_AUDIT_TRAILS'),
    enableEmergencyAccess: env.getBoolean('HIPAA_ENABLE_EMERGENCY_ACCESS'),
    businessAssociateAgreementUrl: env.get('HIPAA_BUSINESS_ASSOCIATE_AGREEMENT_URL'),
    privacyOfficerContact: env.get('HIPAA_PRIVACY_OFFICER_CONTACT'),
    securityOfficerContact: env.get('HIPAA_SECURITY_OFFICER_CONTACT'),
  },
  pciDss: {
    enabled: env.getBoolean('PCI_DSS_ENABLED'),
    enableCardholderDataLogging: env.getBoolean('PCI_DSS_ENABLE_CARDHOLDER_DATA_LOGGING'),
    enableCardholderDataEncryption: env.getBoolean('PCI_DSS_ENABLE_CARDHOLDER_DATA_ENCRYPTION'),
    enableCardholderDataAccessControls: env.getBoolean(
      'PCI_DSS_ENABLE_CARDHOLDER_DATA_ACCESS_CONTROLS'
    ),
    enableCardholderDataAuditTrails: env.getBoolean('PCI_DSS_ENABLE_CARDHOLDER_DATA_AUDIT_TRAILS'),
    complianceLevel: env.get('PCI_DSS_COMPLIANCE_LEVEL'),
    attestationOfComplianceUrl: env.get('PCI_DSS_ATTESTATION_OF_COMPLIANCE_URL'),
    complianceOfficerContact: env.get('PCI_DSS_COMPLIANCE_OFFICER_CONTACT'),
  },
  soc2: {
    enabled: env.getBoolean('SOC2_ENABLED'),
    enableSecurityMonitoring: env.getBoolean('SOC2_ENABLE_SECURITY_MONITORING'),
    enableAvailabilityMonitoring: env.getBoolean('SOC2_ENABLE_AVAILABILITY_MONITORING'),
    enableProcessingIntegrityMonitoring: env.getBoolean(
      'SOC2_ENABLE_PROCESSING_INTEGRITY_MONITORING'
    ),
    enableConfidentialityMonitoring: env.getBoolean('SOC2_ENABLE_CONFIDENTIALITY_MONITORING'),
    enablePrivacyMonitoring: env.getBoolean('SOC2_ENABLE_PRIVACY_MONITORING'),
    reportUrl: env.get('SOC2_REPORT_URL'),
    complianceOfficerContact: env.get('SOC2_COMPLIANCE_OFFICER_CONTACT'),
  },
};

// Validate and export config
export const complianceConfig = validateConfig(complianceConfigSchema, rawConfig);

// Export config type
export type ComplianceConfig = typeof complianceConfig;
