/**
 * Compliance event types
 */
export enum ComplianceEvent {
  // GDPR events
  DATA_ACCESS_REQUESTED = 'gdpr:data:access:requested',
  DATA_ACCESS_VERIFIED = 'gdpr:data:access:verified',
  DATA_ACCESS_COMPLETED = 'gdpr:data:access:completed',
  DATA_DELETION_REQUESTED = 'gdpr:data:deletion:requested',
  DATA_DELETION_VERIFIED = 'gdpr:data:deletion:verified',
  DATA_DELETION_COMPLETED = 'gdpr:data:deletion:completed',

  // CCPA/CPRA events
  CCPA_OPT_OUT_REQUESTED = 'ccpa:opt-out:requested',
  CCPA_OPT_OUT_COMPLETED = 'ccpa:opt-out:completed',
  CCPA_DO_NOT_SELL_REQUESTED = 'ccpa:do-not-sell:requested',
  CCPA_DO_NOT_SELL_COMPLETED = 'ccpa:do-not-sell:completed',

  // HIPAA events
  PHI_ACCESS_REQUESTED = 'hipaa:phi:access:requested',
  PHI_ACCESS_GRANTED = 'hipaa:phi:access:granted',
  PHI_ACCESS_DENIED = 'hipaa:phi:access:denied',

  // PCI DSS events
  CARDHOLDER_DATA_ACCESSED = 'pci:cardholder-data:accessed',
  CARDHOLDER_DATA_STORED = 'pci:cardholder-data:stored',
  CARDHOLDER_DATA_DELETED = 'pci:cardholder-data:deleted',

  // General compliance events
  COMPLIANCE_REPORT_GENERATED = 'compliance:report:generated',
  COMPLIANCE_VIOLATION_DETECTED = 'compliance:violation:detected',
  COMPLIANCE_REMEDIATION_COMPLETED = 'compliance:remediation:completed',
}
