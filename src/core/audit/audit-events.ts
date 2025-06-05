/**
 * Audit event types
 */
export enum AuditEvent {
  // Audit log events
  AUDIT_LOG_CREATED = "audit:log:created",
  AUDIT_LOG_UPDATED = "audit:log:updated",
  AUDIT_LOG_DELETED = "audit:log:deleted",

  // Security incident events
  SECURITY_INCIDENT_DETECTED = "security:incident:detected",
  SECURITY_INCIDENT_RESOLVED = "security:incident:resolved",

  // Compliance events
  COMPLIANCE_REPORT_GENERATED = "compliance:report:generated",
  COMPLIANCE_VIOLATION_DETECTED = "compliance:violation:detected",
  COMPLIANCE_REMEDIATION_COMPLETED = "compliance:remediation:completed",

  // Data privacy events
  DATA_ACCESS_REQUESTED = "data:access:requested",
  DATA_ACCESS_GRANTED = "data:access:granted",
  DATA_ACCESS_DENIED = "data:access:denied",
  DATA_DELETION_REQUESTED = "data:deletion:requested",
  DATA_DELETION_COMPLETED = "data:deletion:completed",

  // Monitoring events
  MONITORING_ALERT_TRIGGERED = "monitoring:alert:triggered",
  MONITORING_ALERT_RESOLVED = "monitoring:alert:resolved",
}
