import { Injectable } from "@tsed/di"

import { auditConfig } from "../../config/audit-config"
import { 
  AuditLogRepository, 
  AuditSearchOptions, 
  AuditSearchResult,
  AuditStatisticsOptions 
} from "../../data/repositories/audit-log.repository"
import type { EventEmitter } from "../../infrastructure/events/event-emitter"
import { logger } from "../../infrastructure/logging/logger"
import { AuditEvent } from "./audit-events"
import { AuditStatus, AuditSeverity} from "./types"
import { AuditLog as DataAuditLog } from "../../data/models/audit-log.model"

/**
 * Audit log service
 * Manages comprehensive audit logging for security and compliance
 */
@Injectable()
export class AuditLogService {
  constructor(
    private auditLogRepository: AuditLogRepository,
    private eventEmitter: EventEmitter,
  ) {}

  /**
   * Create a new audit log entry
   * @param data Audit log data
   * @returns Created audit log
   */
  async create(data: {
    userId?: string | null
    action: string
    entityType?: string
    entityId?: string
    metadata?: Record<string, any>
    ipAddress?: string
    userAgent?: string
    status?: AuditStatus
    severity?: AuditSeverity
  }): Promise<DataAuditLog | null> {
    try {
      // Skip audit logging if disabled
      if (!auditConfig.enabled) {
        return null
      }

      // Set default values
      const auditLog = {
        userId: data.userId || null,
        action: data.action,
        entityType: data.entityType || null,
        entityId: data.entityId || null,
        ipAddress: data.ipAddress || null,
        userAgent: data.userAgent || null,
        status: data.status || AuditStatus.SUCCESS,
        // Include severity in metadata
        metadata: {
          ...(data.metadata || {}),
          severity: data.severity || AuditSeverity.INFO
        }
      }

      // Sanitize metadata but ensure severity is preserved
      const sanitizedMetadata = this.sanitizeMetadata(auditLog.metadata)
      auditLog.metadata = {
        ...sanitizedMetadata,
        severity: data.severity || AuditSeverity.INFO
      }

      // Create audit log entry
      const result = await this.auditLogRepository.create(auditLog)

      // Emit audit log created event
      this.eventEmitter.emit(AuditEvent.AUDIT_LOG_CREATED, {
        auditLogId: result.id,
        userId: result.userId,
        action: result.action,
        timestamp: result.createdAt,
      })

      return result
    } catch (error) {
      // Log error but don't throw - audit logging should not disrupt normal operation
      logger.error("Failed to create audit log", { 
        error: error instanceof Error ? error.message : String(error), 
        data 
      })
      return null
    }
  }

  /**
   * Find audit logs by user ID
   * @param userId User ID
   * @param options Query options
   * @returns Audit logs and total count
   */
  async findByUserId(
    userId: string,
    options: {
      page?: number
      limit?: number
      startDate?: Date
      endDate?: Date
      actions?: string[]
      entityTypes?: string[]
      severity?: string[]
      status?: AuditStatus[]
    } = {},
  ): Promise<AuditSearchResult> {
    try {
      const page = options.page || 1
      const limit = options.limit || 20
      const skip = (page - 1) * limit

      // Create search options with proper typing
      const searchOptions: Partial<AuditSearchOptions> = {
        skip,
        limit,
        userId
      }
      
      // Add optional parameters only if they are defined
      if (options.startDate) searchOptions.startDate = options.startDate
      if (options.endDate) searchOptions.endDate = options.endDate
      if (options.actions) searchOptions.actions = options.actions
      if (options.entityTypes) searchOptions.entityTypes = options.entityTypes
      if (options.severity) searchOptions.severity = options.severity
      if (options.status) searchOptions.status = options.status

      return await this.auditLogRepository.search(searchOptions as AuditSearchOptions)
    } catch (error) {
      logger.error("Failed to find audit logs by user ID", { 
        error: error instanceof Error ? error.message : String(error), 
        userId, 
        options 
      })
      return { logs: [], total: 0 }
    }
  }

  /**
   * Find audit logs by entity
   * @param entityType Entity type
   * @param entityId Entity ID
   * @param options Query options
   * @returns Audit logs and total count
   */
  async findByEntity(
    entityType: string,
    entityId: string,
    options: {
      page?: number
      limit?: number
      startDate?: Date
      endDate?: Date
      actions?: string[]
      severity?: string[]
      status?: AuditStatus[]
    } = {},
  ): Promise<AuditSearchResult> {
    try {
      const page = options.page || 1
      const limit = options.limit || 20
      const skip = (page - 1) * limit

      // Create search options with proper typing
      const searchOptions: Partial<AuditSearchOptions> = {
        skip,
        limit,
        entityTypes: [entityType],
        entityIds: [entityId]
      }
      
      // Add optional parameters only if they are defined
      if (options.startDate) searchOptions.startDate = options.startDate
      if (options.endDate) searchOptions.endDate = options.endDate
      if (options.actions) searchOptions.actions = options.actions
      if (options.severity) searchOptions.severity = options.severity
      if (options.status) searchOptions.status = options.status

      return await this.auditLogRepository.search(searchOptions as AuditSearchOptions)
    } catch (error) {
      logger.error("Failed to find audit logs by entity", { 
        error: error instanceof Error ? error.message : String(error), 
        entityType, 
        entityId, 
        options 
      })
      return { logs: [], total: 0 }
    }
  }

  /**
   * Search audit logs
   * @param options Search options
   * @returns Audit logs and total count
   */
  async search(
    options: {
      page?: number
      limit?: number
      startDate?: Date
      endDate?: Date
      userId?: string
      actions?: string[]
      entityTypes?: string[]
      entityIds?: string[]
      severity?: string[]
      status?: AuditStatus[]
      ipAddress?: string
      query?: string
    } = {},
  ): Promise<AuditSearchResult> {
    try {
      const page = options.page || 1
      const limit = options.limit || 20
      const skip = (page - 1) * limit

      // Create search options with proper typing
      const searchOptions: Partial<AuditSearchOptions> = {
        skip,
        limit
      }
      
      // Add optional parameters only if they are defined
      if (options.startDate) searchOptions.startDate = options.startDate
      if (options.endDate) searchOptions.endDate = options.endDate
      if (options.userId) searchOptions.userId = options.userId
      if (options.actions) searchOptions.actions = options.actions
      if (options.entityTypes) searchOptions.entityTypes = options.entityTypes
      if (options.entityIds) searchOptions.entityIds = options.entityIds
      if (options.severity) searchOptions.severity = options.severity
      if (options.status) searchOptions.status = options.status
      if (options.ipAddress) searchOptions.ipAddress = options.ipAddress
      if (options.query) searchOptions.query = options.query

      return await this.auditLogRepository.search(searchOptions as AuditSearchOptions)
    } catch (error) {
      logger.error("Failed to search audit logs", { 
        error: error instanceof Error ? error.message : String(error), 
        options 
      })
      return { logs: [], total: 0 }
    }
  }

  /**
   * Get audit log statistics
   * @param options Statistics options
   * @returns Audit log statistics
   */
  async getStatistics(
    options: {
      startDate?: Date
      endDate?: Date
      userId?: string
      groupBy?: "action" | "entityType" | "severity" | "status" | "hour" | "day" | "week" | "month"
    } = {},
  ): Promise<Record<string, number>> {
    try {
      // Create statistics options with proper typing
      const statisticsOptions: Partial<AuditStatisticsOptions> = {
        groupBy: options.groupBy || "action"
      }
      
      // Add optional parameters only if they are defined
      if (options.startDate) statisticsOptions.startDate = options.startDate
      if (options.endDate) statisticsOptions.endDate = options.endDate
      if (options.userId) statisticsOptions.userId = options.userId
      
      return await this.auditLogRepository.getStatistics(statisticsOptions as AuditStatisticsOptions)
    } catch (error) {
      logger.error("Failed to get audit log statistics", { 
        error: error instanceof Error ? error.message : String(error), 
        options 
      })
      return {}
    }
  }

  /**
   * Get security incidents
   * @param options Incident options
   * @returns Security incidents
   */
  async getSecurityIncidents(
    options: {
      startDate?: Date
      endDate?: Date
      severity?: string[]
      status?: AuditStatus[]
      page?: number
      limit?: number
    } = {},
  ): Promise<AuditSearchResult> {
    try {
      const page = options.page || 1
      const limit = options.limit || 20
      const skip = (page - 1) * limit

      // Security incidents are audit logs with high severity
      const severity = options.severity || ["warning", "error", "critical"]

      // Create search options with proper typing
      const searchOptions: Partial<AuditSearchOptions> = {
        skip,
        limit,
        severity,
        actions: [
          "LOGIN_FAILED",
          "BRUTE_FORCE_DETECTED",
          "SUSPICIOUS_ACTIVITY_DETECTED",
          "ACCOUNT_LOCKED",
          "PASSWORD_RESET_REQUESTED",
          "MFA_VERIFICATION_FAILED",
          "PERMISSION_DENIED",
          "UNAUTHORIZED_ACCESS_ATTEMPT",
          "CONFIGURATION_CHANGED",
          "USER_ROLE_CHANGED",
          "API_KEY_CREATED",
          "API_KEY_DELETED",
        ]
      }
      
      // Add optional parameters only if they are defined
      if (options.startDate) searchOptions.startDate = options.startDate
      if (options.endDate) searchOptions.endDate = options.endDate
      if (options.status) searchOptions.status = options.status
      
      return await this.auditLogRepository.search(searchOptions as AuditSearchOptions)
    } catch (error) {
      logger.error("Failed to get security incidents", { 
        error: error instanceof Error ? error.message : String(error), 
        options 
      })
      return { logs: [], total: 0 }
    }
  }

  /**
   * Generate compliance report
   * @param reportType Report type
   * @param options Report options
   * @returns Compliance report data
   */
  async generateComplianceReport(
    reportType: "access" | "authentication" | "authorization" | "data" | "admin" | "full",
    options: {
      startDate?: Date
      endDate?: Date
      format?: "json" | "csv" | "pdf"
    } = {},
  ): Promise<any> {
    try {
      const startDate = options.startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // Default to last 30 days
      const endDate = options.endDate || new Date()
      const format = options.format || "json"

      // Define actions to include based on report type
      let actions: string[] = []
      let entityTypes: string[] = []

      switch (reportType) {
        case "access":
          actions = [
            "LOGIN_SUCCESS",
            "LOGIN_FAILED",
            "LOGOUT",
            "SESSION_CREATED",
            "SESSION_EXPIRED",
            "SESSION_TERMINATED",
            "MFA_CHALLENGE_GENERATED",
            "MFA_VERIFICATION_SUCCEEDED",
            "MFA_VERIFICATION_FAILED",
          ]
          break
        case "authentication":
          actions = [
            "USER_REGISTERED",
            "LOGIN_SUCCESS",
            "LOGIN_FAILED",
            "PASSWORD_CHANGED",
            "PASSWORD_RESET_REQUESTED",
            "PASSWORD_RESET_COMPLETED",
            "MFA_FACTOR_ENROLLED",
            "MFA_FACTOR_REMOVED",
            "MFA_VERIFICATION_SUCCEEDED",
            "MFA_VERIFICATION_FAILED",
          ]
          break
        case "authorization":
          actions = [
            "PERMISSION_GRANTED",
            "PERMISSION_DENIED",
            "ROLE_ASSIGNED",
            "ROLE_REMOVED",
            "POLICY_CREATED",
            "POLICY_UPDATED",
            "POLICY_DELETED",
          ]
          entityTypes = ["PERMISSION", "ROLE", "POLICY"]
          break
        case "data":
          actions = ["DATA_ACCESSED", "DATA_CREATED", "DATA_UPDATED", "DATA_DELETED", "DATA_EXPORTED", "DATA_IMPORTED"]
          break
        case "admin":
          actions = [
            "USER_CREATED",
            "USER_UPDATED",
            "USER_DELETED",
            "USER_ENABLED",
            "USER_DISABLED",
            "ROLE_CREATED",
            "ROLE_UPDATED",
            "ROLE_DELETED",
            "CONFIGURATION_CHANGED",
            "SYSTEM_SETTING_CHANGED",
          ]
          break
        case "full":
          // Include all actions
          actions = []
          break
      }

      // Create search options with proper typing
      const searchOptions: Partial<AuditSearchOptions> = {
        startDate,
        endDate,
        limit: 10000 // High limit for reports
      }
      
      // Add optional parameters only if they are defined
      if (actions.length > 0) searchOptions.actions = actions
      if (entityTypes.length > 0) searchOptions.entityTypes = entityTypes
      
      const { logs, total } = await this.auditLogRepository.search(searchOptions as AuditSearchOptions)

      // Format report based on requested format
      if (format === "json") {
        return {
          reportType,
          startDate,
          endDate,
          generatedAt: new Date(),
          totalRecords: total,
          data: logs,
        }
      } else if (format === "csv") {
        // In a real implementation, this would convert to CSV
        return this.convertToCSV(logs)
      } else if (format === "pdf") {
        // In a real implementation, this would generate a PDF
        return {
          format: "pdf",
          content: "PDF report content would be generated here",
        }
      }

      return {
        reportType,
        startDate,
        endDate,
        generatedAt: new Date(),
        totalRecords: total,
        data: logs,
      }
    } catch (error) {
      logger.error("Failed to generate compliance report", { 
        error: error instanceof Error ? error.message : String(error), 
        reportType, 
        options 
      })
      return {
        error: "Failed to generate report",
        details: error instanceof Error ? error.message : String(error),
      }
    }
  }

  /**
   * Convert audit logs to CSV format
   * @param logs Audit logs
   * @returns CSV string
   */
  private convertToCSV(logs: DataAuditLog[]): string {
    try {
      if (logs.length === 0) {
        return ""
      }

      // Define CSV headers
      const headers = [
        "id",
        "createdAt",
        "userId",
        "action",
        "entityType",
        "entityId",
        "status",
        "ipAddress",
        "userAgent",
      ]

      // Create CSV header row
      let csv = headers.join(",") + "\n"

      // Add data rows
      for (const log of logs) {
        const row = headers.map((header) => {
          const value = log[header as keyof DataAuditLog]
          if (value === null || value === undefined) {
            return ""
          }
          if (typeof value === "string") {
            // Escape quotes and wrap in quotes
            return `"${value.replace(/"/g, '""')}"`
          }
          if (value instanceof Date) {
            return value.toISOString()
          }
          return String(value)
        })
        csv += row.join(",") + "\n"
      }

      return csv
    } catch (error) {
      logger.error("Failed to convert audit logs to CSV", { 
        error: error instanceof Error ? error.message : String(error) 
      })
      return ""
    }
  }

  /**
   * Sanitize metadata to remove sensitive information
   * @param metadata Metadata object
   * @returns Sanitized metadata
   */
  private sanitizeMetadata(metadata: Record<string, any>): Record<string, any> {
    try {
      const sanitized = { ...metadata }

      // Remove sensitive fields
      const sensitiveFields = [
        "password",
        "newPassword",
        "oldPassword",
        "currentPassword",
        "secret",
        "token",
        "accessToken",
        "refreshToken",
        "privateKey",
        "apiKey",
        "apiSecret",
        "credentials",
        "ssn",
        "creditCard",
        "cardNumber",
        "cvv",
      ]

      for (const field of sensitiveFields) {
        if (field in sanitized) {
          sanitized[field] = "[REDACTED]"
        }
      }

      // Recursively sanitize nested objects
      for (const [key, value] of Object.entries(sanitized)) {
        if (typeof value === "object" && value !== null) {
          sanitized[key] = this.sanitizeMetadata(value)
        }
      }

      return sanitized
    } catch (error) {
      logger.error("Failed to sanitize metadata", { 
        error: error instanceof Error ? error.message : String(error) 
      })
      return { error: "Failed to sanitize metadata" }
    }
  }
}
