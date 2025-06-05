import { Injectable } from "@tsed/di"
import { v4 as uuidv4 } from "uuid"
import { complianceConfig } from "../../config/compliance.config"
import { logger } from "../../infrastructure/logging/logger"
import type { UserRepository } from "../../data/repositories/user.repository"
import type { DataSubjectRequestRepository } from "../../data/repositories/compliance/data-subject-request.repository"
import type { AuditLogRepository } from "../../data/repositories/audit-log.repository"
import type { EventEmitter } from "../../infrastructure/events/event-emitter"
import { ComplianceEvent } from "./compliance-events"
import type { EmailService } from "../notifications/email.service"
import { BadRequestError, NotFoundError } from "../../utils/error-handling"
import { DataSubjectRequestStatus, DataSubjectRequestType } from "@prisma/client"
import { 
  DataSubjectRequestCreateInput as ModelCreateInput,
  DataSubjectRequestSearchOptions as ModelSearchOptions,
  DataSubjectRequestStatisticsOptions as ModelStatisticsOptions,
  DataSubjectRequestTimelineOptions as ModelTimelineOptions
} from "../../data/models/data-subject-request.model"
// import { UserWithProfile } from "../../data/models/user.model"

/**
 * Input for creating a data subject request
 * Using the model interface directly to ensure type compatibility
 */
export type DataSubjectRequestCreateInput = ModelCreateInput;

/**
 * Options for searching data subject requests
 * Using the model interface directly to ensure type compatibility
 */
export type DataSubjectRequestSearchOptions = ModelSearchOptions;

/**
 * Options for data subject request statistics
 * Using the model interface directly to ensure type compatibility
 */
export type DataSubjectRequestStatisticsOptions = ModelStatisticsOptions;

/**
 * GDPR compliance service
 * Implements GDPR data subject rights and compliance features
 */
@Injectable()
export class GdprService {
  constructor(
    private userRepository: UserRepository,
    private dataSubjectRequestRepository: DataSubjectRequestRepository,
    private auditLogRepository: AuditLogRepository,
    private emailService: EmailService,
    private eventEmitter: EventEmitter,
  ) {}

  /**
   * Create a data subject access request (DSAR)
   * @param data Request data
   * @returns Created request
   */
  async createAccessRequest(data: {
    email: string
    firstName?: string
    lastName?: string
    requestReason?: string
    additionalInfo?: Record<string, any>
    requestedBy?: string
    ipAddress?: string
    userAgent?: string
  }): Promise<any> {
    try {
      logger.debug("Creating data subject access request", { email: data.email })

      // Check if GDPR compliance is enabled
      if (!complianceConfig.gdpr.enabled) {
        throw new BadRequestError("GDPR compliance is not enabled")
      }

      // Generate verification token
      const verificationToken = uuidv4()

      // Create request
      const request = await this.dataSubjectRequestRepository.create({
        type: DataSubjectRequestType.ACCESS,
        status: DataSubjectRequestStatus.PENDING_VERIFICATION,
        email: data.email,
        firstName: data.firstName ?? null,
        lastName: data.lastName ?? null,
        requestReason: data.requestReason ?? null,
        additionalInfo: data.additionalInfo ?? null,
        requestedBy: data.requestedBy ?? null,
        ipAddress: data.ipAddress ?? null,
        userAgent: data.userAgent ?? null,
        verificationToken,
        expiresAt: new Date(Date.now() + complianceConfig.gdpr.verification.tokenTtl * 1000),
        createdAt: new Date(),
        updatedAt: new Date(),
      })

      // Send verification email
      await this.emailService.sendDataAccessRequestVerification(data.email, verificationToken, request.id)

      // Emit event
      this.eventEmitter.emit(ComplianceEvent.DATA_ACCESS_REQUESTED, {
        requestId: request.id,
        email: data.email,
        timestamp: new Date(),
      })

      return {
        id: request.id,
        status: request.status,
        message: "Verification email sent. Please check your email to verify the request.",
      }
    } catch (error) {
      logger.error("Failed to create data subject access request", { error, email: data.email })
      throw error
    }
  }

  /**
   * Verify a data subject access request
   * @param requestId Request ID
   * @param verificationToken Verification token
   * @returns Updated request
   */
  async verifyAccessRequest(requestId: string, verificationToken: string): Promise<any> {
    try {
      logger.debug("Verifying data subject access request", { requestId })

      // Find request
      const request = await this.dataSubjectRequestRepository.findById(requestId)
      if (!request) {
        throw new NotFoundError("Data subject request not found")
      }

      // Check if request is already verified
      if (request.status !== DataSubjectRequestStatus.PENDING_VERIFICATION) {
        throw new BadRequestError("Request is already verified or processed")
      }

      // Check if verification token is valid
      if (request.verificationToken !== verificationToken) {
        throw new BadRequestError("Invalid verification token")
      }

      // Check if verification token has expired
      if (request.expiresAt && request.expiresAt < new Date()) {
        throw new BadRequestError("Verification token has expired")
      }

      // Update request status
      const updatedRequest = await this.dataSubjectRequestRepository.update(requestId, {
        status: DataSubjectRequestStatus.VERIFIED,
        verifiedAt: new Date(),
        updatedAt: new Date(),
      })

      // Find user
      const user = await this.userRepository.findByEmail(request.email)

      // Process request if user exists
      if (user) {
        // Schedule processing
        setTimeout(() => {
          this.processAccessRequest(requestId).catch((error) => {
            logger.error("Failed to process data subject access request", { error, requestId })
          })
        }, 0)
      } else {
        // Update request status if user not found
        await this.dataSubjectRequestRepository.update(requestId, {
          status: DataSubjectRequestStatus.COMPLETED,
          completedAt: new Date(),
          updatedAt: new Date(),
          result: {
            message: "No data found for this email address",
          },
        })
      }

      // Emit event
      this.eventEmitter.emit(ComplianceEvent.DATA_ACCESS_VERIFIED, {
        requestId,
        email: request.email,
        timestamp: new Date(),
      })

      return {
        id: updatedRequest.id,
        status: updatedRequest.status,
        message: "Request verified successfully. Your data will be processed shortly.",
      }
    } catch (error) {
      logger.error("Failed to verify data subject access request", { error, requestId })
      throw error
    }
  }

  /**
   * Process a data subject access request
   * @param requestId Request ID
   * @returns Processing result
   */
  private async processAccessRequest(requestId: string): Promise<any> {
    try {
      logger.debug("Processing data subject access request", { requestId })

      // Find request
      const request = await this.dataSubjectRequestRepository.findById(requestId)
      if (!request) {
        throw new NotFoundError("Data subject request not found")
      }

      // Check if request is verified
      if (request.status !== DataSubjectRequestStatus.VERIFIED) {
        throw new BadRequestError("Request is not verified")
      }

      // Update request status
      await this.dataSubjectRequestRepository.update(requestId, {
        status: DataSubjectRequestStatus.PROCESSING,
        processingStartedAt: new Date(),
        updatedAt: new Date(),
      })

      // Find user
      const user = await this.userRepository.findByEmail(request.email)
      if (!user) {
        // Update request status if user not found
        await this.dataSubjectRequestRepository.update(requestId, {
          status: DataSubjectRequestStatus.COMPLETED,
          completedAt: new Date(),
          updatedAt: new Date(),
          result: {
            message: "No data found for this email address",
          },
        })

        return {
          success: true,
          message: "No data found for this email address",
        }
      }

      // Collect user data
      const userData = await this.collectUserData(user.id)

      // Generate data export
      const dataExport = {
        user: {
          id: user.id,
          email: user.email,
          emailVerified: user.emailVerified,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
          lastLoginAt: user.lastLoginAt,
        },
        profile: userData['profile'],
        sessions: userData['sessions'],
        auditLogs: userData['auditLogs'],
        preferences: userData['preferences'],
      }

      // Update request with result
      await this.dataSubjectRequestRepository.update(requestId, {
        status: DataSubjectRequestStatus.COMPLETED,
        completedAt: new Date(),
        updatedAt: new Date(),
        result: {
          data: dataExport,
        },
      })

      // Send notification email
      await this.emailService.sendDataAccessRequestCompleted(request.email, requestId)

      // Emit event
      this.eventEmitter.emit(ComplianceEvent.DATA_ACCESS_COMPLETED, {
        requestId,
        userId: user.id,
        email: request.email,
        timestamp: new Date(),
      })

      return {
        success: true,
        message: "Data access request processed successfully",
      }
    } catch (error) {
      logger.error("Failed to process data subject access request", { error, requestId })

      // Update request status on error
      await this.dataSubjectRequestRepository.update(requestId, {
        status: DataSubjectRequestStatus.FAILED,
        updatedAt: new Date(),
        result: {
          error: error instanceof Error ? error.message : String(error),
        },
      })

      throw error
    }
  }

  /**
   * Collect user data for GDPR access request
   * @param userId User ID
   * @returns Collected user data
   */
  private async collectUserData(userId: string): Promise<Record<string, any>> {
    try {
      // In a real implementation, this would collect data from various repositories
      // For now, we'll return a simplified structure

      // Get user profile
      const profile = await this.userRepository.findProfileByUserId(userId)

      // Get user sessions
      const sessions = await this.userRepository.findSessionsByUserId(userId)

      // Get user audit logs
      const { logs } = await this.auditLogRepository.search({
        userId,
        limit: 1000,
      })

      // Get user preferences
      const preferences = await this.userRepository.findPreferencesByUserId(userId)

      return {
        profile,
        sessions,
        auditLogs: logs,
        preferences,
      }
    } catch (error) {
      logger.error("Failed to collect user data", { error, userId })
      throw error
    }
  }

  /**
   * Create a data deletion request
   * @param data Request data
   * @returns Created request
   */
  async createDeletionRequest(data: {
    email: string
    firstName?: string
    lastName?: string
    requestReason?: string
    additionalInfo?: Record<string, any>
    requestedBy?: string
    ipAddress?: string
    userAgent?: string
  }): Promise<any> {
    try {
      logger.debug("Creating data deletion request", { email: data.email })

      // Check if GDPR compliance is enabled
      if (!complianceConfig.gdpr.enabled) {
        throw new BadRequestError("GDPR compliance is not enabled")
      }

      // Generate verification token
      const verificationToken = uuidv4()

      // Create request
      const request = await this.dataSubjectRequestRepository.create({
        type: DataSubjectRequestType.DELETION,
        status: DataSubjectRequestStatus.PENDING_VERIFICATION,
        email: data.email,
        firstName: data.firstName ?? null,
        lastName: data.lastName ?? null,
        requestReason: data.requestReason ?? null,
        additionalInfo: data.additionalInfo ?? null,
        requestedBy: data.requestedBy ?? null,
        ipAddress: data.ipAddress ?? null,
        userAgent: data.userAgent ?? null,
        verificationToken,
        expiresAt: new Date(Date.now() + complianceConfig.gdpr.verification.tokenTtl * 1000),
        createdAt: new Date(),
        updatedAt: new Date(),
      })

      // Send verification email
      await this.emailService.sendDataDeletionRequestVerification(data.email, verificationToken, request.id)

      // Emit event
      this.eventEmitter.emit(ComplianceEvent.DATA_DELETION_REQUESTED, {
        requestId: request.id,
        email: data.email,
        timestamp: new Date(),
      })

      return {
        id: request.id,
        status: request.status,
        message: "Verification email sent. Please check your email to verify the request.",
      }
    } catch (error) {
      logger.error("Failed to create data deletion request", { error, email: data.email })
      throw error
    }
  }

  /**
   * Verify a data deletion request
   * @param requestId Request ID
   * @param verificationToken Verification token
   * @returns Updated request
   */
  async verifyDeletionRequest(requestId: string, verificationToken: string): Promise<any> {
    try {
      logger.debug("Verifying data deletion request", { requestId })

      // Find request
      const request = await this.dataSubjectRequestRepository.findById(requestId)
      if (!request) {
        throw new NotFoundError("Data subject request not found")
      }

      // Check if request is already verified
      if (request.status !== DataSubjectRequestStatus.PENDING_VERIFICATION) {
        throw new BadRequestError("Request is already verified or processed")
      }

      // Check if verification token is valid
      if (request.verificationToken !== verificationToken) {
        throw new BadRequestError("Invalid verification token")
      }

      // Check if verification token has expired
      if (request.expiresAt && request.expiresAt < new Date()) {
        throw new BadRequestError("Verification token has expired")
      }

      // Update request status
      const updatedRequest = await this.dataSubjectRequestRepository.update(requestId, {
        status: DataSubjectRequestStatus.VERIFIED,
        verifiedAt: new Date(),
        updatedAt: new Date(),
      })

      // Find user
      const user = await this.userRepository.findByEmail(request.email)

      // Process request if user exists
      if (user) {
        // Schedule processing
        setTimeout(() => {
          this.processDeletionRequest(requestId).catch((error) => {
            logger.error("Failed to process data deletion request", { error, requestId })
          })
        }, 0)
      } else {
        // Update request status if user not found
        await this.dataSubjectRequestRepository.update(requestId, {
          status: DataSubjectRequestStatus.COMPLETED,
          completedAt: new Date(),
          updatedAt: new Date(),
          result: {
            message: "No data found for this email address",
          },
        })
      }

      // Emit event
      this.eventEmitter.emit(ComplianceEvent.DATA_DELETION_VERIFIED, {
        requestId,
        email: request.email,
        timestamp: new Date(),
      })

      return {
        id: updatedRequest.id,
        status: updatedRequest.status,
        message: "Request verified successfully. Your data will be processed shortly.",
      }
    } catch (error) {
      logger.error("Failed to verify data deletion request", { error, requestId })
      throw error
    }
  }

  /**
   * Process a data deletion request
   * @param requestId Request ID
   * @returns Processing result
   */
  private async processDeletionRequest(requestId: string): Promise<any> {
    try {
      logger.debug("Processing data deletion request", { requestId })

      // Find request
      const request = await this.dataSubjectRequestRepository.findById(requestId)
      if (!request) {
        throw new NotFoundError("Data subject request not found")
      }

      // Check if request is verified
      if (request.status !== DataSubjectRequestStatus.VERIFIED) {
        throw new BadRequestError("Request is not verified")
      }

      // Update request status
      await this.dataSubjectRequestRepository.update(requestId, {
        status: DataSubjectRequestStatus.PROCESSING,
        processingStartedAt: new Date(),
        updatedAt: new Date(),
      })

      // Find user
      const user = await this.userRepository.findByEmail(request.email)
      if (!user) {
        // Update request status if user not found
        await this.dataSubjectRequestRepository.update(requestId, {
          status: DataSubjectRequestStatus.COMPLETED,
          completedAt: new Date(),
          updatedAt: new Date(),
          result: {
            message: "No data found for this email address",
          },
        })

        return {
          success: true,
          message: "No data found for this email address",
        }
      }

      // Anonymize user data
      await this.anonymizeUserData(user.id)

      // Update request with result
      await this.dataSubjectRequestRepository.update(requestId, {
        status: DataSubjectRequestStatus.COMPLETED,
        completedAt: new Date(),
        updatedAt: new Date(),
        result: {
          message: "Data deletion request processed successfully",
        },
      })

      // Send notification email
      await this.emailService.sendDataDeletionRequestCompleted(request.email, requestId)

      // Emit event
      this.eventEmitter.emit(ComplianceEvent.DATA_DELETION_COMPLETED, {
        requestId,
        userId: user.id,
        email: request.email,
        timestamp: new Date(),
      })

      return {
        success: true,
        message: "Data deletion request processed successfully",
      }
    } catch (error) {
      logger.error("Failed to process data deletion request", { error, requestId })

      // Update request status on error
      await this.dataSubjectRequestRepository.update(requestId, {
        status: DataSubjectRequestStatus.FAILED,
        updatedAt: new Date(),
        result: {
          error: error instanceof Error ? error.message : String(error),
        },
      })

      throw error
    }
  }

  /**
   * Anonymize user data for GDPR deletion request
   * @param userId User ID
   * @returns Anonymization result
   */
  private async anonymizeUserData(userId: string): Promise<boolean> {
    try {
      // In a real implementation, this would anonymize data across various repositories
      // For now, we'll just anonymize the user record

      // Generate anonymous identifier
      const anonymousId = `anon_${uuidv4()}`

      // Anonymize user
      await this.userRepository.update(userId, {
        email: `${anonymousId}@anonymous.com`,
      })

      // Anonymize user profile
      await this.userRepository.anonymizeProfile(userId)

      // Anonymize user sessions
      await this.userRepository.anonymizeSessions(userId)

      // Anonymize user audit logs
      await this.auditLogRepository.anonymizeByUserId(userId)

      // Anonymize other user data
      // In a real implementation, this would anonymize data in other repositories

      return true
    } catch (error) {
      logger.error("Failed to anonymize user data", { error, userId })
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(String(error));
    }
  }

  /**
   * Get data subject request by ID
   * @param requestId Request ID
   * @returns Data subject request
   */
  async getRequestById(requestId: string): Promise<any> {
    try {
      logger.debug("Getting data subject request by ID", { requestId })

      // Find request
      const request = await this.dataSubjectRequestRepository.findById(requestId)
      if (!request) {
        throw new NotFoundError("Data subject request not found")
      }

      return request
    } catch (error) {
      logger.error("Failed to get data subject request by ID", { error, requestId })
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(String(error));
    }
  }

  /**
   * Get data subject requests by email
   * @param email Email address
   * @param options Query options
   * @returns Data subject requests
   */
  async getRequestsByEmail(
    email: string,
    options: {
      page?: number
      limit?: number
      type?: string
      status?: string
    } = {},
  ): Promise<{ requests: any[]; total: number }> {
    try {
      logger.debug("Getting data subject requests by email", { email })

      const page = options.page || 1
      const limit = options.limit || 20
      const skip = (page - 1) * limit

      // Create a properly typed object for repository call
      const queryOptions: ModelSearchOptions = {
        skip,
        limit,
      };
      
      // Only add type and status if they are defined
      if (options.type) {
        queryOptions.type = options.type as DataSubjectRequestType;
      }
      
      if (options.status) {
        queryOptions.status = options.status as DataSubjectRequestStatus;
      }
      
      return await this.dataSubjectRequestRepository.findByEmail(email, queryOptions)
    } catch (error) {
      logger.error("Failed to get data subject requests by email", { error, email })
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(String(error));
    }
  }

  /**
   * Search data subject requests
   * @param options Search options
   * @returns Data subject requests
   */
  async searchRequests(
    options: {
      page?: number
      limit?: number
      type?: string
      status?: string
      startDate?: Date
      endDate?: Date
      query?: string
    } = {},
  ): Promise<{ requests: any[]; total: number }> {
    try {
      logger.debug("Searching data subject requests", { options })

      const page = options.page || 1
      const limit = options.limit || 20
      const skip = (page - 1) * limit

      // Create a properly typed object for repository call
      const searchOptions: ModelSearchOptions = {
        skip,
        limit,
      };
      
      // Only add optional parameters if they are defined
      if (options.type) {
        searchOptions.type = options.type as DataSubjectRequestType;
      }
      
      if (options.status) {
        searchOptions.status = options.status as DataSubjectRequestStatus;
      }
      
      if (options.startDate) {
        searchOptions.startDate = options.startDate;
      }
      
      if (options.endDate) {
        searchOptions.endDate = options.endDate;
      }
      
      if (options.query) {
        searchOptions.query = options.query;
      }
      
      return await this.dataSubjectRequestRepository.search(searchOptions)
    } catch (error) {
      logger.error("Failed to search data subject requests", { error, options })
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(String(error));
    }
  }

  /**
   * Get data subject request statistics
   * @param options Statistics options
   * @returns Request statistics
   */
  async getRequestStatistics(
    options: {
      startDate?: Date
      endDate?: Date
      groupBy?: "type" | "status" | "day" | "week" | "month"
    } = {},
  ): Promise<Record<string, number>> {
    try {
      logger.debug("Getting data subject request statistics", { options })

      // Create a properly typed object for repository call
      const statsOptions: ModelStatisticsOptions = {
        groupBy: options.groupBy || "type",
      };
      
      // Only add date parameters if they are defined
      if (options.startDate) {
        statsOptions.startDate = options.startDate;
      }
      
      if (options.endDate) {
        statsOptions.endDate = options.endDate;
      }
      
      return await this.dataSubjectRequestRepository.getStatistics(statsOptions)
    } catch (error) {
      logger.error("Failed to get data subject request statistics", { error, options })
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(String(error));
    }
  }

  /**
   * Generate GDPR compliance report
   * @param options Report options
   * @returns Compliance report
   */
  async generateComplianceReport(
    options: {
      startDate?: Date
      endDate?: Date
      format?: "json" | "csv" | "pdf"
    } = {},
  ): Promise<any> {
    try {
      logger.debug("Generating GDPR compliance report", { options })

      const startDate = options.startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // Default to last 30 days
      const endDate = options.endDate || new Date()
      const format = options.format || "json"

      // Get request statistics
      const requestStatsOptions: ModelStatisticsOptions = {
        groupBy: "type" as const,
      };
      
      if (startDate) requestStatsOptions.startDate = startDate;
      if (endDate) requestStatsOptions.endDate = endDate;
      
      const requestStats = await this.dataSubjectRequestRepository.getStatistics(requestStatsOptions);

      // Get request status statistics
      const statusStatsOptions: ModelStatisticsOptions = {
        groupBy: "status" as const,
      };
      
      if (startDate) statusStatsOptions.startDate = startDate;
      if (endDate) statusStatsOptions.endDate = endDate;
      
      const statusStats = await this.dataSubjectRequestRepository.getStatistics(statusStatsOptions)

      // Get request timeline
      const timelineOptions: ModelTimelineOptions = {
        interval: "day",
      };
      
      if (startDate) timelineOptions.startDate = startDate;
      if (endDate) timelineOptions.endDate = endDate;
      
      const timeline = await this.dataSubjectRequestRepository.getTimeline(timelineOptions);

      // Get recent requests
      const searchOptions: ModelSearchOptions = {
        limit: 10,
      };
      
      if (startDate) searchOptions.startDate = startDate;
      if (endDate) searchOptions.endDate = endDate;
      
      const { requests } = await this.dataSubjectRequestRepository.search(searchOptions)

      // Build report
      const report = {
        reportType: "gdpr_compliance",
        startDate,
        endDate,
        generatedAt: new Date(),
        statistics: {
          requestsByType: requestStats,
          requestsByStatus: statusStats,
          timeline,
        },
        recentRequests: requests,
      }

      // Format report based on requested format
      return this.formatReport(report, format)
    } catch (error) {
      logger.error("Failed to generate GDPR compliance report", { error, options })
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(String(error));
    }
  }

  /**
   * Format report based on requested format
   * @param report Report data
   * @param format Requested format
   * @returns Formatted report
   */
  private formatReport(report: any, format: string): any {
    try {
      if (format === "json") {
        return report
      } else if (format === "csv") {
        // In a real implementation, this would convert to CSV
        return this.convertToCSV(report)
      } else if (format === "pdf") {
        // In a real implementation, this would generate a PDF
        return {
          format: "pdf",
          content: "PDF report content would be generated here",
        }
      }
      return report
    } catch (error) {
      logger.error("Failed to format report", { error, format })
      return report
    }
  }

  /**
   * Convert report to CSV format
   * @param report Report data
   * @returns CSV string
   */
  private convertToCSV(report: any): string {
    try {
      // Convert report to CSV format
      const csvRows = [];
      
      // Add headers
      if (report.statistics) {
        csvRows.push('Report Type,Start Date,End Date,Generated At');
        csvRows.push(`${report.reportType},${report.startDate},${report.endDate},${report.generatedAt}`);
        
        // Add statistics data
        csvRows.push('');
        csvRows.push('Statistics:');
        
        // Add request type statistics
        if (report.statistics.requestsByType) {
          csvRows.push('Request Type,Count');
          Object.entries(report.statistics.requestsByType).forEach(([type, count]) => {
            csvRows.push(`${type},${count}`);
          });
        }
      }
      
      return csvRows.join('\n');
    } catch (error) {
      logger.error("Failed to convert report to CSV", { error })
      return ""
    }
  }
}
