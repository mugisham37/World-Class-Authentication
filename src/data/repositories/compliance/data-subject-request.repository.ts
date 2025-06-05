import { Injectable } from "@tsed/di"
import { v4 as uuidv4 } from "uuid"
import { DataSubjectRequestStatus, DataSubjectRequestType, PrismaClient } from "@prisma/client"
import { logger } from "../../../infrastructure/logging/logger"
import { 
  DataSubjectRequestCreateInput, 
  DataSubjectRequestUpdateInput,
  DataSubjectRequestSearchOptions,
  DataSubjectRequestStatisticsOptions,
  DataSubjectRequestTimelineOptions
} from "../../../data/models/data-subject-request.model"
import { DatabaseError } from "../../../utils/error-handling"

/**
 * Helper functions for data formatting
 */
function ensureString(value: any): string {
  if (value === undefined || value === null) {
    return "unknown";
  }
  return String(value);
}

/**
 * Format a date for grouping in statistics
 */
function formatDateForGrouping(dateInput: Date | null | undefined, groupByInput: string): string {
  // Early return for null/undefined dates
  if (!dateInput) return "unknown";
  
  // Ensure groupBy is a valid string
  const groupBy: string = groupByInput || "day";
  
  try {
    // Ensure we're working with a valid Date object
    const dateObj = new Date(dateInput);
    
    // Validate the date is not Invalid Date
    if (isNaN(dateObj.getTime())) {
      return "unknown";
    }
    
    // Format the date based on the groupBy parameter
    switch (groupBy) {
      case "day": {
        const isoString = dateObj.toISOString();
        const datePart = isoString.split("T")[0];
        return datePart || "unknown"; // Ensure we return a string
      }
      case "week": {
        // Get the first day of the week (Monday)
        const day = dateObj.getUTCDay();
        const diff = dateObj.getUTCDate() - day + (day === 0 ? -6 : 1);
        // Create a new date object for Monday
        const monday = new Date(Date.UTC(dateObj.getUTCFullYear(), dateObj.getUTCMonth(), diff));
        
        // Handle potential invalid date
        if (isNaN(monday.getTime())) {
          return "unknown";
        }
        
        const isoString = monday.toISOString();
        const datePart = isoString.split("T")[0];
        return datePart || "unknown"; // Ensure we return a string
      }
      case "month": {
        // Safely get year and month
        const year = dateObj.getUTCFullYear();
        const month = String(dateObj.getUTCMonth() + 1).padStart(2, "0");
        
        // Ensure both parts are valid
        if (!year || !month) {
          return "unknown";
        }
        
        return `${year}-${month}`;
      }
      default:
        // Default case for any other value
        return "unknown";
    }
  } catch (error) {
    // If any date operations fail, return a safe default
    logger.warn("Error formatting date for grouping", { error, dateInput, groupBy });
    return "unknown";
  }
}

/**
 * Repository for data subject requests (GDPR, CCPA, etc.)
 */
@Injectable()
export class DataSubjectRequestRepository {
  constructor(private prisma: PrismaClient) {}

  /**
   * Create a new data subject request
   * @param data Request data
   * @returns Created request
   */
  async create(data: DataSubjectRequestCreateInput) {
    try {
      return await this.prisma.dataSubjectRequest.create({
        data: {
          id: data.id || uuidv4(),
          type: data.type,
          status: data.status,
          email: data.email,
          firstName: data.firstName ?? null,
          lastName: data.lastName ?? null,
          userId: data.userId ?? null,
          requestReason: data.requestReason ?? null,
          additionalInfo: data.additionalInfo ?? {},
          requestedBy: data.requestedBy ?? null,
          ipAddress: data.ipAddress ?? null,
          userAgent: data.userAgent ?? null,
          verificationToken: data.verificationToken ?? null,
          expiresAt: data.expiresAt ?? null,
          createdAt: data.createdAt ?? new Date(),
          updatedAt: data.updatedAt ?? new Date(),
        },
      })
    } catch (error) {
      logger.error("Failed to create data subject request", { error, data })
      throw new DatabaseError("Failed to create data subject request", "DB_CREATE_ERROR", error instanceof Error ? error : undefined)
    }
  }

  /**
   * Find a data subject request by ID
   * @param id Request ID
   * @returns Request or null if not found
   */
  async findById(id: string) {
    try {
      return await this.prisma.dataSubjectRequest.findUnique({
        where: { id },
      })
    } catch (error) {
      logger.error("Failed to find data subject request by ID", { error, id })
      throw new DatabaseError("Failed to find data subject request", "DB_FIND_ERROR", error instanceof Error ? error : undefined)
    }
  }

  /**
   * Find data subject requests by email
   * @param email Email address
   * @param options Query options
   * @returns Requests and total count
   */
  async findByEmail(
    email: string,
    options: {
      skip?: number
      limit?: number
      type?: DataSubjectRequestType
      status?: DataSubjectRequestStatus
    } = {},
  ) {
    try {
      const where: any = { email }

      if (options.type) {
        where.type = options.type
      }

      if (options.status) {
        where.status = options.status
      }

      const [requests, total] = await Promise.all([
        this.prisma.dataSubjectRequest.findMany({
          where,
          orderBy: { createdAt: "desc" },
          skip: options.skip ?? 0,
          take: options.limit ?? 20,
        }),
        this.prisma.dataSubjectRequest.count({ where }),
      ])

      return { requests, total }
    } catch (error) {
      logger.error("Failed to find data subject requests by email", { error, email, options })
      throw new DatabaseError("Failed to find data subject requests by email", "DB_FIND_ERROR", error instanceof Error ? error : undefined)
    }
  }

  /**
   * Find a data subject request by verification token
   * @param token Verification token
   * @returns Request or null if not found
   */
  async findByVerificationToken(token: string) {
    try {
      return await this.prisma.dataSubjectRequest.findFirst({
        where: { verificationToken: token },
      })
    } catch (error) {
      logger.error("Failed to find data subject request by verification token", { error, token })
      throw new DatabaseError("Failed to find data subject request by verification token", "DB_FIND_ERROR", error instanceof Error ? error : undefined)
    }
  }

  /**
   * Update a data subject request
   * @param id Request ID
   * @param data Update data
   * @returns Updated request
   */
  async update(id: string, data: DataSubjectRequestUpdateInput) {
    try {
      // Create a clean update object that Prisma will accept
      const updateData: any = {
        updatedAt: new Date(),
      };
      
      // Only include defined fields in the update
      if (data.type !== undefined) updateData.type = data.type;
      if (data.status !== undefined) updateData.status = data.status;
      if (data.email !== undefined) updateData.email = data.email;
      if (data.firstName !== undefined) updateData.firstName = data.firstName;
      if (data.lastName !== undefined) updateData.lastName = data.lastName;
      if (data.userId !== undefined) updateData.userId = data.userId;
      if (data.requestReason !== undefined) updateData.requestReason = data.requestReason;
      if (data.additionalInfo !== undefined) updateData.additionalInfo = data.additionalInfo;
      if (data.requestedBy !== undefined) updateData.requestedBy = data.requestedBy;
      if (data.ipAddress !== undefined) updateData.ipAddress = data.ipAddress;
      if (data.userAgent !== undefined) updateData.userAgent = data.userAgent;
      if (data.verificationToken !== undefined) updateData.verificationToken = data.verificationToken;
      if (data.expiresAt !== undefined) updateData.expiresAt = data.expiresAt;
      if (data.verifiedAt !== undefined) updateData.verifiedAt = data.verifiedAt;
      if (data.processingStartedAt !== undefined) updateData.processingStartedAt = data.processingStartedAt;
      if (data.completedAt !== undefined) updateData.completedAt = data.completedAt;
      if (data.result !== undefined) updateData.result = data.result;
      
      return await this.prisma.dataSubjectRequest.update({
        where: { id },
        data: updateData,
      });
    } catch (error) {
      logger.error("Failed to update data subject request", { error, id, data })
      throw new DatabaseError("Failed to update data subject request", "DB_UPDATE_ERROR", error instanceof Error ? error : undefined)
    }
  }

  /**
   * Search data subject requests
   * @param options Search options
   * @returns Requests and total count
   */
  async search(options: DataSubjectRequestSearchOptions = {}) {
    try {
      const where: any = {}

      if (options.type) {
        where.type = options.type
      }

      if (options.status) {
        where.status = options.status
      }

      if (options.startDate || options.endDate) {
        where.createdAt = {}
        if (options.startDate) {
          where.createdAt.gte = options.startDate
        }
        if (options.endDate) {
          where.createdAt.lte = options.endDate
        }
      }

      if (options.query) {
        where.OR = [
          { email: { contains: options.query, mode: "insensitive" } },
          { firstName: { contains: options.query, mode: "insensitive" } },
          { lastName: { contains: options.query, mode: "insensitive" } },
          { requestReason: { contains: options.query, mode: "insensitive" } },
        ]
      }

      const [requests, total] = await Promise.all([
        this.prisma.dataSubjectRequest.findMany({
          where,
          orderBy: { createdAt: "desc" },
          skip: options.skip ?? 0,
          take: options.limit ?? 20,
        }),
        this.prisma.dataSubjectRequest.count({ where }),
      ])

      return { requests, total }
    } catch (error) {
      logger.error("Failed to search data subject requests", { error, options })
      throw new DatabaseError("Failed to search data subject requests", "DB_SEARCH_ERROR", error instanceof Error ? error : undefined)
    }
  }

  /**
   * Get statistics for data subject requests
   * @param options Statistics options
   * @returns Statistics
   */
  async getStatistics(options: DataSubjectRequestStatisticsOptions = {}): Promise<Record<string, number>> {
    try {
      const where: any = {}

      if (options.startDate || options.endDate) {
        where.createdAt = {}
        if (options.startDate) {
          where.createdAt.gte = options.startDate
        }
        if (options.endDate) {
          where.createdAt.lte = options.endDate
        }
      }

      const requests = await this.prisma.dataSubjectRequest.findMany({
        where,
        select: {
          type: true,
          status: true,
          createdAt: true,
        },
      })

      const stats: Record<string, number> = {}

      // Ensure groupBy is a valid value
      const groupByValue = ensureString(
        options.groupBy && ["type", "status", "day", "week", "month"].includes(options.groupBy) 
          ? options.groupBy 
          : "type"
      );
      
      for (const request of requests) {
        // Initialize key with a default value
        let key = "unknown";
        
        if (groupByValue === "type" && request.type) {
          // Group by request type
          key = ensureString(request.type);
        } else if (groupByValue === "status" && request.status) {
          // Group by request status
          key = ensureString(request.status);
        } else if (["day", "week", "month"].includes(groupByValue) && request.createdAt) {
          // Group by time period
          const date = new Date(request.createdAt);
          key = formatDateForGrouping(date, groupByValue);
        } else if (request.type) {
          // Default fallback to type
          key = ensureString(request.type);
        }
        
        // Increment the counter for this key
        stats[key] = (stats[key] || 0) + 1;
      }

      return stats
    } catch (error) {
      logger.error("Failed to get data subject request statistics", { error, options })
      throw new DatabaseError("Failed to get data subject request statistics", "DB_STATS_ERROR", error instanceof Error ? error : undefined)
    }
  }

  /**
   * Get timeline data for data subject requests
   * @param options Timeline options
   * @returns Timeline data
   */
  async getTimeline(options: DataSubjectRequestTimelineOptions = {}): Promise<Record<string, number>> {
    try {
      const where: any = {}

      if (options.startDate || options.endDate) {
        where.createdAt = {}
        if (options.startDate) {
          where.createdAt.gte = options.startDate
        }
        if (options.endDate) {
          where.createdAt.lte = options.endDate
        }
      }

      const requests = await this.prisma.dataSubjectRequest.findMany({
        where,
        select: {
          createdAt: true,
        },
        orderBy: {
          createdAt: "asc",
        },
      })

      const timeline: Record<string, number> = {}
      
      // Ensure interval is a valid value
      const intervalValue = ensureString(
        options.interval && ["day", "week", "month"].includes(options.interval) 
          ? options.interval 
          : "day"
      );
      
      for (const request of requests) {
        if (!request.createdAt) {
          continue; // Skip entries without a creation date
        }
        
        const date = new Date(request.createdAt);
        // Format the date according to the interval
        const key = formatDateForGrouping(date, intervalValue);
        
        // Increment the counter for this time period
        timeline[key] = (timeline[key] || 0) + 1;
      }

      return timeline
    } catch (error) {
      logger.error("Failed to get data subject request timeline", { error, options })
      throw new DatabaseError("Failed to get data subject request timeline", "DB_TIMELINE_ERROR", error instanceof Error ? error : undefined)
    }
  }

  /**
   * Delete expired verification tokens
   * @returns Number of deleted tokens
   */
  async deleteExpiredVerificationTokens(): Promise<number> {
    try {
      const now = new Date()
      const result = await this.prisma.dataSubjectRequest.updateMany({
        where: {
          expiresAt: { lt: now },
          status: DataSubjectRequestStatus.PENDING_VERIFICATION,
        },
        data: {
          status: DataSubjectRequestStatus.FAILED,
          verificationToken: null,
          updatedAt: now,
        },
      })
      return result.count
    } catch (error) {
      logger.error("Failed to delete expired verification tokens", { error })
      throw new DatabaseError("Failed to delete expired verification tokens", "DB_UPDATE_ERROR", error instanceof Error ? error : undefined)
    }
  }
}
