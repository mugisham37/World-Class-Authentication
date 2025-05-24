import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError, NotFoundError } from '../../utils/error-handling';
import { prisma } from '../prisma/client';
import {
  BaseRepository,
  CreateData,
  FilterOptions,
  QueryOptions,
  TransactionCallback,
  TransactionManager,
  TransactionOptions,
  UpdateData,
} from './base.repository';

/**
 * Base Prisma repository implementation
 * Provides common operations for all Prisma repositories
 * @template T The entity type
 * @template ID The ID type
 */
export abstract class PrismaBaseRepository<T, ID>
  implements BaseRepository<T, ID>, TransactionManager
{
  /**
   * The Prisma client instance
   */
  protected readonly prisma: PrismaClient;

  /**
   * The Prisma model name
   */
  protected abstract readonly modelName: string;

  /**
   * Constructor
   * @param prismaClient Optional Prisma client instance
   */
  constructor(prismaClient?: PrismaClient) {
    this.prisma = prismaClient || prisma;
  }

  /**
   * Get the Prisma model delegate
   * @returns The Prisma model delegate
   */
  protected get model(): any {
    return (this.prisma as any)[this.modelName];
  }

  /**
   * Convert a filter to a Prisma where clause
   * @param filter The filter criteria
   * @returns The Prisma where clause
   */
  protected toWhereClause(filter?: FilterOptions<T>): any {
    if (!filter) {
      return {};
    }
    return filter;
  }

  /**
   * Convert query options to Prisma options
   * @param options The query options
   * @returns The Prisma options
   */
  protected toPrismaOptions(options?: QueryOptions): any {
    if (!options) {
      return {};
    }

    const prismaOptions: any = {};

    if (options.skip !== undefined) {
      prismaOptions.skip = options.skip;
    }

    if (options.take !== undefined) {
      prismaOptions.take = options.take;
    }

    if (options.orderBy) {
      prismaOptions.orderBy = options.orderBy;
    }

    if (options.include) {
      prismaOptions.include = options.include;
    }

    if (options.select) {
      prismaOptions.select = options.select;
    }

    return prismaOptions;
  }

  /**
   * Find an entity by its ID
   * @param id The entity ID
   * @returns The entity or null if not found
   */
  async findById(id: ID): Promise<T | null> {
    try {
      const result = await this.model.findUnique({
        where: { id },
      });
      return result as T | null;
    } catch (error) {
      logger.error(`Error finding ${this.modelName} by ID`, { id, error });
      throw new DatabaseError(
        `Error finding ${this.modelName} by ID`,
        'REPOSITORY_FIND_BY_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find all entities
   * @param options Optional query options
   * @returns Array of entities
   */
  async findAll(options?: QueryOptions): Promise<T[]> {
    try {
      const prismaOptions = this.toPrismaOptions(options);
      const results = await this.model.findMany(prismaOptions);
      return results as T[];
    } catch (error) {
      logger.error(`Error finding all ${this.modelName}`, { error });
      throw new DatabaseError(
        `Error finding all ${this.modelName}`,
        'REPOSITORY_FIND_ALL_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find entities by a filter
   * @param filter The filter criteria
   * @param options Optional query options
   * @returns Array of entities matching the filter
   */
  async findBy(filter: FilterOptions<T>, options?: QueryOptions): Promise<T[]> {
    try {
      const where = this.toWhereClause(filter);
      const prismaOptions = this.toPrismaOptions(options);
      const results = await this.model.findMany({
        where,
        ...prismaOptions,
      });
      return results as T[];
    } catch (error) {
      logger.error(`Error finding ${this.modelName} by filter`, { filter, error });
      throw new DatabaseError(
        `Error finding ${this.modelName} by filter`,
        'REPOSITORY_FIND_BY_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find one entity by a filter
   * @param filter The filter criteria
   * @returns The entity or null if not found
   */
  async findOneBy(filter: FilterOptions<T>): Promise<T | null> {
    try {
      const where = this.toWhereClause(filter);
      const result = await this.model.findFirst({
        where,
      });
      return result as T | null;
    } catch (error) {
      logger.error(`Error finding one ${this.modelName} by filter`, { filter, error });
      throw new DatabaseError(
        `Error finding one ${this.modelName} by filter`,
        'REPOSITORY_FIND_ONE_BY_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Create a new entity
   * @param data The entity data
   * @returns The created entity
   */
  async create(data: CreateData<T>): Promise<T> {
    try {
      const result = await this.model.create({
        data,
      });
      return result as T;
    } catch (error) {
      logger.error(`Error creating ${this.modelName}`, { data, error });
      throw new DatabaseError(
        `Error creating ${this.modelName}`,
        'REPOSITORY_CREATE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Create multiple entities
   * @param data Array of entity data
   * @returns Array of created entities
   */
  async createMany(data: CreateData<T>[]): Promise<T[]> {
    try {
      // Prisma's createMany doesn't return the created records
      // So we use transaction to create each record and return them
      return await this.transaction(async () => {
        const results: T[] = [];
        for (const item of data) {
          const result = await this.model.create({
            data: item,
          });
          results.push(result as T);
        }
        return results;
      });
    } catch (error) {
      logger.error(`Error creating many ${this.modelName}`, { count: data.length, error });
      throw new DatabaseError(
        `Error creating many ${this.modelName}`,
        'REPOSITORY_CREATE_MANY_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update an entity
   * @param id The entity ID
   * @param data The update data
   * @returns The updated entity
   */
  async update(id: ID, data: UpdateData<T>): Promise<T> {
    try {
      const result = await this.model.update({
        where: { id },
        data,
      });
      return result as T;
    } catch (error) {
      logger.error(`Error updating ${this.modelName}`, { id, data, error });

      // Check if the error is a record not found error
      if (error instanceof Error && error.message.includes('Record to update not found')) {
        throw new NotFoundError(`${this.modelName} with ID ${String(id)} not found`);
      }

      throw new DatabaseError(
        `Error updating ${this.modelName}`,
        'REPOSITORY_UPDATE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update multiple entities by a filter
   * @param filter The filter criteria
   * @param data The update data
   * @returns The number of updated entities
   */
  async updateMany(filter: FilterOptions<T>, data: UpdateData<T>): Promise<number> {
    try {
      const where = this.toWhereClause(filter);
      const result = await this.model.updateMany({
        where,
        data,
      });
      return result.count;
    } catch (error) {
      logger.error(`Error updating many ${this.modelName}`, { filter, data, error });
      throw new DatabaseError(
        `Error updating many ${this.modelName}`,
        'REPOSITORY_UPDATE_MANY_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete an entity by its ID
   * @param id The entity ID
   * @returns True if the entity was deleted, false otherwise
   */
  async delete(id: ID): Promise<boolean> {
    try {
      await this.model.delete({
        where: { id },
      });
      return true;
    } catch (error) {
      logger.error(`Error deleting ${this.modelName}`, { id, error });

      // Check if the error is a record not found error
      if (error instanceof Error && error.message.includes('Record to delete does not exist')) {
        return false;
      }

      throw new DatabaseError(
        `Error deleting ${this.modelName}`,
        'REPOSITORY_DELETE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete multiple entities by a filter
   * @param filter The filter criteria
   * @returns The number of deleted entities
   */
  async deleteMany(filter: FilterOptions<T>): Promise<number> {
    try {
      const where = this.toWhereClause(filter);
      const result = await this.model.deleteMany({
        where,
      });
      return result.count;
    } catch (error) {
      logger.error(`Error deleting many ${this.modelName}`, { filter, error });
      throw new DatabaseError(
        `Error deleting many ${this.modelName}`,
        'REPOSITORY_DELETE_MANY_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count entities by a filter
   * @param filter The filter criteria
   * @returns The number of entities matching the filter
   */
  async count(filter?: FilterOptions<T>): Promise<number> {
    try {
      const where = this.toWhereClause(filter);
      return await this.model.count({
        where,
      });
    } catch (error) {
      logger.error(`Error counting ${this.modelName}`, { filter, error });
      throw new DatabaseError(
        `Error counting ${this.modelName}`,
        'REPOSITORY_COUNT_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Check if an entity exists by its ID
   * @param id The entity ID
   * @returns True if the entity exists, false otherwise
   */
  async exists(id: ID): Promise<boolean> {
    try {
      const count = await this.model.count({
        where: { id },
      });
      return count > 0;
    } catch (error) {
      logger.error(`Error checking if ${this.modelName} exists`, { id, error });
      throw new DatabaseError(
        `Error checking if ${this.modelName} exists`,
        'REPOSITORY_EXISTS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Check if entities exist by a filter
   * @param filter The filter criteria
   * @returns True if any entity matches the filter, false otherwise
   */
  async existsBy(filter: FilterOptions<T>): Promise<boolean> {
    try {
      const where = this.toWhereClause(filter);
      const count = await this.model.count({
        where,
      });
      return count > 0;
    } catch (error) {
      logger.error(`Error checking if ${this.modelName} exists by filter`, { filter, error });
      throw new DatabaseError(
        `Error checking if ${this.modelName} exists by filter`,
        'REPOSITORY_EXISTS_BY_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Execute a function within a transaction
   * @param callback The function to execute
   * @param options Transaction options
   * @returns The result of the callback function
   */
  async transaction<T>(callback: TransactionCallback<T>, options?: TransactionOptions): Promise<T> {
    const isolationLevel = options?.isolationLevel;

    try {
      return await this.prisma.$transaction(
        async (tx: PrismaClient) => {
          // Create a new instance of the repository with the transaction client
          const repo = this.withTransaction(tx);

          // Set the repository as the 'this' context for the callback
          return await callback.call(repo);
        },
        {
          isolationLevel: isolationLevel as any,
          timeout: options?.timeout,
        }
      );
    } catch (error) {
      logger.error(`Transaction failed for ${this.modelName}`, { error });
      throw new DatabaseError(
        `Transaction failed for ${this.modelName}`,
        'REPOSITORY_TRANSACTION_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected abstract withTransaction(tx: PrismaClient): BaseRepository<T, ID>;
}
