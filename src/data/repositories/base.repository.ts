/**
 * Base repository interface
 * Defines common operations for all repositories
 * @template T The entity type
 * @template ID The ID type
 */
export interface BaseRepository<T, ID> {
  /**
   * Find an entity by its ID
   * @param id The entity ID
   * @returns The entity or null if not found
   */
  findById(id: ID): Promise<T | null>;

  /**
   * Find all entities
   * @param options Optional query options
   * @returns Array of entities
   */
  findAll(options?: QueryOptions): Promise<T[]>;

  /**
   * Find entities by a filter
   * @param filter The filter criteria
   * @param options Optional query options
   * @returns Array of entities matching the filter
   */
  findBy(filter: FilterOptions<T>, options?: QueryOptions): Promise<T[]>;

  /**
   * Find one entity by a filter
   * @param filter The filter criteria
   * @returns The entity or null if not found
   */
  findOneBy(filter: FilterOptions<T>): Promise<T | null>;

  /**
   * Create a new entity
   * @param data The entity data
   * @returns The created entity
   */
  create(data: CreateData<T>): Promise<T>;

  /**
   * Create multiple entities
   * @param data Array of entity data
   * @returns Array of created entities
   */
  createMany(data: CreateData<T>[]): Promise<T[]>;

  /**
   * Update an entity
   * @param id The entity ID
   * @param data The update data
   * @returns The updated entity
   */
  update(id: ID, data: UpdateData<T>): Promise<T>;

  /**
   * Update multiple entities by a filter
   * @param filter The filter criteria
   * @param data The update data
   * @returns The number of updated entities
   */
  updateMany(filter: FilterOptions<T>, data: UpdateData<T>): Promise<number>;

  /**
   * Delete an entity by its ID
   * @param id The entity ID
   * @returns True if the entity was deleted, false otherwise
   */
  delete(id: ID): Promise<boolean>;

  /**
   * Delete multiple entities by a filter
   * @param filter The filter criteria
   * @returns The number of deleted entities
   */
  deleteMany(filter: FilterOptions<T>): Promise<number>;

  /**
   * Count entities by a filter
   * @param filter The filter criteria
   * @returns The number of entities matching the filter
   */
  count(filter?: FilterOptions<T>): Promise<number>;

  /**
   * Check if an entity exists by its ID
   * @param id The entity ID
   * @returns True if the entity exists, false otherwise
   */
  exists(id: ID): Promise<boolean>;

  /**
   * Check if entities exist by a filter
   * @param filter The filter criteria
   * @returns True if any entity matches the filter, false otherwise
   */
  existsBy(filter: FilterOptions<T>): Promise<boolean>;
}

/**
 * Query options for repository operations
 */
export interface QueryOptions {
  /**
   * Number of items to skip
   */
  skip?: number;

  /**
   * Number of items to take
   */
  take?: number;

  /**
   * Order by criteria
   */
  orderBy?: OrderByOptions;

  /**
   * Include related entities
   */
  include?: IncludeOptions;

  /**
   * Select specific fields
   */
  select?: SelectOptions;
}

/**
 * Order by options
 */
export type OrderByOptions = Record<string, 'asc' | 'desc'>;

/**
 * Include options for related entities
 */
export interface IncludeOptions {
  [key: string]: boolean | NestedInclude;
}

/**
 * Nested include options for related entities
 */
export interface NestedInclude {
  include?: IncludeOptions;
  select?: SelectOptions;
}

/**
 * Select options for specific fields
 */
export type SelectOptions = Record<string, boolean>;

/**
 * Filter options for repository operations
 * @template T The entity type
 */
export type FilterOptions<T> = Partial<T> | Record<string, any>;

/**
 * Create data for repository operations
 * @template T The entity type
 */
export type CreateData<T> = Omit<Partial<T>, 'id' | 'createdAt' | 'updatedAt'>;

/**
 * Update data for repository operations
 * @template T The entity type
 */
export type UpdateData<T> = Omit<Partial<T>, 'id' | 'createdAt' | 'updatedAt'>;

/**
 * Transaction callback function
 * @template T The return type
 */
export type TransactionCallback<T> = (tx?: any) => Promise<T>;

/**
 * Transaction options
 */
export interface TransactionOptions {
  /**
   * Transaction isolation level
   */
  isolationLevel?: 'ReadUncommitted' | 'ReadCommitted' | 'RepeatableRead' | 'Serializable';

  /**
   * Transaction timeout in milliseconds
   */
  timeout?: number;
}

/**
 * Transaction manager interface
 */
export interface TransactionManager {
  /**
   * Execute a function within a transaction
   * @param callback The function to execute
   * @param options Transaction options
   * @returns The result of the callback function
   */
  transaction<R>(callback: (tx: any) => Promise<R>, options?: TransactionOptions): Promise<R>;
}
