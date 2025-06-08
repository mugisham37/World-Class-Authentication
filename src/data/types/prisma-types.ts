import { PrismaClient, Prisma } from '@prisma/client';

/**
 * TransactionClient type that represents a Prisma client in a transaction
 * Excludes methods that are not available in a transaction
 */
export type TransactionClient = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$transaction' | '$on' | '$use'
>;

/**
 * ExtendedPrismaClient interface that extends PrismaClient with additional functionality
 */
export interface ExtendedPrismaClient {
  // Core Prisma methods
  $connect(): Promise<void>;
  $disconnect(): Promise<void>;
  $on(event: 'query', callback: (event: Prisma.QueryEvent) => void): void;
  $on(event: 'info' | 'warn' | 'error', callback: (event: Prisma.LogEvent) => void): void;
  $queryRaw<T = unknown>(query: TemplateStringsArray | Prisma.Sql, ...values: any[]): Promise<T>;

  // Transaction method
  $transaction<R>(
    fn: (prisma: ExtendedPrismaClient) => Promise<R>,
    options?: {
      maxWait?: number;
      timeout?: number;
      isolationLevel?: 'ReadUncommitted' | 'ReadCommitted' | 'RepeatableRead' | 'Serializable';
    }
  ): Promise<R>;

  // Prisma model properties
  adminApproval: PrismaClient['adminApproval'];
  auditLog: PrismaClient['auditLog'];
  credential: PrismaClient['credential'];
  mfaChallenge: PrismaClient['mfaChallenge'];
  mfaFactor: PrismaClient['mfaFactor'];
  passwordHistory: PrismaClient['passwordHistory'];
  user: PrismaClient['user'];
  session: PrismaClient['session'];
  userProfile: PrismaClient['userProfile'];

  // Additional properties
  client: PrismaClient;
  [key: string]: any;
}

/**
 * Union type for all possible Prisma client types
 * This is used for repository constructors to accept any type of Prisma client
 */
export type PrismaClientType = PrismaClient | ExtendedPrismaClient | TransactionClient;

/**
 * Type guard to check if a client is an ExtendedPrismaClient
 * @param client The client to check
 * @returns True if the client is an ExtendedPrismaClient
 */
export function isExtendedPrismaClient(client: PrismaClientType): client is ExtendedPrismaClient {
  return '$transaction' in client && 'client' in client;
}

/**
 * Type guard to check if a client is a PrismaClient
 * @param client The client to check
 * @returns True if the client is a PrismaClient
 */
export function isPrismaClient(client: PrismaClientType): client is PrismaClient {
  return client instanceof PrismaClient;
}

/**
 * Type guard to check if a client supports transactions
 * @param client The client to check
 * @returns True if the client supports transactions
 */
export function supportsTransactions(
  client: PrismaClientType
): client is PrismaClient | ExtendedPrismaClient {
  return '$transaction' in client && typeof client.$transaction === 'function';
}

/**
 * Type guard to check if a client is a TransactionClient
 * @param client The client to check
 * @returns True if the client is a TransactionClient
 */
export function isTransactionClient(client: PrismaClientType): client is TransactionClient {
  return !('$transaction' in client);
}

/**
 * Helper function to execute an operation within a transaction
 * @param prisma The Prisma client
 * @param operation The operation to execute
 * @returns The result of the operation
 * @throws Error if the client is not a PrismaClient or ExtendedPrismaClient
 */
export async function executeInTransaction<R>(
  prisma: PrismaClientType,
  operation: (tx: TransactionClient) => Promise<R>
): Promise<R> {
  if (!supportsTransactions(prisma)) {
    throw new Error('Cannot start transaction: client does not support transactions');
  }

  // Use type assertion to handle the union type
  if (prisma instanceof PrismaClient) {
    return prisma.$transaction((tx: any) => operation(tx as unknown as TransactionClient), {
      maxWait: 5000,
      timeout: 10000,
    });
  } else {
    // Must be ExtendedPrismaClient since we checked with supportsTransactions
    return (prisma as ExtendedPrismaClient).$transaction(
      (tx: any) => operation(tx as unknown as TransactionClient),
      { maxWait: 5000, timeout: 10000 }
    );
  }
}

/**
 * Helper function to safely execute a transaction or fallback to direct operation
 * @param prisma The Prisma client
 * @param operation The operation to execute within a transaction
 * @param fallbackOperation The operation to execute if transaction is not supported
 * @returns The result of the operation
 */
export async function safeTransaction<R>(
  prisma: PrismaClientType,
  operation: (tx: TransactionClient) => Promise<R>,
  fallbackOperation: () => Promise<R>
): Promise<R> {
  if (supportsTransactions(prisma)) {
    return executeInTransaction(prisma, operation);
  } else {
    return fallbackOperation();
  }
}
