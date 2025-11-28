/**
 * Transaction Manager for Database Operations
 * Provides transaction support across different database adapters
 */

import type { IDatabaseAdapter } from "./adapter";
import type {
  ControllerError,
  DatabaseErrorType,
  ControllerResponse,
} from "../types/errors";
import { createErrorResponse } from "../types/errors";

export interface Transaction {
  id: string;
  connection: any; // IDatabaseConnection or similar
  isActive: boolean;
  createdAt: Date;
}

export interface TransactionOptions {
  timeout?: number; // Timeout in milliseconds
  isolationLevel?:
    | "READ_UNCOMMITTED"
    | "READ_COMMITTED"
    | "REPEATABLE_READ"
    | "SERIALIZABLE";
}

export class TransactionManager {
  private activeTransactions = new Map<string, Transaction>();
  private cleanupInterval: NodeJS.Timeout;
  private readonly DEFAULT_TIMEOUT = 5 * 60 * 1000; // 5 minutes

  constructor(
    private adapter: IDatabaseAdapter,
    private options: TransactionOptions = {},
  ) {
    // Setup periodic cleanup of abandoned transactions
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60000); // Check every minute
  }

  /**
   * Begin a new transaction
   */
  async begin(): Promise<Transaction> {
    try {
      const connection = this.adapter.getConnection();
      const transactionId = this.generateTransactionId();

      // Begin transaction based on database type
      await this.beginTransaction(connection);

      const transaction: Transaction = {
        id: transactionId,
        connection,
        isActive: true,
        createdAt: new Date(),
      };

      this.activeTransactions.set(transactionId, transaction);
      return transaction;
    } catch (error: unknown) {
      throw createErrorResponse(error, {
        operation: "beginTransaction",
        table: "transaction",
      });
    }
  }

  /**
   * Commit a transaction
   */
  async commit(transaction: Transaction): Promise<void> {
    if (!transaction.isActive) {
      throw new Error("Transaction is not active");
    }

    try {
      await this.commitTransaction(transaction.connection);
      transaction.isActive = false;
      this.activeTransactions.delete(transaction.id);
    } catch (error: unknown) {
      // Ensure cleanup even on commit failure
      transaction.isActive = false;
      this.activeTransactions.delete(transaction.id);
      throw error;
    }
  }

  /**
   * Rollback a transaction
   */
  async rollback(transaction: Transaction): Promise<void> {
    if (!transaction.isActive) {
      throw new Error("Transaction is not active");
    }

    try {
      await this.rollbackTransaction(transaction.connection);
      transaction.isActive = false;
      this.activeTransactions.delete(transaction.id);
    } catch (error: unknown) {
      // Ensure cleanup even on rollback failure
      transaction.isActive = false;
      this.activeTransactions.delete(transaction.id);
      throw error;
    }
  }

  /**
   * Execute operations within a transaction
   */
  async transaction<T>(
    operations: (trx: Transaction) => Promise<T>,
  ): Promise<ControllerResponse<T>> {
    const trx = await this.begin();

    try {
      const result = await operations(trx);
      await this.commit(trx);

      return {
        success: true,
        data: result,
      };
    } catch (error: unknown) {
      await this.rollback(trx);
      const errorResponse = createErrorResponse(error, {
        operation: "transaction",
        table: "unknown",
      });

      return {
        success: false,
        error: errorResponse.error,
        errorType: errorResponse.errorType as DatabaseErrorType,
      };
    }
  }

  /**
   * Get active transaction count
   */
  getActiveTransactionCount(): number {
    return this.activeTransactions.size;
  }

  /**
   * Get transaction by ID
   */
  getTransaction(id: string): Transaction | undefined {
    return this.activeTransactions.get(id);
  }

  /**
   * Cleanup abandoned transactions
   */
  cleanup(): void {
    const now = Date.now();
    const timeout = this.options.timeout || this.DEFAULT_TIMEOUT;

    for (const [id, transaction] of this.activeTransactions) {
      if (now - transaction.createdAt.getTime() > timeout) {
        console.warn(`Cleaning up abandoned transaction: ${id}`);
        this.rollback(transaction).catch(console.error);
      }
    }
  }

  /**
   * Destroy transaction manager and cleanup resources
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    // Rollback all active transactions
    for (const transaction of this.activeTransactions.values()) {
      this.rollback(transaction).catch(console.error);
    }

    this.activeTransactions.clear();
  }

  /**
   * Generate unique transaction ID
   */
  private generateTransactionId(): string {
    return `trx_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Begin transaction based on database type
   */
  private async beginTransaction(connection: any): Promise<void> {
    const dbType = this.adapter.getDatabaseType();

    if (dbType.isSQLite) {
      await connection.query("BEGIN TRANSACTION").run();
    } else if (dbType.isSQLServer) {
      // SQL Server specific transaction begin
      await connection.query("BEGIN TRANSACTION").run();
    } else {
      // PostgreSQL and others
      await connection.query("BEGIN").run();
    }
  }

  /**
   * Commit transaction based on database type
   */
  private async commitTransaction(connection: any): Promise<void> {
    await connection.query("COMMIT").run();
  }

  /**
   * Rollback transaction based on database type
   */
  private async rollbackTransaction(connection: any): Promise<void> {
    await connection.query("ROLLBACK").run();
  }
}

/**
 * Enhanced BaseController with transaction support
 */
export abstract class TransactionalController {
  protected transactionManager: TransactionManager;

  constructor(
    protected adapter: IDatabaseAdapter,
    transactionOptions?: TransactionOptions,
  ) {
    this.transactionManager = new TransactionManager(
      adapter,
      transactionOptions,
    );
  }

  /**
   * Execute operations within a transaction
   */
  protected async executeInTransaction<T>(
    operations: (trx: Transaction) => Promise<T>,
  ): Promise<ControllerResponse<T>> {
    return this.transactionManager.transaction(operations);
  }

  /**
   * Get transaction manager for advanced usage
   */
  protected getTransactionManager(): TransactionManager {
    return this.transactionManager;
  }

  /**
   * Cleanup resources when controller is destroyed
   */
  destroy(): void {
    this.transactionManager.destroy();
  }
}
