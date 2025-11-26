/**
 * Database Adapter Interface
 * Allows users to provide custom database adapters while defaulting to Bun SQLite
 */

import type { Database } from "bun:sqlite";
import { SQL } from "bun";

// Interface unificada para conexión de base de datos
export interface IQueryResult {
  all(...params: unknown[]): Promise<unknown[]>;
  get(...params: unknown[]): Promise<unknown>;
  run(...params: unknown[]): Promise<{ changes: number; lastInsertRowid?: number }>;
}

export interface IDatabaseConnection {
  query(sql: string): IQueryResult;
  prepare?(sql: string): unknown;
}

// Mantener compatibilidad con exports existentes
export type DatabaseConnection = IDatabaseConnection;

export type SupportedDatabase = Database | SQL;

export interface DatabaseAdapterConfig {
  database: SupportedDatabase;
  isSQLite?: boolean;
  isSQLServer?: boolean;
  isPostgreSQL?: boolean;
  isMySQL?: boolean;
  connectionString?: string;
}

/**
 * Base adapter interface that all database adapters must implement
 */
export interface IDatabaseAdapter {
  /**
   * Get the underlying database connection
   */
  getConnection(): DatabaseConnection;
  
  /**
   * Get the database configuration
   */
  getConfig(): DatabaseAdapterConfig;
  
  /**
   * Initialize the database connection
   */
  initialize(): Promise<void>;
  
  /**
   * Close the database connection
   */
  close(): Promise<void>;
  
  /**
   * Check if the connection is active
   */
  isConnected(): boolean;
  
  /**
   * Get database type information
   */
  getDatabaseType(): {
    isSQLite: boolean;
    isSQLServer: boolean;
    isPostgreSQL: boolean;
    isMySQL: boolean;
  };
  
  /**
   * Get database-specific SQL syntax helpers
   */
  getSqlHelpers(): {
    mapDataType: (type: string) => string;
    formatDefaultValue: (value: any) => string;
    getRandomOrder: () => string;
    getPrimaryKeyQuery: (tableName: string) => string;
    getTableInfoQuery: (tableName: string) => string;
  };
}

/**
 * Default Bun SQLite adapter implementation
 */
export class BunSQLiteAdapter implements IDatabaseAdapter {
  private connection: DatabaseConnection;
  private config: DatabaseAdapterConfig;

  constructor(config: DatabaseAdapterConfig) {
    this.config = {
      isSQLite: true,
      isSQLServer: false,
      isPostgreSQL: false,
      isMySQL: false,
      ...config,
    };
    this.connection = this.createConnection();
  }

  private createConnection(): DatabaseConnection {
    const { database } = this.config;
    
    // Type guard para SQLite
    if (this.isSQLiteDatabase(database)) {
      return {
        query: (sql: string) => ({
          all: async (...params: unknown[]): Promise<unknown[]> => {
            const stmt = database.prepare(sql);
            return stmt.all(...(params as any[]));
          },
          get: async (...params: unknown[]): Promise<unknown> => {
            const stmt = database.prepare(sql);
            return stmt.get(...(params as any[]));
          },
          run: async (...params: unknown[]): Promise<{ changes: number; lastInsertRowid?: number }> => {
            const stmt = database.prepare(sql);
            const result = stmt.run(...(params as any[]));
            return {
              changes: result.changes,
              lastInsertRowid: result.lastInsertRowid != null ? Number(result.lastInsertRowid) : undefined,
            };
          },
        }),
        prepare: (sql: string) => database.prepare(sql),
      };
    }
    
    // Para SQL (PostgreSQL/MySQL), implementación genérica
    return {
      query: (sql: string) => ({
        all: async (...params: unknown[]): Promise<unknown[]> => {
          try {
            // Convertir unknown[] a tipos compatibles con SQL
            const sqlParams = params.map(param => {
              if (param === null || param === undefined) return null;
              if (typeof param === 'string' || typeof param === 'number' || 
                  typeof param === 'boolean' || typeof param === 'bigint') {
                return param;
              }
              if (param instanceof Uint8Array || param instanceof Buffer) {
                return param;
              }
              if (param instanceof Date) {
                return param.toISOString();
              }
              // Para otros tipos, convertir a string
              return String(param);
            });
            const result = await (database as SQL).unsafe(sql, sqlParams as any[]);
            return Array.isArray(result) ? result : [result];
          } catch (error: unknown) {
            console.error("SQL query.all error:", error);
            throw error;
          }
        },
        get: async (...params: unknown[]): Promise<unknown> => {
          try {
            // Convertir unknown[] a tipos compatibles con SQL
            const sqlParams = params.map(param => {
              if (param === null || param === undefined) return null;
              if (typeof param === 'string' || typeof param === 'number' || 
                  typeof param === 'boolean' || typeof param === 'bigint') {
                return param;
              }
              if (param instanceof Uint8Array || param instanceof Buffer) {
                return param;
              }
              if (param instanceof Date) {
                return param.toISOString();
              }
              return String(param);
            });
            const result = await (database as SQL).unsafe(sql, sqlParams as any[]);
            return Array.isArray(result) ? result[0] : result;
          } catch (error: unknown) {
            console.error("SQL query.get error:", error);
            throw error;
          }
        },
        run: async (...params: unknown[]): Promise<{ changes: number; lastInsertRowid?: number }> => {
          try {
            // Convertir unknown[] a tipos compatibles con SQL
            const sqlParams = params.map(param => {
              if (param === null || param === undefined) return null;
              if (typeof param === 'string' || typeof param === 'number' || 
                  typeof param === 'boolean' || typeof param === 'bigint') {
                return param;
              }
              if (param instanceof Uint8Array || param instanceof Buffer) {
                return param;
              }
              if (param instanceof Date) {
                return param.toISOString();
              }
              return String(param);
            });
            await (database as SQL).unsafe(sql, sqlParams as any[]);
            return { changes: 1, lastInsertRowid: undefined };
          } catch (error: unknown) {
            console.error("SQL query.run error:", error);
            throw error;
          }
        },
      }),
      prepare: () => {
        throw new Error("Prepared statements not supported for SQL databases in this adapter");
      },
    };
  }

  private isSQLiteDatabase(db: SupportedDatabase): db is Database {
    return this.config.isSQLite === true;
  }

  async initialize(): Promise<void> {
    // SQLite initialization
    if (this.isSQLiteDatabase(this.config.database)) {
      if (this.config.database.exec) {
        this.config.database.exec("PRAGMA foreign_keys = ON");
      }
    }
  }

  async close(): Promise<void> {
    // SQLite doesn't typically need explicit closing in Bun
  }

  isConnected(): boolean {
    return !!this.config.database;
  }

  getConnection(): DatabaseConnection {
    return this.connection;
  }

  getConfig(): DatabaseAdapterConfig {
    return this.config;
  }

  getDatabaseType() {
    return {
      isSQLite: this.config.isSQLite ?? false,
      isSQLServer: this.config.isSQLServer ?? false,
      isPostgreSQL: this.config.isPostgreSQL ?? false,
      isMySQL: this.config.isMySQL ?? false,
    };
  }

  getSqlHelpers() {
    return {
      mapDataType: (type: string): string => {
        const upperType = type.toUpperCase();
        switch (upperType) {
          case "SERIAL":
            return "INTEGER";
          case "VARCHAR":
            return "TEXT";
          case "BOOLEAN":
          case "BIT":
            return "INTEGER";
          case "DATE":
            return "TEXT";
          case "DATETIME":
            return "TEXT";
          default:
            return upperType;
        }
      },
      
      formatDefaultValue: (value: any): string => {
        if (value === null) return "NULL";
        if (typeof value === "boolean") return value ? "1" : "0";
        
        if (typeof value === "string") {
          const upperValue = value.toUpperCase();
          const isFunctionOrKeyword = 
            /^\(.*\)$/.test(value.trim()) || 
            ["CURRENT_TIMESTAMP", "CURRENT_DATE", "CURRENT_TIME"].includes(upperValue);
          
          return isFunctionOrKeyword ? value : `'${value.replace(/'/g, "''")}'`;
        }
        
        return String(value);
      },
      
      getRandomOrder: (): string => "ORDER BY RANDOM()",
      
      getPrimaryKeyQuery: (tableName: string): string => 
        `PRAGMA table_info("${tableName}")`,
      
      getTableInfoQuery: (tableName: string): string => 
        `PRAGMA table_info("${tableName}")`,
    };
  }
}

/**
 * Adapter factory for creating the appropriate adapter based on configuration
 */
export class AdapterFactory {
  /**
   * Create a database adapter based on configuration
   */
  static createAdapter(config: DatabaseAdapterConfig): IDatabaseAdapter {
    // Default to Bun SQLite if no specific type is set
    if (!config.isSQLite && !config.isSQLServer && !config.isPostgreSQL && !config.isMySQL) {
      return new BunSQLiteAdapter({ ...config, isSQLite: true });
    }
    
    // Create adapter based on database type
    if (config.isSQLite) {
      return new BunSQLiteAdapter(config);
    }
    
    // For other database types, user should provide their own adapter
    throw new Error(
      `Unsupported database type. Please provide a custom adapter for ${this.getDatabaseTypeName(config)}`
    );
  }
  
  /**
   * Register a custom adapter for a specific database type
   */
  static registerCustomAdapter(
    databaseType: string,
    adapterClass: new (config: DatabaseAdapterConfig) => IDatabaseAdapter
  ): void {
    (globalThis as any).__customAdapters = (globalThis as any).__customAdapters || {};
    (globalThis as any).__customAdapters[databaseType] = adapterClass;
  }
  
  /**
   * Get a human-readable database type name
   */
  private static getDatabaseTypeName(config: DatabaseAdapterConfig): string {
    if (config.isSQLite) return "SQLite";
    if (config.isSQLServer) return "SQL Server";
    if (config.isPostgreSQL) return "PostgreSQL";
    if (config.isMySQL) return "MySQL";
    return "Unknown";
  }
}

/**
 * Example custom adapter template that users can extend
 */
export abstract class CustomDatabaseAdapter implements IDatabaseAdapter {
  protected connection: DatabaseConnection;
  protected config: DatabaseAdapterConfig;

  constructor(config: DatabaseAdapterConfig) {
    this.config = config;
    this.connection = this.createConnection();
  }

  // Abstract methods that must be implemented by custom adapters
  protected abstract createConnection(): DatabaseConnection;
  protected abstract initializeConnection(): Promise<void>;
  protected abstract closeConnection(): Promise<void>;
  protected abstract checkConnection(): boolean;
  protected abstract getDatabaseTypeString(): string;

  async initialize(): Promise<void> {
    await this.initializeConnection();
  }

  async close(): Promise<void> {
    await this.closeConnection();
  }

  isConnected(): boolean {
    return this.checkConnection();
  }

  getConnection(): DatabaseConnection {
    return this.connection;
  }

  getConfig(): DatabaseAdapterConfig {
    return this.config;
  }

  getDatabaseType() {
    return {
      isSQLite: this.config.isSQLite ?? false,
      isSQLServer: this.config.isSQLServer ?? false,
      isPostgreSQL: this.config.isPostgreSQL ?? false,
      isMySQL: this.config.isMySQL ?? false,
    };
  }

  getSqlHelpers() {
    // Default implementation - should be overridden by specific adapters
    return {
      mapDataType: (type: string): string => type.toUpperCase(),
      formatDefaultValue: (value: any): string => {
        if (value === null) return "NULL";
        if (typeof value === "string") return `'${value.replace(/'/g, "''")}'`;
        return String(value);
      },
      getRandomOrder: (): string => "ORDER BY RANDOM()",
      getPrimaryKeyQuery: (tableName: string): string => 
        `SELECT column_name FROM information_schema.key_column_usage WHERE table_name = '${tableName}'`,
      getTableInfoQuery: (tableName: string): string => 
        `SELECT * FROM information_schema.columns WHERE table_name = '${tableName}'`,
    };
  }
}
