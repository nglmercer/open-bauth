/**
 * Generic Base Controller for CRUD Operations
 * Database-agnostic controller that works with Bun's SQL interface
 * Enhanced with BIT type support for SQL Server compatibility
 */

import { SQL } from "bun";
import type { Database } from "bun:sqlite";
import type { IDatabaseAdapter, DatabaseAdapterConfig, IDatabaseConnection } from "./adapter";
import { AdapterFactory } from "./adapter";
import { createErrorResponse, DatabaseErrorType, type ControllerError } from "../types/errors";
import { z } from "zod";
import { SQLiteSchemaExtractor, type GeneratedZodSchema } from "./schema/schema-extractor";

export type TruthyFilter = { isTruthy: true };
export type FalsyFilter = { isFalsy: true };
export type SetFilter = { isSet: boolean };
export type OperatorFilter<V> = {
  operator: string;
  value: V;
};

export type AdvancedFilter<V> =
  | TruthyFilter
  | FalsyFilter
  | SetFilter
  | OperatorFilter<V>;

export type WhereConditions<T> = {
  [P in keyof T]?: T[P] | T[P][] | null | AdvancedFilter<T[P]>;
};

export interface QueryOptions<T = unknown> {
  limit?: number;
  offset?: number;
  orderBy?: string;
  orderDirection?: "ASC" | "DESC";
  where?: WhereConditions<T>;
}
export interface ColumnInfo {
  name: string;
  type: string;
  notNull: boolean;
  defaultValue: unknown;
  primaryKey: boolean;
}
export interface JoinOptions {
  table: string;
  on: string;
  type?: "INNER" | "LEFT" | "RIGHT" | "FULL";
  select?: string[];
}

export interface RelationOptions<T = unknown> extends QueryOptions<T> {
  joins?: JoinOptions[];
  select?: string[];
}

export interface SimpleSearchOptions {
  limit?: number;
  offset?: number;
  orderBy?: string;
  orderDirection?: "ASC" | "DESC";
}

export interface ControllerResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  errorType?: DatabaseErrorType;
  message?: string;
  total?: number;
}

export interface ValidationSchema {
  parse(data: unknown): unknown;
}

export interface SchemaCollection {
  [tableName: string]: {
    create?: ValidationSchema;
    update?: ValidationSchema;
    read?: ValidationSchema;
  };
}
export type ColumnType =
  | "INTEGER"
  | "TEXT"
  | "REAL"
  | "BLOB"
  | "BOOLEAN"
  | "BIT"
  | "DATE"
  | "DATETIME"
  | "VARCHAR"
  | "SERIAL";
export interface ColumnDefinition {
  name: string;
  type: ColumnType;
  primaryKey?: boolean;
  notNull?: boolean;
  unique?: boolean;
  defaultValue?: unknown;
  autoIncrement?: boolean;
  check?: string;
  references?: {
    table: string;
    column: string;
  };
}

export interface TableSchema {
  tableName: string;
  columns: ColumnDefinition[];
  indexes?: {
    name: string;
    columns: string[];
    unique?: boolean;
  }[];
}

export interface DatabaseConnection {
  query(sql: string): {
    all(...params: any[]): Promise<any[]>;
    get(...params: any[]): Promise<any>;
    run(
      ...params: any[]
    ): Promise<{ changes: number; lastInsertRowid?: number }>;
  };
  prepare?(sql: string): any;
}

export interface BaseControllerOptions {
  database?: SQL | Database;
  adapter?: IDatabaseAdapter;
  schemas?: SchemaCollection;
  isSQLite?: boolean;
  isSQLServer?: boolean;
}

export class DatabaseAdapter implements DatabaseConnection {
  private db: SQL | Database;
  private isSQLite: boolean;

  constructor(database: SQL | Database, isSQLite: boolean = false) {
    this.db = database;
    this.isSQLite = isSQLite;
  }

  query(sql: string) {
    return {
      all: async (...params: any[]): Promise<any[]> => {
        if (this.isSQLite) {
          const stmt = (this.db as Database).prepare(sql);
          return stmt.all(...params);
        } else {
          try {
            const result = await (this.db as SQL).unsafe(sql, params);
            return Array.isArray(result) ? result : [result];
          } catch (error: any) {
            console.error("DatabaseAdapter.query.all error:", error.message);
            throw error;
          }
        }
      },
      get: async (...params: any[]): Promise<any> => {
        if (this.isSQLite) {
          const stmt = (this.db as Database).prepare(sql);
          return stmt.get(...params);
        } else {
          try {
            const result = await (this.db as SQL).unsafe(sql, params);
            return Array.isArray(result) ? result[0] : result;
          } catch (error: any) {
            console.error("DatabaseAdapter.query.get error:", error.message);
            throw error;
          }
        }
      },
      run: async (
        ...params: any[]
      ): Promise<{ changes: number; lastInsertRowid?: number }> => {
        if (this.isSQLite) {
          const stmt = (this.db as Database).prepare(sql);
          const result = stmt.run(...params);
          return {
            changes: result.changes,
            lastInsertRowid:
              result.lastInsertRowid != null
                ? Number(result.lastInsertRowid)
                : undefined,
          };
        } else {
          try {
            await (this.db as SQL).unsafe(sql, params);
            // NOTE: This is a simplification. Getting actual changes/rowid from generic SQL is complex.
            return { changes: 1, lastInsertRowid: undefined };
          } catch (error: any) {
            console.error("DatabaseAdapter.query.run error:", error.message);
            throw error;
          }
        }
      },
    };
  }

  prepare(sql: string) {
    if (this.isSQLite) {
      return (this.db as Database).prepare(sql);
    }
    return null;
  }
}

export class BaseController<T = Record<string, unknown>> {
  protected adapter: IDatabaseAdapter;
  protected tableName: string;
  protected schemas?: SchemaCollection;
  protected isSQLite: boolean;
  protected isSQLServer: boolean;

  constructor(tableName: string, options: BaseControllerOptions) {
    this.tableName = tableName;
    this.schemas = options.schemas;

    // Use provided adapter or create one from database
    if (options.adapter) {
      this.adapter = options.adapter;
      const dbType = this.adapter.getDatabaseType();
      this.isSQLite = dbType.isSQLite;
      this.isSQLServer = dbType.isSQLServer;
    } else if (options.database) {
      // Create default adapter from database
      const adapterConfig: DatabaseAdapterConfig = {
        database: options.database,
        isSQLite: options.isSQLite ?? false,
        isSQLServer: options.isSQLServer ?? false,
      };
      this.adapter = AdapterFactory.createAdapter(adapterConfig);
      this.isSQLite = options.isSQLite ?? false;
      this.isSQLServer = options.isSQLServer ?? false;
    } else {
      throw new Error("Either 'adapter' or 'database' must be provided in BaseControllerOptions");
    }
  }

  static async initializeDatabase(
    database: SQL | Database,
    schemas: TableSchema[],
    isSQLite: boolean = false,
    isSQLServer: boolean = false,
  ): Promise<ControllerResponse> {
    const adapter = new DatabaseAdapter(database, isSQLite);

    // For SQLite, wrap initialization in a transaction for performance and safety
    if (isSQLite) (database as Database).exec("BEGIN TRANSACTION;");

    try {
      for (const schema of schemas) {
        const createTableSQL = BaseController.generateCreateTableSQL(
          schema,
          isSQLite,
          isSQLServer,
        );
        await adapter.query(createTableSQL).run();

        if (schema.indexes) {
          for (const index of schema.indexes) {
            const createIndexSQL = BaseController.generateCreateIndexSQL(
              schema.tableName,
              index,
              isSQLite,
            );
            await adapter.query(createIndexSQL).run();
          }
        }
      }

      if (isSQLite) (database as Database).exec("COMMIT;");

      return {
        success: true,
        message: `Successfully created ${schemas.length} tables`,
      };
    } catch (error: any) {
      if (isSQLite) (database as Database).exec("ROLLBACK;");
      return {
        success: false,
        error: error.message,
      };
    }
  }

  private static generateCreateTableSQL(
    schema: TableSchema,
    isSQLite: boolean,
    isSQLServer: boolean = false,
  ): string {
    const columns = schema.columns
      .map((col) => {
        let columnDef = `"${col.name}" ${BaseController.mapDataType(
          col.type,
          isSQLite,
          isSQLServer,
        )}`;

        if (col.primaryKey) {
          columnDef += " PRIMARY KEY";
          if (col.autoIncrement && isSQLite) {
            columnDef += " AUTOINCREMENT";
          }
        }

        if (col.notNull && !col.primaryKey) {
          columnDef += " NOT NULL";
        }

        if (col.unique && !col.primaryKey) {
          columnDef += " UNIQUE";
        }

        if (col.defaultValue !== undefined) {
          columnDef += ` DEFAULT ${BaseController.formatDefaultValue(
            col.defaultValue,
          )}`;
        }

        if (col.references) {
          columnDef += ` REFERENCES "${col.references.table}"("${col.references.column}")`;
        }

        if (col.check) {
          columnDef += ` CHECK (${col.check})`;
        }

        return columnDef;
      })
      .join(", ");

    return `CREATE TABLE IF NOT EXISTS "${schema.tableName}" (${columns})`;
  }

  private static generateCreateIndexSQL(
    tableName: string,
    index: { name: string; columns: string[]; unique?: boolean },
    isSQLite: boolean,
  ): string {
    const unique = index.unique ? "UNIQUE " : "";
    const columns = index.columns.map((c) => `"${c}"`).join(", ");
    return `CREATE ${unique}INDEX IF NOT EXISTS "${index.name}" ON "${tableName}" (${columns})`;
  }

  private static mapDataType(
    type: string,
    isSQLite: boolean,
    isSQLServer: boolean = false,
  ): string {
    const upperType = type.toUpperCase();

    if (isSQLite) {
      switch (upperType) {
        case "SERIAL":
          return "INTEGER";
        case "VARCHAR":
          return "TEXT";
        case "BOOLEAN":
        case "BIT":
          return "BOOLEAN";
        case "DATE":
          return "DATE";
        case "DATETIME":
          return "DATETIME";
        default:
          return upperType;
      }
    } else if (isSQLServer) {
      switch (upperType) {
        case "BOOLEAN":
          return "BIT";
        case "DATE":
          return "DATE";
        case "DATETIME":
          return "DATETIME";
        case "SERIAL":
          return "INT IDENTITY(1,1)";
        default:
          return upperType;
      }
    } else {
      // PostgreSQL (assumed default)
      switch (upperType) {
        case "BIT":
          return "BOOLEAN"; // Map BIT to BOOLEAN in PostgreSQL
        case "BOOLEAN":
          return "BOOLEAN";
        case "DATE":
          return "DATE";
        case "DATETIME":
          return "TIMESTAMP";
        default:
          return upperType;
      }
    }
  }

  private static formatDefaultValue(value: any): string {
    if (value === null) {
      return "NULL";
    }

    if (typeof value === "boolean") {
      return value ? "1" : "0"; // Use 1/0 for boolean in SQLite and SQL Server BIT
    }

    if (typeof value === "string") {
      const upperValue = value.toUpperCase();
      const isFunctionOrKeyword =
        /^\(.*\)$/.test(value.trim()) || // Matches anything in parentheses like (lower(...))
        ["CURRENT_TIMESTAMP", "CURRENT_DATE", "CURRENT_TIME"].includes(
          upperValue,
        );

      if (isFunctionOrKeyword) {
        return value;
      } else {
        return `'${value.replace(/'/g, "''")}'`;
      }
    }

    if (typeof value === "object") {
      return `'${JSON.stringify(value).replace(/'/g, "''")}'`;
    }

    return String(value);
  }

  private validateData(
    data: any,
    operation: "create" | "update" | "read",
  ): any {
    if (!this.schemas || !this.schemas[this.tableName]) {
      return data;
    }

    try {
      const tableSchemas = this.schemas[this.tableName];
      let schema: ValidationSchema | undefined;

      switch (operation) {
        case "create":
          schema = tableSchemas?.create;
          break;
        case "update":
          schema = tableSchemas?.update;
          break;
        case "read":
        default:
          schema = tableSchemas?.read;
          break;
      }

      if (!schema) {
        return data;
      }

      return schema.parse(data);
    } catch (error: any) {
      throw new Error(`Validation error: ${error.message}`);
    }
  }

  // src/database/base-controller.ts

  private buildWhereClause(conditions: Record<string, any>): {
    sql: string;
    params: any[];
  } {
    if (!conditions || Object.keys(conditions).length === 0) {
      return { sql: "", params: [] };
    }

    const clauses: string[] = [];
    const params: any[] = [];

    for (const [key, value] of Object.entries(conditions)) {
      if (value === null) {
        clauses.push(`"${key}" IS NULL`);
        continue;
      }

      if (Array.isArray(value)) {
        if (value.length === 0) {
          clauses.push("1 = 0");
          continue;
        }
        clauses.push(`"${key}" IN (${value.map(() => "?").join(", ")})`);
        params.push(...value.map((v) => this.convertValueForDatabase(v)));
        continue;
      }

      if (
        typeof value === "object" &&
        !ArrayBuffer.isView(value) &&
        !(value instanceof Date)
      ) {
        if ("isTruthy" in value && value.isTruthy === true) {
          clauses.push(`"${key}" = ?`);
          params.push(1);
          continue;
        } else if ("isFalsy" in value && value.isFalsy === true) {
          clauses.push(`("${key}" IS NULL OR "${key}" = ?)`);
          params.push(0);
          continue;
        } else if ("isSet" in value) {
          // IS NULL/IS NOT NULL should work consistently across versions
          clauses.push(`"${key}" IS ${value.isSet ? "NOT NULL" : "NULL"}`);
          continue;
        } else if ("operator" in value) {
          clauses.push(`"${key}" ${value.operator} ?`);
          params.push(value.value);
          continue;
        }
      }

      clauses.push(`"${key}" = ?`);
      params.push(this.convertValueForDatabase(value));
    }

    return {
      sql: ` WHERE ${clauses.join(" AND ")}`,
      params,
    };
  }

  /**
   * Enhanced boolean detection including BIT type support
   */
  private isBooleanLike(value: any): boolean {
    if (typeof value === "boolean") {
      return true;
    }
    if (typeof value === "number" && (value === 0 || value === 1)) {
      return true;
    }
    if (
      (value instanceof Uint8Array || value instanceof Buffer) &&
      value.length === 1
    ) {
      return true;
    }
    if (ArrayBuffer.isView(value) && value.byteLength === 1) {
      return true;
    }
    return false;
  }

  /**
   * Enhanced boolean normalization with BIT type support
   */
  private normalizeBooleanValue(value: any): boolean {
    if (typeof value === "boolean") {
      return value;
    }
    if (typeof value === "number") {
      return value === 1;
    }
    if (value instanceof Uint8Array || value instanceof Buffer) {
      return value[0] === 1;
    }
    if (ArrayBuffer.isView(value)) {
      const uint8View = new Uint8Array(value.buffer, value.byteOffset, 1);
      return uint8View[0] === 1;
    }
    return Boolean(value);
  }

  /**
   * Enhanced database value conversion with BIT type support
   */
  private convertValueForDatabase(value: any): any {
    if (this.isBooleanLike(value)) {
      const boolValue = this.normalizeBooleanValue(value);
      if (this.isSQLite || this.isSQLServer) {
        return boolValue ? 1 : 0;
      }
      return boolValue;
    }

    return value;
  }
  private async getTableInfo(): Promise<Array<{ name: string; pk: number }>> {
    try {
      const connection = this.adapter.getConnection();
      if (this.isSQLite) {
        const result = await connection
          .query(`PRAGMA table_info("${this.tableName}")`)
          .all();
        return Array.isArray(result)
          ? (result as any[]).map((col: any) => ({ name: col.name, pk: col.pk }))
          : [];
      } else {
        // Generic SQL for PostgreSQL
        const result = await connection
          .query(
            `
          SELECT
            column_name as name,
            CASE WHEN column_name = ANY(
              SELECT a.attname
              FROM pg_index i
              JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
              WHERE i.indrelid = $1::regclass AND i.indisprimary
            ) THEN 1 ELSE 0 END as pk
          FROM information_schema.columns
          WHERE table_name = $1 AND table_schema = 'public'
          ORDER BY ordinal_position
        `,
          )
          .all(this.tableName);
        return Array.isArray(result) ? (result as any[]) : [];
      }
    } catch (error) {
      // Fallback for other systems or errors
      return [{ name: "id", pk: 1 }];
    }
  }

  private async getPrimaryKey(): Promise<string> {
    const tableInfo = await this.getTableInfo();
    const primaryKey = tableInfo.find((col) => col.pk === 1)?.name;
    return primaryKey || "id";
  }

  async create(data: Record<string, any>): Promise<ControllerResponse<T>> {
    try {
      const validatedData = this.validateData(data, "create");
      const cleanData = Object.fromEntries(
        Object.entries(validatedData).filter(
          ([_, value]) => value !== undefined,
        ),
      );
      if (Object.keys(cleanData).length === 0) {
        return {
          success: false,
          error: "No valid data provided",
          errorType: DatabaseErrorType.VALIDATION_ERROR
        };
      }

      const columns = Object.keys(cleanData).map((c) => `"${c}"`);
      const placeholders = Object.keys(cleanData)
        .map(() => "?")
        .join(", ");

      const values = Object.entries(cleanData).map(([key, value]) => {
        if (
          value === null ||
          typeof value === "string" ||
          typeof value === "number" ||
          typeof value === "boolean" ||
          typeof value === "bigint" ||
          ArrayBuffer.isView(value)
        ) {
          return this.convertValueForDatabase(value);
        }
        if (value instanceof Date) {
          return value.toISOString();
        }
        if (typeof value === "object") {
          return JSON.stringify(value);
        }

        throw new Error(
          `Invalid data type for column '${key}': ${typeof value}. Expected string, number, boolean, null, Date, or TypedArray`,
        );
      });

      const insertQuery = `INSERT INTO "${this.tableName}" (${columns.join(", ")}) VALUES (${placeholders}) RETURNING *`;
      const result = await this.adapter.getConnection().query(insertQuery).get(...values);

      if (!result) {
        return {
          success: false,
          error:
            "Failed to create record or retrieve the created data from database",
          errorType: DatabaseErrorType.QUERY_ERROR
        };
      }

      return {
        success: true,
        data: result as T,
        message: "Record created successfully",
      };
    } catch (error: unknown) {
      return createErrorResponse<T>(error, {
        operation: "create",
        table: this.tableName
      });
    }
  }

  async findById(id: number | string): Promise<ControllerResponse<T>> {
    try {
      const primaryKey = await this.getPrimaryKey();
      const result = await this.adapter.getConnection()
        .query(`SELECT * FROM "${this.tableName}" WHERE "${primaryKey}" = ?`)
        .get(id);

      if (!result) {
        return {
          success: false,
          error: "Record not found",
          errorType: DatabaseErrorType.NOT_FOUND
        };
      }

      return {
        success: true,
        data: result as T,
      };
    } catch (error: unknown) {
      return createErrorResponse<T>(error, {
        operation: "findById",
        table: this.tableName,
        id
      });
    }
  }

  async findAll(options: QueryOptions = {}): Promise<ControllerResponse<T[]>> {
    try {
      const {
        limit = 100,
        offset = 0,
        orderBy,
        orderDirection = "ASC",
        where,
      } = options;
      const { sql: whereClause, params } = this.buildWhereClause(where || {});

      let query = `SELECT * FROM "${this.tableName}"${whereClause}`;
      let countQuery = `SELECT COUNT(*) as total FROM "${this.tableName}"${whereClause}`;

      if (orderBy) {
        query += ` ORDER BY "${orderBy}" ${orderDirection}`;
      }

      query += ` LIMIT ? OFFSET ?`;
      params.push(limit, offset);

      const records = await this.adapter.getConnection().query(query).all(...params);

      const countParams = params.slice(0, -2);
      const totalResult = (await this.adapter.getConnection()
        .query(countQuery)
        .get(...countParams)) as { total: number };

      return {
        success: true,
        data: records as T[],
        total: totalResult.total,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  async update(
    id: number | string,
    data: Record<string, any>,
  ): Promise<ControllerResponse<T>> {
    try {
      const validatedData = this.validateData(data, "update");
      const cleanData = Object.fromEntries(
        Object.entries(validatedData).filter(
          ([_, value]) => value !== undefined,
        ),
      );

      if (Object.keys(cleanData).length === 0) {
        return {
          success: false,
          error: "No valid data provided for update",
          errorType: DatabaseErrorType.VALIDATION_ERROR
        };
      }

      const primaryKey = await this.getPrimaryKey();
      const columns = Object.keys(cleanData);
      const setClause = columns.map((col) => `"${col}" = ?`).join(", ");
      const values = [
        ...Object.values(cleanData).map((value) =>
          this.convertValueForDatabase(value),
        ),
        id,
      ];

      const updateQuery = `UPDATE "${this.tableName}" SET ${setClause} WHERE "${primaryKey}" = ?`;
      const result = await this.adapter.getConnection().query(updateQuery).run(...values);

      if (result.changes === 0) {
        return {
          success: false,
          error: "Record not found or no changes made",
          errorType: DatabaseErrorType.NOT_FOUND
        };
      }

      const updatedRecord = await this.findById(id);

      return {
        success: true,
        data: updatedRecord.data,
        message: "Record updated successfully",
      };
    } catch (error: unknown) {
      return createErrorResponse<T>(error, {
        operation: "update",
        table: this.tableName,
        id
      });
    }
  }

  async delete(id: number | string): Promise<ControllerResponse> {
    try {
      const primaryKey = await this.getPrimaryKey();
      const deleteQuery = `DELETE FROM "${this.tableName}" WHERE "${primaryKey}" = ?`;
      const result = await this.adapter.getConnection().query(deleteQuery).run(id);

      if (result.changes === 0) {
        return {
          success: false,
          error: "Record not found",
          errorType: DatabaseErrorType.NOT_FOUND
        };
      }

      return {
        success: true,
        message: "Record deleted successfully",
      };
    } catch (error: unknown) {
      return createErrorResponse(error, {
        operation: "delete",
        table: this.tableName,
        id
      });
    }
  }

  async query(sql: string, params: any[] = []): Promise<ControllerResponse> {
    try {
      const records = await this.adapter.getConnection().query(sql).all(...params);
      return {
        success: true,
        data: records,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  async getSchema(): Promise<{
    success: boolean;
    data?: { columns: ColumnInfo[]; tableName?: string };
    error?: string;
  }> {
    try {
      const pragmaQuery = this.adapter.getConnection().query(
        `PRAGMA table_info(${this.tableName})`,
      );
      const rawColumns = (await pragmaQuery.all()) as any[];

      if (!rawColumns || rawColumns.length === 0) {
        return {
          success: false,
          error: `Table '${this.tableName}' not found or has no columns.`,
        };
      }

      const columns: ColumnInfo[] = rawColumns.map((col) => ({
        name: col.name,
        type: col.type,
        notNull: col.notnull === 1, // 'notnull' 0  1
        defaultValue: col.dflt_value,
        primaryKey: col.pk > 0,
        ...col,
      }));

      return { success: true, data: { columns, tableName: this.tableName } };
    } catch (error: any) {
      // this.logger.error(...);
      return {
        success: false,
        error: `Failed to get schema for table ${this.tableName}: ${error.message}`,
      };
    }
  }

  async search(
    filters: WhereConditions<T> = {},
    options: SimpleSearchOptions = {},
  ): Promise<ControllerResponse<T[]>> {
    try {
      return await this.findAll({ where: filters as WhereConditions<T>, ...options });
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  async findFirst(
    filters: WhereConditions<T> = {},
  ): Promise<ControllerResponse<T | null>> {
    try {
      const result = await this.search(filters, { limit: 1 });

      if (
        result.success &&
        Array.isArray(result.data) &&
        result.data.length > 0
      ) {
        return {
          success: true,
          data: result.data[0] as T,
        };
      } else if (!result.success) {
        return result as ControllerResponse<T | null>;
      }

      return {
        success: true,
        data: null,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  async count(
    filters: WhereConditions<T> = {},
  ): Promise<ControllerResponse<number>> {
    try {
      const { sql: whereClause, params } = this.buildWhereClause(
        (filters as Record<string, any>) || {},
      );
      const query = `SELECT COUNT(*) as total FROM "${this.tableName}"${whereClause}`;
      const result = (await this.adapter.getConnection().query(query).get(...params)) as {
        total: number;
      };

      return {
        success: true,
        data: result.total,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  async random(
    filters: WhereConditions<T> = {},
    limit: number = 1,
  ): Promise<ControllerResponse<T[]>> {
    try {
      const { sql: whereClause, params } = this.buildWhereClause(
        (filters as Record<string, any>) || {},
      );

      const randomOrderClause = this._getRandomOrderClause();

      const query = `SELECT * FROM "${this.tableName}"${whereClause} ${randomOrderClause} LIMIT ?`;
      params.push(limit);

      const records = await this.adapter.getConnection().query(query).all(...params);

      return {
        success: true,
        data: records as T[],
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }
  private _getRandomOrderClause(): string {
    if (this.isSQLServer) {
      return "ORDER BY NEWID()";
    }

    if (this.isSQLite) {
      return "ORDER BY RANDOM()";
    }

    return "ORDER BY RANDOM()";
  }
  async findWithRelations(
    options: RelationOptions<T> = {},
  ): Promise<ControllerResponse<T[]>> {
    try {
      const {
        limit = 100,
        offset = 0,
        orderBy,
        orderDirection = "ASC",
        where,
        joins = [],
        select = [],
      } = options;
      const { sql: whereClause, params } = this.buildWhereClause(where || {});

      let selectClause: string;

      if (select.length > 0) {
        selectClause = select
          .map((col) => {
            if (col.includes(".")) {
              const [tbl, cl] = col.split(".");
              return `"${tbl}"."${cl}"`;
            }
            return `"${this.tableName}"."${col}"`;
          })
          .join(", ");
      } else {
        const selectParts: string[] = [];

        for (const join of joins) {
          if (join.select && join.select.length > 0) {
            const joinColumns = join.select
              .map((col) => {
                if (col === "*") {
                  return `"${join.table}".*`;
                }
                if (/\s+as\s+/i.test(col)) {
                  const [originalCol, alias] = col.split(/\s+as\s+/i);
                  return `"${join.table}"."${(originalCol || '').trim()}" AS "${(alias || '').trim()}"`;
                }
                return `"${join.table}"."${col}" AS "${join.table}_${col}"`;
              })
              .join(", ");
            if (joinColumns) {
              selectParts.push(joinColumns);
            }
          }
        }

        selectParts.push(`"${this.tableName}".*`);
        selectClause = selectParts.filter((p) => p.trim()).join(", ");
      }

      let joinClause = "";
      for (const join of joins) {
        const joinType = join.type || "LEFT";
        joinClause += ` ${joinType} JOIN "${join.table}" ON ${join.on}`;
      }

      let query = `SELECT ${selectClause} FROM "${this.tableName}"${joinClause}${whereClause}`;

      if (orderBy) {
        const qualifiedOrderBy = orderBy.includes(".")
          ? orderBy.replace(/(\w+)\.(\w+)/, `"$1"."$2"`)
          : `"${this.tableName}"."${orderBy}"`;
        query += ` ORDER BY ${qualifiedOrderBy} ${orderDirection}`;
      }

      query += ` LIMIT ? OFFSET ?`;
      params.push(limit, offset);

      const records = await this.adapter.getConnection().query(query).all(...params);

      const primaryKey = await this.getPrimaryKey();
      let countQuery = `SELECT COUNT(DISTINCT "${this.tableName}"."${primaryKey}") as total FROM "${this.tableName}"${joinClause}${whereClause}`;
      const countParams = params.slice(0, -2);
      const totalResult = (await this.adapter.getConnection()
        .query(countQuery)
        .get(...countParams)) as { total: number };
      const processedData = records.map((record: any) => {
        return Object.fromEntries(
          Object.entries(record).filter(
            ([_, value]) => value !== null && value !== undefined,
          ),
        ) as T;
      });

      return {
        success: true,
        data: processedData,
        total: totalResult.total,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  async findByIdWithRelations(
    id: number | string,
    joins: JoinOptions[] = [],
    select: string[] = [],
  ): Promise<ControllerResponse<T>> {
    try {
      const primaryKey = await this.getPrimaryKey();

      let selectClause: string;

      if (select.length > 0) {
        selectClause = select
          .map((col) => {
            if (col.includes(".")) {
              const [tbl, cl] = col.split(".");
              return `"${tbl}"."${cl}"`;
            }
            return `"${this.tableName}"."${col}"`;
          })
          .join(", ");
      } else {
        const selectParts: string[] = [];

        for (const join of joins) {
          if (join.select && join.select.length > 0) {
            const joinColumns = join.select
              .map((col) => {
                if (col === "*") {
                  return `"${join.table}".*`;
                }
                if (/\s+as\s+/i.test(col)) {
                  const [originalCol, alias] = col.split(/\s+as\s+/i);
                  return `"${join.table}"."${(originalCol || '').trim()}" AS "${(alias || '').trim()}"`;
                }
                return `"${join.table}"."${col}" AS "${join.table}_${col}"`;
              })
              .join(", ");
            if (joinColumns) {
              selectParts.push(joinColumns);
            }
          }
        }

        selectParts.push(`"${this.tableName}".*`);
        selectClause = selectParts.filter((p) => p.trim()).join(", ");
      }

      let joinClause = "";
      for (const join of joins) {
        const joinType = join.type || "LEFT";
        joinClause += ` ${joinType} JOIN "${join.table}" ON ${join.on}`;
      }

      const query = `SELECT ${selectClause} FROM "${this.tableName}"${joinClause} WHERE "${this.tableName}"."${primaryKey}" = ?`;
      const record = await this.adapter.getConnection().query(query).get(id);

      if (!record) {
        return {
          success: false,
          error: "Record not found",
        };
      }
      const processedRecord = Object.fromEntries(
        Object.entries(record).filter(
          ([_, value]) => value !== null && value !== undefined,
        ),
      );

      return {
        success: true,
        data: processedRecord as T,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Helper method to create a simple join configuration
   */
  createJoin(
    table: string,
    localKey: string,
    foreignKey: string,
    type: "INNER" | "LEFT" | "RIGHT" | "FULL" = "LEFT",
    select?: string[],
  ): JoinOptions {
    return {
      table,
      on: `"${this.tableName}"."${localKey}" = "${table}"."${foreignKey}"`,
      type,
      select,
    };
  }

  /**
   * Helper method to create a reverse join configuration
   */
  createReverseJoin(
    targetTable: string,
    sourceForeignKey: string,
    targetPrimaryKey: string = "id",
    type: "INNER" | "LEFT" | "RIGHT" = "LEFT",
    selectColumns: string[] = ["*"],
  ): JoinOptions {
    let select: string[] | undefined = undefined;

    if (!selectColumns.includes("*")) {
      select = selectColumns;
    } else {
      if (targetTable === "categories") {
        select = [
          "name AS category_name",
          "description AS category_description",
        ];
      } else if (targetTable === "users") {
        select = ["name AS user_name", "email AS user_email"];
      }
    }

    return {
      table: targetTable,
      on: `"${this.tableName}"."${sourceForeignKey}" = "${targetTable}"."${targetPrimaryKey}"`,
      type,
      select,
    };
  }

  /**
   * Extrae y genera schemas Zod para la tabla actual
   */
  async extractSchema(): Promise<ControllerResponse<GeneratedZodSchema>> {
    try {
      const config = this.adapter.getConfig();
      const extractor = new SQLiteSchemaExtractor(config);
      const schema = await extractor.extractTableSchema(this.tableName);

      if (!schema) {
        return {
          success: false,
          error: `Failed to extract schema for table '${this.tableName}'`,
          errorType: DatabaseErrorType.QUERY_ERROR
        };
      }

      return {
        success: true,
        data: schema
      };
    } catch (error: unknown) {
      return createErrorResponse<GeneratedZodSchema>(error, {
        operation: "extractSchema",
        table: this.tableName
      });
    }
  }


  /**
   * Obtiene todos los schemas de la base de datos
   */
  async getAllDatabaseSchemas(): Promise<ControllerResponse<GeneratedZodSchema[]>> {
    try {
      const config = this.adapter.getConfig();
      const extractor = new SQLiteSchemaExtractor(config);
      const schemas = await extractor.extractAllSchemas();
      await extractor.close();

      return {
        success: true,
        data: schemas,
        message: `Extracted schemas for ${schemas.length} tables`
      };
    } catch (error: unknown) {
      return createErrorResponse<GeneratedZodSchema[]>(error, {
        operation: "getAllDatabaseSchemas"
      });
    }
  }

  /**
   * Static method to create a BaseController with auto-extracted schema
   */
  static async createWithAutoSchema<T = Record<string, unknown>>(
    tableName: string,
    database: SQL | Database,
    options: BaseControllerOptions = {}
  ): Promise<BaseController<T>> {
    // Create extractor to get table information
    const extractor = new SQLiteSchemaExtractor(database);

    try {
      // Extract schema for the specific table
      const extractedSchema = await extractor.extractTableSchema(tableName);

      if (!extractedSchema) {
        throw new Error(`Could not extract schema for table: ${tableName}`);
      }

      // Create validation schemas from extracted information
      // For create, we need to exclude auto-increment primary keys
      const schemaDef = extractedSchema.schema._def as any;
      const createFields = { ...schemaDef.shape };

      // Remove auto-increment primary key from create validation
      for (const column of extractedSchema.tableSchema.columns) {
        if (column.primaryKey && column.autoIncrement) {
          delete createFields[column.name];
        }
      }

      const createSchema = z.object(createFields);

      const schemas: SchemaCollection = {
        [tableName]: {
          create: createSchema,
          update: extractedSchema.schema,
          read: extractedSchema.schema
        }
      };

      // Create controller with auto-extracted schemas
      return new BaseController<T>(tableName, {
        ...options,
        database,
        schemas
      });
    } finally {
      await extractor.close();
    }
  }
}

export * from "./config";
export * from "./schema/schema-builder";
export * from "./schema/oauth-schema-extensions";
export * from "./schema/schema";
export * from "./schema/schema-extractor";