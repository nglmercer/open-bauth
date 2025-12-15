/**
 * Database Migration System
 * Handles migration from legacy table structures to normalized schemas
 */

import type { Database } from "bun:sqlite";
import {
  BaseController,
  type TableSchema,
  type ControllerResponse,
} from "../src/database/base-controller";
import { DatabaseInitializer } from "../src/database/database-initializer";

export interface ColumnMapping {
  oldName: string;
  newName: string;
  transform?: (value: any) => any;
  defaultValue?: any;
}

export interface TableMigration {
  oldTableName: string;
  newTableName: string;
  columnMappings: ColumnMapping[];
  customMigration?: (oldData: any) => any;
  skipIfExists?: boolean;
}

export interface MigrationConfig {
  database: Database;
  migrations: TableMigration[];
  backupTables?: boolean;
  logger?: Logger;
}

interface Logger {
  info(message: string, ...args: any[]): void;
  warn(message: string, ...args: any[]): void;
  error(message: string, ...args: any[]): void;
}

export interface MigrationResult {
  success: boolean;
  migratedTables: string[];
  errors: string[];
  totalRecordsMigrated: number;
  duration: number;
  backupTables?: string[];
}

const defaultLogger: Logger = {
  info: (msg: string, ...args: any[]) =>
    console.log(`[MIGRATION] ${msg}`, ...args),
  warn: (msg: string, ...args: any[]) =>
    console.warn(`[MIGRATION] ${msg}`, ...args),
  error: (msg: string, ...args: any[]) =>
    console.error(`[MIGRATION] ${msg}`, ...args),
};

// Predefined mappings for common Spanish to English translations
// En database-migration-system.ts

export const SPANISH_MAPPINGS: Record<string, ColumnMapping[]> = {
  // Mapeo para la tabla principal 'users' de la librería
  usuarios_a_users: [
    { oldName: "idUsuario", newName: "id" },
    { oldName: "correoUsuario", newName: "email" },
    { oldName: "claveUsuario", newName: "password_hash" },
    { oldName: "nombres", newName: "first_name" },
    { oldName: "apellidos", newName: "last_name" },
    { oldName: "fechaCreacion", newName: "created_at" },
  ],
  // Mapeo para nuestra nueva tabla 'user_profiles'
  usuarios_a_profiles: [
    { oldName: "idUsuario", newName: "user_id" }, // MUY IMPORTANTE: vincula con la tabla 'users'
    { oldName: "apodoUsuario", newName: "username" },
    {
      oldName: "nsfwUsuario",
      newName: "nsfw_enabled",
      transform: (val: any) => Boolean(val),
    },
    { oldName: "apicode", newName: "api_code" },
    { oldName: "fechaNacimiento", newName: "birth_date" },
    { oldName: "state", newName: "state" },
    { oldName: "country", newName: "country" },
    { oldName: "phone", newName: "phone" },
    {
      oldName: "preRegistrado",
      newName: "pre_registered",
      transform: (val: any) => Boolean(val),
    },
    {
      oldName: "creadorContenido",
      newName: "content_creator",
      transform: (val: any) => Boolean(val),
    },
    {
      oldName: "anticipado",
      newName: "early_access",
      transform: (val: any) => Boolean(val),
    },
    { oldName: "fotoPerfilUsuario", newName: "profile_photo_url" },
    { oldName: "plan", newName: "plan" },
    { oldName: "idUltimaTransaccion", newName: "last_transaction_id" },
    { oldName: "fechaUltimaTransaccion", newName: "last_transaction_date" },
  ],
  // El mapeo de roles permanece igual
  roles: [
    { oldName: "idRol", newName: "id" },
    { oldName: "nombreRol", newName: "name" },
    { oldName: "descripcionRol", newName: "description" },
    { oldName: "fechaCreacion", newName: "created_at" },
    {
      oldName: "activo",
      newName: "is_active",
      transform: (val: any) => Boolean(val),
    },
  ],
  permisos: [
    { oldName: "idPermiso", newName: "id" },
    { oldName: "nombrePermiso", newName: "name" },
    { oldName: "recurso", newName: "resource" },
    { oldName: "accion", newName: "action" },
    { oldName: "descripcion", newName: "description" },
    { oldName: "fechaCreacion", newName: "created_at" },
  ],
};

export class DatabaseMigrationManager {
  private database: Database;
  private logger: Logger;
  private backupTables: boolean;

  constructor(config: MigrationConfig) {
    this.database = config.database;
    this.logger = config.logger || defaultLogger;
    this.backupTables = config.backupTables ?? true;
  }

  /**
   * Run all configured migrations
   */
  async migrate(migrations: TableMigration[]): Promise<MigrationResult> {
    const startTime = Date.now();
    const result: MigrationResult = {
      success: false,
      migratedTables: [],
      errors: [],
      totalRecordsMigrated: 0,
      duration: 0,
      backupTables: [],
    };

    this.logger.info("Starting database migration...");

    try {
      // Begin transaction for safety
      this.database.run("BEGIN TRANSACTION;");

      for (const migration of migrations) {
        try {
          const migrationResult = await this.migrateSingleTable(migration);

          if (migrationResult.success) {
            result.migratedTables.push(migration.newTableName);
            result.totalRecordsMigrated += migrationResult.recordCount || 0;

            if (migrationResult.backupTable) {
              result.backupTables?.push(migrationResult.backupTable);
            }
          } else {
            result.errors.push(
              `Failed to migrate ${migration.oldTableName}: ${migrationResult.error}`,
            );
          }
        } catch (error: any) {
          result.errors.push(
            `Error migrating ${migration.oldTableName}: ${error.message}`,
          );
          this.logger.error(
            `Migration failed for ${migration.oldTableName}:`,
            error,
          );
        }
      }

      // Commit transaction if all migrations succeeded
      if (result.errors.length === 0) {
        this.database.run("COMMIT;");
        result.success = true;
        this.logger.info(
          `Migration completed successfully. Migrated ${result.totalRecordsMigrated} records across ${result.migratedTables.length} tables.`,
        );
      } else {
        this.database.run("ROLLBACK;");
        this.logger.error(
          `Migration failed with ${result.errors.length} errors. Transaction rolled back.`,
        );
      }
    } catch (error: any) {
      this.database.run("ROLLBACK;");
      result.errors.push(`Transaction error: ${error.message}`);
      this.logger.error("Migration transaction failed:", error);
    }

    result.duration = Date.now() - startTime;
    return result;
  }

  /**
   * Migrate a single table
   */
  private async migrateSingleTable(migration: TableMigration): Promise<{
    success: boolean;
    error?: string;
    recordCount?: number;
    backupTable?: string;
  }> {
    const {
      oldTableName,
      newTableName,
      columnMappings,
      customMigration,
      skipIfExists,
    } = migration;

    this.logger.info(`Starting migration: ${oldTableName} -> ${newTableName}`);

    // Check if old table exists
    const oldTableExists = await this.checkTableExists(oldTableName);
    if (!oldTableExists) {
      return {
        success: false,
        error: `Source table ${oldTableName} does not exist`,
      };
    }

    // Check if new table exists and skip if configured
    const newTableExists = await this.checkTableExists(newTableName);
    if (newTableExists && skipIfExists) {
      this.logger.info(`Skipping migration: ${newTableName} already exists`);
      return { success: true, recordCount: 0 };
    }

    try {
      // Create backup if enabled
      let backupTableName: string | undefined;
      if (this.backupTables) {
        backupTableName = await this.createBackupTable(oldTableName);
        this.logger.info(`Created backup table: ${backupTableName}`);
      }

      // Get old table data
      const oldData = await this.getTableData(oldTableName);
      this.logger.info(
        `Retrieved ${oldData.length} records from ${oldTableName}`,
      );

      // Transform data according to mappings
      const transformedData = await this.transformData(
        oldData,
        columnMappings,
        customMigration,
      );
      this.logger.info(`Transformed ${transformedData.length} records`);

      // Insert into new table (assuming it exists)
      if (transformedData.length > 0) {
        await this.insertTransformedData(newTableName, transformedData);
        this.logger.info(
          `Inserted ${transformedData.length} records into ${newTableName}`,
        );
      }

      return {
        success: true,
        recordCount: transformedData.length,
        backupTable: backupTableName,
      };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Check if table exists
   */
  private async checkTableExists(tableName: string): Promise<boolean> {
    const result = this.database
      .query("SELECT name FROM sqlite_master WHERE type='table' AND name=?")
      .get(tableName);
    return !!result;
  }

  /**
   * Create backup table
   */
  private async createBackupTable(originalTableName: string): Promise<string> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "_");
    const backupTableName = `${originalTableName}_backup_${timestamp}`;

    this.database.run(
      `CREATE TABLE "${backupTableName}" AS SELECT * FROM "${originalTableName}"`,
    );
    return backupTableName;
  }

  /**
   * Get all data from a table
   */
  private async getTableData(tableName: string): Promise<any[]> {
    const stmt = this.database.prepare(`SELECT * FROM "${tableName}"`);
    return stmt.all();
  }

  /**
   * Transform data according to column mappings
   */
  private async transformData(
    data: any[],
    mappings: ColumnMapping[],
    customTransform?: (data: any) => any,
  ): Promise<any[]> {
    return data.map((row) => {
      let transformedRow: any = {};

      // Apply column mappings
      for (const mapping of mappings) {
        const oldValue = row[mapping.oldName];

        if (oldValue !== undefined) {
          let newValue = oldValue;

          // Apply transformation if provided
          if (mapping.transform) {
            try {
              newValue = mapping.transform(oldValue);
            } catch (error: any) {
              this.logger.warn(
                `Transformation failed for ${mapping.oldName}:`,
                error,
              );
              newValue = mapping.defaultValue ?? oldValue;
            }
          }

          transformedRow[mapping.newName] = newValue;
        } else if (mapping.defaultValue !== undefined) {
          transformedRow[mapping.newName] = mapping.defaultValue;
        }
      }

      // Apply custom transformation if provided
      if (customTransform) {
        try {
          transformedRow = customTransform(transformedRow) || transformedRow;
        } catch (error: any) {
          this.logger.warn("Custom transformation failed:", error);
        }
      }

      return transformedRow;
    });
  }

  /**
   * Insert transformed data into new table
   */
  private async insertTransformedData(
    tableName: string,
    data: any[],
  ): Promise<void> {
    if (data.length === 0) return;

    const firstRow = data[0];
    const columns = Object.keys(firstRow);
    const placeholders = columns.map(() => "?").join(", ");
    const columnNames = columns.map((col) => `"${col}"`).join(", ");

    const insertSQL = `INSERT OR IGNORE INTO "${tableName}" (${columnNames}) VALUES (${placeholders})`;
    const stmt = this.database.prepare(insertSQL);

    for (const row of data) {
      const values = columns.map((col) => row[col]);
      stmt.run(...values);
    }
  }

  /**
   * Analyze existing table structure
   */
  async analyzeTable(tableName: string): Promise<{
    exists: boolean;
    columns: Array<{ name: string; type: string; pk: number }>;
    recordCount: number;
    sampleData: any[];
  }> {
    const exists = await this.checkTableExists(tableName);

    if (!exists) {
      return { exists: false, columns: [], recordCount: 0, sampleData: [] };
    }

    // Get table info
    const columns = this.database
      .query(`PRAGMA table_info("${tableName}")`)
      .all() as any[];

    // Get record count
    const countResult = this.database
      .query(`SELECT COUNT(*) as count FROM "${tableName}"`)
      .get() as any;
    const recordCount = countResult?.count || 0;

    // Get sample data (first 5 rows)
    const sampleData = this.database
      .query(`SELECT * FROM "${tableName}" LIMIT 5`)
      .all();

    return {
      exists: true,
      columns: columns.map((col) => ({
        name: col.name,
        type: col.type,
        pk: col.pk,
      })),
      recordCount,
      sampleData,
    };
  }

  /**
   * Generate migration config from table analysis
   */
  async generateMigrationConfig(
    oldTableName: string,
    newTableName: string,
    customMappings?: Record<string, string>,
  ): Promise<TableMigration | null> {
    const analysis = await this.analyzeTable(oldTableName);

    if (!analysis.exists) {
      this.logger.warn(`Table ${oldTableName} does not exist`);
      return null;
    }

    // Use predefined mappings if available, otherwise use custom or identity mapping
    let columnMappings: ColumnMapping[] = [];

    if (SPANISH_MAPPINGS[oldTableName]) {
      columnMappings = SPANISH_MAPPINGS[oldTableName];
    } else {
      // Generate mappings from columns
      columnMappings = analysis.columns.map((col) => ({
        oldName: col.name,
        newName: customMappings?.[col.name] || col.name,
      }));
    }

    return {
      oldTableName,
      newTableName,
      columnMappings,
      skipIfExists: true,
    };
  }

  /**
   * Preview migration without executing it
   */
  async previewMigration(migration: TableMigration): Promise<{
    sourceTableAnalysis: Awaited<{
      exists: boolean;
      columns: Array<{
        name: string;
        type: string;
        pk: number;
      }>;
      recordCount: number;
      sampleData: any[];
    }>;
    sampleTransformedData: any[];
    estimatedRecords: number;
  }> {
    const sourceAnalysis = await this.analyzeTable(migration.oldTableName);

    if (!sourceAnalysis.exists) {
      throw new Error(`Source table ${migration.oldTableName} does not exist`);
    }

    // Transform sample data
    const sampleTransformed = await this.transformData(
      sourceAnalysis.sampleData,
      migration.columnMappings,
      migration.customMigration,
    );

    return {
      sourceTableAnalysis: sourceAnalysis,
      sampleTransformedData: sampleTransformed,
      estimatedRecords: sourceAnalysis.recordCount,
    };
  }

  /**
   * Cleanup backup tables older than specified days
   */
  async cleanupBackups(olderThanDays: number = 30): Promise<string[]> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

    // Get all tables
    const tables = this.database
      .query(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%_backup_%'",
      )
      .all() as any[];

    const deletedTables: string[] = [];

    for (const table of tables) {
      const tableName = table.name;

      // Extract timestamp from backup table name
      const timestampMatch = tableName.match(/_backup_(.+)$/);
      if (timestampMatch) {
        const timestamp = timestampMatch[1].replace(/_/g, ":");
        const tableDate = new Date(timestamp.replace(/_/g, "."));

        if (tableDate < cutoffDate) {
          this.database.run(`DROP TABLE "${tableName}"`);
          deletedTables.push(tableName);
          this.logger.info(`Deleted old backup table: ${tableName}`);
        }
      }
    }

    return deletedTables;
  }
}

// Utility functions for common migration scenarios

/**
 * Create a complete migration configuration for Spanish to English user table
 */
export function createUserMigrationConfig(
  oldTableName: string = "usuarios",
  newTableName: string = "users",
): TableMigration {
  return {
    oldTableName,
    newTableName,
    columnMappings: SPANISH_MAPPINGS.usuarios,
    customMigration: (data: any) => {
      // Ensure required fields for auth system
      return {
        ...data,
        is_active: data.is_active ?? true,
        password_hash: data.password_hash || data.claveUsuario,
      };
    },
    skipIfExists: true,
  };
}

/**
 * Helper to create migration manager with database initializer
 */
export async function createMigrationWithInit(
  database: Database,
  targetSchemas: TableSchema[],
  migrations: TableMigration[],
  logger?: Logger,
): Promise<{
  initResult: Awaited<ReturnType<DatabaseInitializer["initialize"]>>;
  migrationResult: MigrationResult;
}> {
  // Initialize target schema first
  const dbInit = new DatabaseInitializer({
    database,
    logger,
    enableWAL: true,
    enableForeignKeys: true,
  });

  const initResult = await dbInit.initialize(targetSchemas);

  if (!initResult.success) {
    throw new Error(
      `Database initialization failed: ${initResult.errors.join(", ")}`,
    );
  }

  // Run migrations
  const migrationManager = new DatabaseMigrationManager({
    database,
    migrations,
    backupTables: true,
    logger,
  });

  const migrationResult = await migrationManager.migrate(migrations);

  return { initResult, migrationResult };
}
