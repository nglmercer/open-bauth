/**
 * Schema Builder - Dynamic Schema Construction
 * 
 * This module provides utilities for building database schemas dynamically.
 * By default, no schemas are predefined - you must import and register them.
 * 
 * @example
 * ```ts
 * import { getAuthSchemas } from 'open-bauth/schemas';
 * 
 * const schemas = getAuthSchemas();
 * // Use schemas with DatabaseInitializer
 * ```
 */

import type { TableSchema, ColumnDefinition } from "../base-controller";
import { Schema } from "./schema";
import {
  getDatabaseConfig,
  getAllTableNames,
  getTableName,
  type DatabaseTableConfig,
} from "../config";
import { StandardFields } from "./constants";

// Re-export constants
export * from "./constants";

/**
 * Empty base schemas - the system works without predefined schemas
 * Users should import schemas from 'open-bauth/schemas' module
 */
export const BASE_SCHEMAS: Record<string, Schema> = {};

/**
 * Apply schema extensions to a base schema
 */
function applySchemaExtensions(
  baseSchema: TableSchema,
  extension?: import("../config").SchemaExtension,
): TableSchema {
  if (!extension) return baseSchema;

  let columns = [...baseSchema.columns];

  if (extension.removedColumns) {
    const toRemove = new Set(extension.removedColumns);
    columns = columns.filter((col) => !toRemove.has(col.name));
  }

  if (extension.modifiedColumns) {
    const modifications = new Map(
      extension.modifiedColumns.map((c) => [c.name, c]),
    );
    columns = columns.map((col) => modifications.get(col.name) || col);
  }

  if (extension.additionalColumns) {
    columns.push(...extension.additionalColumns);
  }

  return { ...baseSchema, columns };
}

/**
 * Update table references based on custom table names
 */
function updateTableReferences(
  schema: TableSchema,
  tableNames: Record<string, string>,
): TableSchema {
  const referenceMap: Record<string, string> = {};

  // Build reference map from known table names
  Object.entries(tableNames).forEach(([key, name]) => {
    referenceMap[key] = name;
  });

  const updatedColumns = schema.columns.map((column) => {
    if (column.references && referenceMap[column.references.table]) {
      return {
        ...column,
        references: {
          ...column.references,
          table: referenceMap[column.references.table],
        },
      };
    }
    return column;
  });

  const updatedIndexes = (schema.indexes || []).map((index) => {
    let newName = index.name;
    Object.entries(referenceMap).forEach(([key, customName]) => {
      if (newName.includes(`idx_${key}_`)) {
        newName = newName.replace(`idx_${key}_`, `idx_${customName}_`);
      }
    });
    return { ...index, name: newName };
  });

  return {
    ...schema,
    columns: updatedColumns,
    indexes: updatedIndexes,
  };
}

/**
 * Build database schemas from configuration
 * 
 * This function now returns an empty array by default unless:
 * 1. Schema extensions are configured
 * 2. External schemas are provided
 * 
 * For predefined auth/OAuth schemas, import them from 'open-bauth/schemas'
 */
export function buildDatabaseSchemas(): TableSchema[] {
  const config = getDatabaseConfig();
  const tableNames = getAllTableNames();
  const schemaExtensions = config.schemaExtensions || {};
  const schemas: TableSchema[] = [];

  // Process BASE_SCHEMAS (empty by default)
  const baseKeys = Object.keys(BASE_SCHEMAS) as (keyof typeof BASE_SCHEMAS)[];

  for (const key of baseKeys) {
    const definition = BASE_SCHEMAS[key];
    const configKey = key as keyof DatabaseTableConfig;
    const customTableName = tableNames[configKey];
    const extension = schemaExtensions[configKey];

    if (definition && customTableName) {
      let schema = definition.toTableSchema(customTableName);
      schema = applySchemaExtensions(schema, extension);
      schema = updateTableReferences(schema, tableNames);
      schemas.push(schema);
    }
  }

  // Process OAuth-style schema extensions
  const extensionKeys: (keyof DatabaseTableConfig)[] = [
    "oauthClients",
    "authorizationCodes",
    "refreshTokens",
    "deviceSecrets",
    "biometricCredentials",
    "anonymousUsers",
    "userDevices",
    "mfaConfigurations",
    "securityChallenges",
    "oauthSessions",
    "users",
    "roles",
    "permissions",
    "userRoles",
    "rolePermissions",
    "sessions",
  ];

  for (const key of extensionKeys) {
    const extension = schemaExtensions[key];
    const tableName = tableNames[key];

    if (extension?.additionalColumns?.length) {
      schemas.push({
        tableName: tableName || key,
        columns: extension.additionalColumns,
        indexes: [],
      });
    }
  }

  return schemas;
}

/**
 * Get table schema by table name
 */
export function getTableSchema(tableName: string): TableSchema | null {
  return buildDatabaseSchemas().find((s) => s.tableName === tableName) || null;
}

/**
 * Get table schema by configuration key
 */
export function getTableSchemaByKey(
  tableKey: keyof DatabaseTableConfig,
): TableSchema | null {
  return getTableSchema(getTableName(tableKey));
}

/**
 * Register external schemas to be used by the database
 * This is the recommended way to add schemas
 */
export function registerExternalSchemas(schemas: TableSchema[]): void {
  const { setDatabaseConfig, getDatabaseConfig, createSchemaExtension } = require("../config");
  const currentConfig = getDatabaseConfig();
  
  const schemaExtensions: Record<string, ReturnType<typeof createSchemaExtension>> = {};
  
  for (const schema of schemas) {
    schemaExtensions[schema.tableName] = createSchemaExtension(
      schema.columns,
      [],
      [],
    );
    
    if (schema.indexes && schema.indexes.length > 0) {
      // Include indexes in the extension
      schemaExtensions[schema.tableName] = createSchemaExtension(
        schema.columns,
        [],
        [],
      );
    }
  }

  setDatabaseConfig({
    ...currentConfig,
    schemaExtensions: {
      ...currentConfig.schemaExtensions,
      ...schemaExtensions,
    },
  });
}

/**
 * Merge schemas from multiple sources
 */
export function mergeSchemas(...schemaArrays: TableSchema[][]): TableSchema[] {
  const merged = new Map<string, TableSchema>();
  
  for (const schemas of schemaArrays) {
    for (const schema of schemas) {
      merged.set(schema.tableName, schema);
    }
  }
  
  return Array.from(merged.values());
}