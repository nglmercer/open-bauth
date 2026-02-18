// src/index.ts
// Core exports - no schemas included by default
export * from "./logger";
export * from "./services";
export * from "./database";
export * from "./types/auth";
export * from "./types/oauth";
export * from "./types/index";

// Reexportar Zod para conveniencia de usuarios y control de versiones
export * as zod from "zod";
export { z as z } from "zod";

// Reexportar tipos más comunes de forma explícita
export type {
  ZodSchema,
  ZodType,
  ZodObject,
  ZodTypeAny
} from "zod";

// Schema utilities (core only - no predefined schemas)
export { Schema, StandardFields } from "./database/schema";
export type {
  SchemaDefinition,
  SchemaField,
  SchemaOptions,
  SchemaIndex,
  SchemaTypeOptions,
  ModelZodSchemas,
  TypedModelZodSchemas,
  InferTypedSchemaRead,
  InferTypedSchemaCreate,
  InferTypedSchemaUpdate,
} from "./database/schema";

// Database utilities
export {
  BaseController,
  type TableSchema,
  type ColumnDefinition,
  type ControllerResponse,
  type SchemaCollection,
} from "./database/base-controller";

// Database initialization (works without predefined schemas)
export {
  DatabaseInitializer,
  SchemaRegistry,
  getCurrentSchemas,
  registerSchemas,
  hasSchemas,
  loadDefaultSchemas,
  getDefaultAuthSchemas,
  DATABASE_SCHEMAS,
} from "./database/database-initializer";

export type {
  MigrationResult,
  IntegrityCheckResult,
  DatabaseConfig as DatabaseInitializerConfig,
  DatabaseLogger,
} from "./database/database-initializer";

// Config utilities
export {
  getDatabaseConfig,
  setDatabaseConfig,
  getTableName,
  getAllTableNames,
  createSchemaExtension,
  SchemaExtensions,
  COMMON_COLUMNS,
  type DatabaseTableConfig,
  type DatabaseSchemaExtensions,
  type SchemaExtension,
} from "./database/config";