# Technical Specification for Extending Initial Tables (Template)

This document defines the standardized way to add new tables to the project's base schema, ensuring they always exist and are created/migrated safely through the database initializer.

Relevant files:
- Initializer and schema registration: [`src/database/database-initializer.ts`](src/database/database-initializer.ts)
- Generic controller and SQL utilities: [`src/database/base-controller.ts`](src/database/base-controller.ts)
- Database re-exports: [`src/database/index.ts`](src/database/index.ts) and [`src/index.ts`](src/index.ts)

## Objective
- Incorporate new tables (e.g., points, notifications, processes) in a safe and repeatable manner.
- Ensure creation via `DatabaseInitializer.initialize/migrate/repair`.
- Maintain consistency in names, data types, keys, relationships, and indexes.
- Allow schema extension from outside the library via minimal API (`externalSchemas`, `registerSchemas`, and `SchemaRegistry`), without modifying the base `DATABASE_SCHEMAS` array.

## Core Concepts
- `TableSchema`: describes the table (columns, indexes). Consumed by `BaseController.initializeDatabase` to generate and execute `CREATE TABLE/INDEX IF NOT EXISTS`.
- `ColumnDefinition`: defines name, type, PK, UNIQUE, NOT NULL, DEFAULT, and references (FK).
- `DEFAULT_SCHEMAS`: exported alias of the internal default set (backward compatibility). Do not modify it; use it as base if you need to compose.
- Effective schemas: `DatabaseInitializer` combines by default `DEFAULT_SCHEMAS` + optional `externalSchemas` for `initialize`, `checkIntegrity`, `reset`, and `getStatistics` unless an explicit array is passed.
- Extension API:
  - `externalSchemas` (constructor): allows passing a `TableSchema[]` array from outside to combine with base ones.
  - `registerSchemas(schemas)`: method to dynamically register new schemas after construction; deduplicates by `tableName` and overrides existing if duplicates.
  - `SchemaRegistry`: lightweight utility for modular registration, merging, and retrieving schemas, useful for external packages/plugins.
- Type and default handling:
  - `mapDataType` adapts types for SQLite and other engines.
  - `formatDefaultValue` ensures correct defaults: booleans → 1/0 in SQLite; SQL functions/keywords without quotes (e.g., `CURRENT_TIMESTAMP`, expressions in parentheses); string literals with single quotes.
- Integrity and migration:
  - `DatabaseInitializer.checkIntegrity` detects missing tables/indexes.
  - `DatabaseInitializer.initialize` creates the full schema set.
  - `DatabaseInitializer.migrate/repair` re-creates missing components.

## Extension Flow
1. Define your new table as `TableSchema` in your own package or app code (outside the library).
2. Register it using one of these options (without touching `DATABASE_SCHEMAS`):
   - Pass via `externalSchemas` in constructor.
   - Call `initializer.registerSchemas(schema | schema[])` after constructing `DatabaseInitializer`.
   - Compose a `SchemaRegistry`, pass `registry.getAll()` to constructor or `registerSchemas`.
3. Run `initialize()` or `migrate()/repair()` on startup to ensure existence.
4. Consume the table via `BaseController` or `DatabaseInitializer.createController`.

## TableSchema Template (copy and adapt)
```ts
// Reference file: src/database/database-initializer.ts
export const NEW_SCHEMAS: TableSchema[] = [
  {
    tableName: "<table_name>",
    columns: [
      // Recommended PK (UUID-like via randomblob hex in SQLite):
      { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },

      // Examples:
      // { name: