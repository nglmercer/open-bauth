# SQLite Migration Generator

The migration generator (`src/database/schema/migration-generator.ts`) takes the differences detected by the `SchemaComparator` and generates the precise sequence of SQL statements required to migrate the database to the target state.

## Overview

Generating migrations for SQLite is complex due to its limited `ALTER TABLE` support. The `SQLiteMigrationGenerator` handles this by implementing a robust "Table Rebuild" strategy when necessary, ensuring data preservation and structural integrity.

## Migration Process

The `generateMigrationSQL` method produces an ordered array of SQL statements following this sequence:

1. **Drop Views**: Removes explicitly dropped or altered views, plus "stale" views (views depending on modified tables).
2. **Drop Tables**: Removes tables marked for deletion.
3. **Create Tables**: Creates new tables.
4. **Rename Tables**: Executes `ALTER TABLE ... RENAME TO ...`.
5. **Alter Tables**:
   - Performs standard `ALTER TABLE` operations (e.g., `ADD COLUMN`, `DROP COLUMN`) where supported.
   - **Table Rebuilds**: If an operation is not supported (e.g., modifying a column's type or adding a `NOT NULL` column without a default), the table is completely rebuilt.
6. **Create Views**: Recreates views in dependency order to prevent errors.
7. **Manage Triggers**: Drops, Creates, or Recreates triggers.

## Key Capabilities

### Table Rebuild Strategy

When a simple `ALTER TABLE` is insufficient, the generator performs a full rebuild:

1. Creates a temporary table `_new_TableName` with the new schema.
2. Copies data from the old table to the new one (mapping renamed columns if needed).
3. Preserves `sqlite_sequence` values for tables with `AUTOINCREMENT`.
4. Drops the old table.
5. Renames the temporary table to the original name.
6. Recreates indexes and triggers.

### Stale View & Trigger Detection

If a table is modified (even if just renamed), views and triggers depending on it might become invalid. The generator:

- Scans `targetViews` and `targetTriggers` for references to modified tables.
- Automatically drops and recreates these "stale" artifacts to ensure they link correctly to the new table structure.

### Dependency Sorting

Views are sorted topologically based on their dependencies. This ensures that if `View A` depends on `View B`, `View B` is created first.

## Usage

```typescript
import { SQLiteMigrationGenerator } from "./database/schema/migration-generator";

const sqlStatements = SQLiteMigrationGenerator.generateMigrationSQL(
  diff, // The SchemaDiff object
  targetTriggers, // List of all desired triggers (for restoration)
  targetViews // List of all desired views (for restoration)
);

// Execute statements in a transaction
db.transaction(() => {
  for (const sql of sqlStatements) {
    db.prepare(sql).run();
  }
})();
```

## Limitations / Considerations

- **Complex Defaults**: While simple defaults work well, complex SQL expressions in default values may trigger a table rebuild to be safe.
- **Foreign Keys**: The rebuild process temporarily disables foreign keys (standard SQLite practice) but ensures data integrity is maintained during the copy.
