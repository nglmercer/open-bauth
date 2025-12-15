# Schema Comparison

The schema comparison module (`src/database/schema/schema-comparison.ts`) is responsible for detecting differences between the current state of the database and the target state defined in your application's schema definitions. It is a critical component of the migration system, providing the input required by the `SQLiteMigrationGenerator`.

## Overview

The core class `SchemaComparator` compares three main database artifacts:

1. **Tables**: Columns, data types, constraints (PK, Unique, Not Null), default values, and indexes.
2. **Views**: SQL definitions.
3. **Triggers**: SQL definitions.

It produces a `SchemaDiff` object containing list of detected changes, classified by type: `CREATE`, `DROP`, `ALTER`, or `RENAME`.

## Key Features

### Table Comparison

The comparator performs a deep inspection of table structures:

- **Columns**: Checks for changes in name (via rename hints), data type, nullability, uniqueness, and default values.
- **Indexes**: Checks for added, removed, or modified indexes.
- **Renames**: It can detect table and column renames if provided with a `CompareOptions` object containing mapping hints.

### SQLite Normalization

To reduce false positives, the comparator normalizes SQL artifacts typical of SQLite:

- **Types**: Normalizes `VARCHAR` to `TEXT`, `INT` to `INTEGER`, `BOOL` to `BOOLEAN`, etc.
- **Default Values**: Handles quoting differences (e.g., `'1'` vs `1`) and function wrappers (e.g., `(CURRENT_TIMESTAMP)` vs `CURRENT_TIMESTAMP`).
- **SQL Whitespace**: Normalizes whitespace in View and Trigger definitions to compare logic rather than formatting.

## Usage

```typescript
import { SchemaComparator } from "./database/schema/schema-comparison";

const diff = SchemaComparator.compareSchemas(
  currentTables, // Array of TableSchema from database
  targetTables, // Array of TableSchema from code
  options, // Optional hints for renames
  currentViews, // Existing views
  targetViews, // Desired views
  currentTriggers, // Existing triggers
  targetTriggers // Desired triggers
);

console.log(diff.tableDiffs); // List of table changes
```

## Diff Structure

The output `SchemaDiff` contains arrays of differences:

```typescript
interface SchemaDiff {
  tableDiffs: TableDiff[];
  viewDiffs: ViewDiff[];
  triggerDiffs: TriggerDiff[];
}
```

Each "Diff" object (e.g., `TableDiff`) contains:

- `changeType`: The type of operation (`CREATE`, `DROP`, `ALTER`, `RENAME`, `NONE`).
- `oldSchema` / `newSchema`: The state before and after.
- `columnDiffs`: Specific changes to columns.
- `indexDiffs`: Specific changes to indexes.
