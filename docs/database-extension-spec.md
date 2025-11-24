# Technical Specification for Extending Initial Tables (Template)

Defines standardized addition of new tables to base schema, ensuring safe creation/migration via initializer.

**Relevant files**:
- [`src/database/database-initializer.ts`](src/database/database-initializer.ts)
- [`src/database/base-controller.ts`](src/database/base-controller.ts)

## Objective
- Add tables (points, notifications) safely.
- Creation via `initialize/migrate/repair`.
- Consistency: names, types, keys, indexes.
- External extension without modifying core.

## Concepts
- `TableSchema`: table description.
- `ColumnDefinition`: column spec.
- `DEFAULT_SCHEMAS`: base (don't modify).
- Effective: base + external.
- API: `externalSchemas`, `registerSchemas()`, `SchemaRegistry`.

## Flow
1. Define `TableSchema`.
2. Register (externalSchemas/registerSchemas/SchemaRegistry).
3. `initialize()`.
4. Use `createController(table)`.

## Template
```ts
export const NEW_SCHEMAS: TableSchema[] = [
  {
    tableName: "points",
    columns: [
      { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
      { name: "user_id", type: "TEXT", notNull: true, references: { table: "users", column: "id" } },
      { name: "points", type: "INTEGER", notNull: true, defaultValue: 0 },
      { name: "reason", type: "TEXT" },
      { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" }
    ],
    indexes: [
      { name: "idx_points_user_id", columns: ["user_id"] }
    ]
  },
  // notifications, processes examples...
];
```

Register:
```ts
const initializer = new DatabaseInitializer({ database: db, externalSchemas: NEW_SCHEMAS });
await initializer.initialize();
```

## Examples
1. **Points**:
   - Columns: id, user_id (FK), points, reason, created_at
   - Indexes: user_id, created_at

2. **Notifications**:
   - id, user_id, title, body, channel, status, read_at, created_at
   - Indexes: user_id, status

3. **Processes**:
   - id, name, status, retries, payload, last_error, started_at, finished_at

Defaults: literals "'pending'", functions `CURRENT_TIMESTAMP` no quotes.

## Conventions
- snake_case columns
- TEXT PK with randomblob
- DATETIME CURRENT_TIMESTAMP
- BOOLEAN → 1/0 SQLite
- Indexes on FK/frequent filters

## Checklist
- [ ] TableSchema with PK/FK/indexes
- [ ] Register external
- [ ] Test initialize/integrity
- [ ] Defaults/types validated

## Common Issues
- Defaults: "'text'", `CURRENT_TIMESTAMP` no quotes
- UNIQUE/FK: indexes/references
- Booleans: BOOLEAN type

## Validation
bun test tests/schema-extension.test.ts

---
Template for consistent, safe schema extension.