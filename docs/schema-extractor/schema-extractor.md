# Database Schema Extractor

The Schema Extractor is a powerful utility that automatically extracts table structures from an existing SQLite database and converts them into typed schema definitions and Zod schemas. This is particularly useful when working with legacy databases or when you need to generate type-safe interfaces for existing tables.

## 🚀 Quick Start

```typescript
import { SQLiteSchemaExtractor, createSchemaExtractor } from '../src/database/schema/schema-extractor';
import { Database } from "bun:sqlite";

// Option 1: Using the helper function
const extractor = createSchemaExtractor("path/to/database.db");

// Option 2: Using with an existing database instance
const db = new Database("path/to/database.db");
const extractor = new SQLiteSchemaExtractor(db);

// Extract all table schemas
const allSchemas = await extractor.extractAllSchemas();

// Extract a specific table
const userSchema = await extractor.extractTableSchema("users");
```

## 📋 Overview

The Schema Extractor provides functionality to:

- Extract table structures from SQLite databases
- Convert extracted structures to `TableSchema` objects
- Generate Zod schemas for runtime type validation
- Detect column types automatically, including intelligent date detection
- Extract constraints (primary keys, foreign keys, unique constraints, check constraints)
- Support for manual overrides to correct or enhance extracted data
- Convert to the `Schema` class format for compatibility with other parts of the library

## 🔧 API Reference

### Constructor

```typescript
constructor(database: Database | SQL | DatabaseAdapterConfig)
```

Creates a new instance of the `SQLiteSchemaExtractor`.

**Parameters:**

- `database`: Either a Database instance, a SQL query instance, or a database adapter configuration object

### Methods

#### getAllTableNames()

```typescript
async getAllTableNames(): Promise<string[]>
```

Retrieves all table names from the database, excluding system tables.

**Returns:**

- An array of table names as strings

#### getAllTablesInfo()

```typescript
async getAllTablesInfo(): Promise<TableInfo[]>
```

Gets detailed information for all tables in the database, including columns, SQL, indexes, and foreign keys.

**Returns:**

- An array of `TableInfo` objects

#### getTableInfo()

```typescript
async getTableInfo(tableName: string): Promise<TableInfo | null>
```

Retrieves detailed information for a specific table.

**Parameters:**

- `tableName`: The name of the table to analyze

**Returns:**

- A `TableInfo` object or null if the table doesn't exist

#### extractAllSchemas()

```typescript
async extractAllSchemas(): Promise<GeneratedZodSchema[]>
```

Extracts and generates Zod schemas for all tables in the database.

**Returns:**

- An array of `GeneratedZodSchema` objects, each containing the table name, Zod schema, and table schema

#### extractTableSchema()

```typescript
async extractTableSchema(tableName: string): Promise<GeneratedZodSchema | null>
```

Extracts and generates a Zod schema for a specific table.

**Parameters:**

- `tableName`: The name of the table to extract

**Returns:**

- A `GeneratedZodSchema` object or null if the table doesn't exist

#### extractAsTableSchemas()

```typescript
async extractAsTableSchemas(): Promise<TableSchema[]>
```

Extracts all schemas and converts them to `TableSchema` objects compatible with the schema builder.

**Returns:**

- An array of `TableSchema` objects

#### extractTableSchemaAsTableSchema()

```typescript
async extractTableSchemaAsTableSchema(tableName: string): Promise<TableSchema | null>
```

Extracts a specific table and converts it to a `TableSchema` object.

**Parameters:**

- `tableName`: The name of the table to extract

**Returns:**

- A `TableSchema` object or null if the table doesn't exist

#### extractAsSchemaInstances()

```typescript
async extractAsSchemaInstances(): Promise<{ [tableName: string]: Schema }>
```

Extracts schemas and converts them to `Schema` class instances.

**Returns:**

- An object mapping table names to `Schema` instances

#### registerOverride()

```typescript
public registerOverride(tableName: string, columnName: string, override: Partial<ColumnDefinition>)
```

Registers a manual override for a specific column to correct or enhance automatically detected properties.

**Parameters:**

- `tableName`: The name of the table
- `columnName`: The name of the column
- `override`: Partial column definition with properties to override

#### registerTableOverride()

```typescript
public registerTableOverride(tableName: string, override: Partial<TableSchema>)
```

Registers a manual override for a table schema, useful for defining indexes that cannot be extracted from the table SQL.

**Parameters:**

- `tableName`: The name of the table
- `override`: Partial table schema with properties to override

#### close()

```typescript
async close(): Promise<void>
```

Closes the adapter connection and cleans up resources.

## 🔍 Advanced Features

### Automatic Type Detection

The extractor automatically detects column types and enhances them where possible:

- **Date Detection**: Analyzes TEXT columns to detect if they contain date values
- **Foreign Key Detection**: Extracts foreign key relationships from PRAGMA data and table SQL
- **Index Extraction**: Identifies both single-column and multi-column indexes
- **Constraint Analysis**: Extracts unique constraints and check constraints

### Manual Overrides

You can use manual overrides to correct or enhance the automatically extracted schema:

```typescript
// Override a column type
extractor.registerOverride("users", "status", {
  type: "TEXT",
  notNull: true,
  defaultValue: "active"
});

// Override table properties
extractor.registerTableOverride("users", {
  indexes: [
    { name: "idx_user_email_status", columns: ["email", "status"] }
  ]
});
```

### Zod Schema Generation

The extractor generates Zod schemas that can be used for runtime validation:

```typescript
const userSchema = await extractor.extractTableSchema("users");
if (userSchema) {
  // Validate data against the schema
  const result = userSchema.schema.parse({
    id: 1,
    email: "user@example.com",
    password: "securepassword"
  });
  
  // The result will be typed according to the table structure
  
  // You can also use safeParse for error handling
  const validationResult = userSchema.schema.safeParse({
    id: "invalid-id", // This will fail validation if id is expected to be a number
    email: "user@example.com"
  });
  
  if (validationResult.success) {
    console.log("Valid user:", validationResult.data);
  } else {
    console.error("Validation errors:", validationResult.error.format());
  }
  
  // Extract schemas for all tables
  const allSchemas = await extractor.extractAllSchemas();
  
  // Create a type-safe validation function
  const validateUser = (data: unknown) => {
    const userSchema = allSchemas.find(s => s.tableName === "users")?.schema;
    if (!userSchema) throw new Error("User schema not found");
    
    return userSchema.parse(data);
  };
}
```

## 🔄 Integration with DatabaseInitializer

You can use the schema extractor to generate schemas for the DatabaseInitializer:

```typescript
import { DatabaseInitializer } from '../src/database/base-controller';
import { Database } from 'bun:sqlite';

// Extract existing schemas
const extractor = createSchemaExtractor("existing.db");
const tableSchemas = await extractor.extractAsTableSchemas();

// Use with DatabaseInitializer
const dbInitializer = new DatabaseInitializer({
  database: db,
  externalSchemas: tableSchemas
});

// Initialize the database with the extracted schemas
await dbInitializer.initialize();

// Get a controller for one of the extracted tables
const usersController = dbInitializer.getController("users");
const users = await usersController.search({ email: "user@example.com" });
```

### Complete Workflow Example

```typescript
import { createSchemaExtractor, DatabaseInitializer, AuthService, JWTService } from 'open-bauth';
import { Database } from 'bun:sqlite';

async function initializeFromExistingDatabase(dbPath: string) {
  // 1. Extract schemas from existing database
  const extractor = createSchemaExtractor(dbPath);
  const schemas = await extractor.extractAllSchemas();
  
  // 2. Create a new database instance
  const db = new Database('new-auth.db');
  
  // 3. Initialize with extracted schemas
  const dbInitializer = new DatabaseInitializer({
    database: db,
    externalSchemas: schemas.map(s => s.tableSchema)
  });
  
  // 4. Initialize the database
  await dbInitializer.initialize();
  
  // 5. Set up authentication services
  const jwtService = new JWTService('your-secret', '7d');
  const authService = new AuthService(dbInitializer, jwtService);
  
  // 6. Extract Zod schemas for validation
  const userSchema = schemas.find(s => s.tableName === "users")?.schema;
  
  return {
    dbInitializer,
    authService,
    schemas,
    validate: (data: any) => userSchema?.parse(data)
  };
}

// Usage
const { dbInitializer, authService, validate } = await initializeFromExistingDatabase("legacy.db");
```

## 📊 Interfaces and Types

### TableInfo

```typescript
interface TableInfo {
  tableName: string;
  columns: SQLiteColumnInfo[];
  sql: string;
  inspectedTypes?: Record<string, string>;
  indexes?: { name: string; columns: string[]; unique?: boolean }[];
  foreignKeys?: { table: string; from: string; to: string }[];
}
```

### SQLiteColumnInfo

```typescript
interface SQLiteColumnInfo {
  cid: number;
  name: string;
  type: string;
  notnull: number;
  dflt_value: any;
  pk: number;
}
```

### GeneratedZodSchema

```typescript
interface GeneratedZodSchema {
  tableName: string;
  schema: z.ZodObject<any>;
  tableSchema: TableSchema;
}
```

## 💡 Use Cases

### 1. Legacy Database Integration

When working with an existing database that wasn't created with this library, the schema extractor can generate type-safe interfaces for all tables:

```typescript
const extractor = createSchemaExtractor("legacy.db");
const schemas = await extractor.extractAllSchemas();

// Now you have Zod schemas for validation
schemas.forEach(({ tableName, schema }) => {
  console.log(`Schema for ${tableName}:`, schema);
});
```

### 2. Schema Migration

When migrating from one database system to another, use the schema extractor to export the structure:

```typescript
// Extract from SQLite
const extractor = createSchemaExtractor("source.db");
const schemas = await extractor.extractAsTableSchemas();

// Use with a different adapter
const pgAdapter = AdapterFactory.createAdapter({
  // PostgreSQL configuration
});

// Now you can use the schemas with PostgreSQL
```

### 3. Documentation Generation

Generate documentation for existing databases:

```typescript
const extractor = createSchemaExtractor("production.db");
const tableNames = await extractor.getAllTableNames();

for (const tableName of tableNames) {
  const tableInfo = await extractor.getTableInfo(tableName);
  console.log(`Table: ${tableInfo.tableName}`);
  console.log(`Columns: ${tableInfo.columns.length}`);
  console.log(`Indexes: ${tableInfo.indexes?.length || 0}`);
  console.log(`Foreign Keys: ${tableInfo.foreignKeys?.length || 0}`);
}
```

## ⚡ Performance Considerations

- The extractor performs database queries to analyze the structure, so it should be used during initialization or development rather than in hot code paths
- Data inspection for date detection samples up to 10 rows per column, which is generally sufficient for accurate detection
- Complex queries with many tables may take time to analyze; consider caching the results if needed

## 🔒 Security Considerations

- The extractor reads the database schema but doesn't access table data (except for limited sampling for type detection)
- No sensitive data is exposed during the extraction process
- The extracted schema may reveal table and column names, which should be considered part of your API surface

