# Database Extension Specification

This specification covers extending initial tables and adding completely custom tables to the authentication database without modifying the core library.

## 📋 Table of Contents

- [Overview](#overview)
- [Core Concepts](#core-concepts)
- [Schema Definition](#schema-definition)
- [Extension Mechanisms](#extension-mechanisms)
- [Predefined Extensions](#predefined-extensions)
- [Custom Extensions](#custom-extensions)
- [External Schemas](#external-schemas)
- [DatabaseInitializer API](#databaseinitializer-api)
- [Migration Support](#migration-support)
- [Best Practices](#best-practices)

## 🌟 Overview

The database extension system allows developers to:
- **Extend core tables** (users, roles, permissions) without modifying library code
- **Add custom tables** for application-specific data
- **Maintain compatibility** with library updates
- **Use type-safe** schema definitions
- **Handle migrations** automatically

### Key Benefits

1. **Non-Breaking Extensions**: Extend functionality without modifying core library
2. **Type Safety**: Full TypeScript support for all extensions
3. **Migration Support**: Automatic schema migration handling
4. **Backward Compatibility**: Extensions work across library versions
5. **Performance Optimized**: Efficient schema operations

## 🏗️ Core Concepts

### TableSchema

Core interface for defining database tables:

```typescript
interface TableSchema {
  tableName: string;
  columns: ColumnDefinition[];
  indexes?: IndexDefinition[];
  foreignKeys?: ForeignKeyDefinition[];
  uniqueConstraints?: UniqueConstraintDefinition[];
  checkConstraints?: CheckConstraintDefinition[];
}
```

### ColumnDefinition

Defines individual table columns:

```typescript
interface ColumnDefinition {
  name: string;
  type: string; // TEXT, INTEGER, BOOLEAN, BIT, DATETIME, etc.
  primaryKey?: boolean;
  autoIncrement?: boolean;
  notNull?: boolean;
  unique?: boolean;
  defaultValue?: string | number | boolean;
  references?: ReferenceDefinition;
  check?: string; // CHECK constraint
}
```

### Extension Types

1. **Schema Extensions**: Modify existing core tables
2. **External Schemas**: Add completely new tables
3. **Schema Registry**: Manage multiple schema sets

## 📝 Schema Definition

### Basic Schema Example

```typescript
import { TableSchema, ColumnDefinition } from "open-bauth/src/database/base-controller";

const customTable: TableSchema = {
  tableName: "user_profiles",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "user_id", type: "TEXT", notNull: true, references: { table: "users", column: "id" } },
    { name: "bio", type: "TEXT" },
    { name: "avatar_url", type: "TEXT" },
    { name: "date_of_birth", type: "DATETIME" },
    { name: "is_verified", type: "BOOLEAN", defaultValue: false },
    { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" },
    { name: "updated_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" }
  ],
  indexes: [
    { name: "idx_user_profiles_user_id", columns: ["user_id"] },
    { name: "idx_user_profiles_verified", columns: ["is_verified"] }
  ],
  foreignKeys: [
    { name: "fk_user_profiles_user_id", columns: ["user_id"], referencesTable: "users", referencesColumns: ["id"], onDelete: "CASCADE" }
  ]
};
```

### Advanced Schema Features

#### Column Types

```typescript
// Supported column types
type ColumnType = 
  | "TEXT"           // Variable length text
  | "INTEGER"         // 32-bit integer
  | "BIGINT"          // 64-bit integer
  | "REAL"            // Floating point number
  | "BOOLEAN"          // True/false values
  | "BIT"              // SQL Server compatible bit type
  | "DATETIME"         // Date and time
  | "DATE"            // Date only
  | "TIME"            // Time only
  | "JSON"            // JSON data storage
  | "BLOB"            // Binary data
  | "UUID";            // UUID values
```

#### Index Definitions

```typescript
interface IndexDefinition {
  name: string;
  columns: string[];
  unique?: boolean;
  partial?: boolean;
  where?: string; // Partial index condition
}
```

#### Foreign Key Definitions

```typescript
interface ForeignKeyDefinition {
  name?: string;
  columns: string[];
  referencesTable: string;
  referencesColumns: string[];
  onUpdate?: "CASCADE" | "SET NULL" | "RESTRICT" | "NO ACTION";
  onDelete?: "CASCADE" | "SET NULL" | "RESTRICT" | "NO ACTION";
}
```

## 🔧 Extension Mechanisms

### 1. Schema Extensions

Modify existing core tables:

```typescript
import { setDatabaseConfig, SchemaExtensions } from 'open-bauth';

// Extend users table
setDatabaseConfig({
  schemaExtensions: {
    users: {
      additionalColumns: [
        { name: "phone_number", type: "TEXT" },
        { name: "avatar_url", type: "TEXT" },
        { name: "timezone", type: "TEXT", defaultValue: "'UTC'" },
        { name: "language", type: "TEXT", defaultValue: "'en'" }
      ],
      removedColumns: ["is_active"], // Remove default column
      modifiedColumns: [
        { name: "email", type: "TEXT", notNull: true, unique: true }
      ],
      additionalIndexes: [
        { name: "idx_users_phone", columns: ["phone_number"] }
      ]
    }
  }
});
```

### 2. External Schemas

Add completely new tables:

```typescript
import { DatabaseInitializer } from 'open-bauth';

const notificationsSchema: TableSchema = {
  tableName: "notifications",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "user_id", type: "TEXT", notNull: true, references: { table: "users", column: "id" } },
    { name: "title", type: "TEXT", notNull: true },
    { name: "message", type: "TEXT" },
    { name: "type", type: "TEXT", defaultValue: "'info'" },
    { name: "read", type: "BIT", defaultValue: false },
    { name: "priority", type: "INTEGER", defaultValue: 0 },
    { name: "expires_at", type: "DATETIME" },
    { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" }
  ],
  indexes: [
    { name: "idx_notifications_user", columns: ["user_id"] },
    { name: "idx_notifications_read", columns: ["read"] },
    { name: "idx_notifications_expires", columns: ["expires_at"] }
  ]
};

const dbInitializer = new DatabaseInitializer({ 
  database: db, 
  externalSchemas: [notificationsSchema] 
});
```

### 3. Schema Registry

Manage multiple schema sets:

```typescript
import { SchemaRegistry } from 'open-bauth';

// Create schema registries
const userExtensions = new SchemaRegistry([
  userProfileSchema,
  userPreferencesSchema
]);

const contentSchemas = new SchemaRegistry([
  postsSchema,
  commentsSchema,
  categoriesSchema
]);

// Merge registries
const allSchemas = SchemaRegistry.merge(userExtensions, contentSchemas);

// Apply to database initializer
const dbInitializer = new DatabaseInitializer({
  database: db,
  externalSchemas: allSchemas.getAll()
});
```

## 🎨 Predefined Extensions

### UserProfile Extension

Adds profile fields to users table:

```typescript
import { SchemaExtensions } from 'open-bauth';

setDatabaseConfig({
  schemaExtensions: {
    users: SchemaExtensions.addUserProfileFields()
  }
});

// Adds columns:
// - phone_number: TEXT
// - avatar_url: TEXT
// - timezone: TEXT (default: 'UTC')
// - language: TEXT (default: 'en')
// - bio: TEXT
// - website: TEXT
// - birth_date: DATETIME
```

### Soft Delete Extension

Adds soft delete functionality:

```typescript
setDatabaseConfig({
  schemaExtensions: {
    users: SchemaExtensions.addSoftDelete(),
    posts: SchemaExtensions.addSoftDelete(),
    comments: SchemaExtensions.addSoftDelete()
  }
});

// Adds columns:
// - deleted_at: DATETIME
// - is_deleted: BOOLEAN (computed)
```

### Metadata Extension

Adds JSON metadata column:

```typescript
setDatabaseConfig({
  schemaExtensions: {
    users: SchemaExtensions.addMetadata(),
    roles: SchemaExtensions.addMetadata()
  }
});

// Adds column:
// - metadata: JSON (default: '{}')
```

### Audit Fields Extension

Adds audit trail fields:

```typescript
setDatabaseConfig({
  schemaExtensions: {
    posts: SchemaExtensions.addAuditFields(),
    comments: SchemaExtensions.addAuditFields()
  }
});

// Adds columns:
// - created_by: TEXT (references users.id)
// - updated_by: TEXT (references users.id)
```

### Status Field Extension

Replaces boolean is_active with status field:

```typescript
setDatabaseConfig({
  schemaExtensions: {
    users: SchemaExtensions.useStatusField()
  }
});

// Replaces is_active with:
// - status: TEXT (default: 'active')
// Options: 'active', 'inactive', 'suspended', 'pending'
```

## 🛠️ Custom Extensions

### Adding Custom Columns

```typescript
setDatabaseConfig({
  schemaExtensions: {
    users: {
      additionalColumns: [
        { name: "age", type: "INTEGER", check: "age >= 13" },
        { name: "gender", type: "TEXT", check: "gender IN ('male', 'female', 'other')" },
        { name: "salary", type: "REAL", check: "salary >= 0" },
        { name: "department_id", type: "TEXT", references: { table: "departments", column: "id" } }
      ],
      additionalIndexes: [
        { name: "idx_users_age", columns: ["age"] },
        { name: "idx_users_department", columns: ["department_id"] }
      ]
    }
  }
});
```

### Removing Default Columns

```typescript
setDatabaseConfig({
  schemaExtensions: {
    users: {
      removedColumns: ["is_active", "created_at"] // Remove default columns
    }
  }
});
```

### Modifying Existing Columns

```typescript
setDatabaseConfig({
  schemaExtensions: {
    users: {
      modifiedColumns: [
        { 
          name: "email", 
          type: "TEXT", 
          notNull: true, 
          unique: true,
          check: "email LIKE '%@%.%'" // Email validation
        },
        { 
          name: "password_hash", 
          type: "TEXT", 
          notNull: true 
        }
      ]
    }
  }
});
```

## 📋 External Schemas

### OAuth 2.0 Schema Extensions

Complete OAuth 2.0 implementation:

```typescript
import { registerOAuthSchemaExtensions, getOAuthSchemas } from 'open-bauth/src/database/oauth-schema-extensions';

// Register OAuth extensions
registerOAuthSchemaExtensions();

// Get all OAuth schemas
const oauthSchemas = getOAuthSchemas();

// Initialize with OAuth schemas
const dbInitializer = new DatabaseInitializer({
  database: db,
  externalSchemas: oauthSchemas
});

// Creates tables:
// - oauth_clients
// - authorization_codes
// - refresh_tokens
// - device_secrets
// - biometric_credentials
// - anonymous_users
// - user_devices
// - mfa_configurations
// - security_challenges
// - oauth_sessions
```

### Custom Business Logic Schemas

Application-specific tables:

```typescript
// E-commerce schemas
const productSchema: TableSchema = {
  tableName: "products",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "name", type: "TEXT", notNull: true },
    { name: "description", type: "TEXT" },
    { name: "price", type: "REAL", notNull: true, check: "price >= 0" },
    { name: "category_id", type: "TEXT", references: { table: "categories", column: "id" } },
    { name: "is_active", type: "BOOLEAN", defaultValue: true },
    { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" }
  ],
  indexes: [
    { name: "idx_products_category", columns: ["category_id"] },
    { name: "idx_products_active", columns: ["is_active"] },
    { name: "idx_products_price", columns: ["price"] }
  ]
};

const orderSchema: TableSchema = {
  tableName: "orders",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "user_id", type: "TEXT", notNull: true, references: { table: "users", column: "id" } },
    { name: "total", type: "REAL", notNull: true, check: "total >= 0" },
    { name: "status", type: "TEXT", defaultValue: "'pending'", check: "status IN ('pending', 'paid', 'shipped', 'delivered', 'cancelled')" },
    { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" }
  ],
  foreignKeys: [
    { name: "fk_orders_user_id", columns: ["user_id"], referencesTable: "users", referencesColumns: ["id"], onDelete: "RESTRICT" }
  ]
};

const dbInitializer = new DatabaseInitializer({
  database: db,
  externalSchemas: [productSchema, orderSchema]
});
```

## 🏭 DatabaseInitializer API

### Constructor Options

```typescript
interface DatabaseInitializerConfig {
  database: Database; // Database connection
  externalSchemas?: TableSchema[]; // Custom tables
  tableNames?: Record<string, string>; // Custom table names
  schemaExtensions?: Record<string, SchemaExtension>; // Core table extensions
  migrationOptions?: MigrationOptions; // Migration settings
}

const dbInitializer = new DatabaseInitializer({
  database: db,
  externalSchemas: [customSchema1, customSchema2],
  tableNames: {
    users: "app_users",
    roles: "user_roles"
  },
  schemaExtensions: {
    users: SchemaExtensions.addUserProfileFields()
  },
  migrationOptions: {
    autoMigrate: true,
    backupBeforeMigration: true
  }
});
```

### Initialization Methods

```typescript
// Initialize database with all schemas
const initResult = await dbInitializer.initialize();

// Result includes:
interface InitializationResult {
  success: boolean;
  tablesCreated: string[];
  tablesUpdated: string[];
  errors?: string[];
  migrationResults?: MigrationResult[];
}

// Check if already initialized
const isInitialized = await dbInitializer.isInitialized();

// Get schema information
const schemaInfo = await dbInitializer.getSchemaInfo();
```

### Controller Creation

```typescript
// Create controller for any table
const usersController = dbInitializer.createController("users");
const productsController = dbInitializer.createController("products");
const notificationsController = dbInitializer.createController("notifications");

// Controllers provide full CRUD API
const users = await usersController.findAll();
const product = await productsController.findById("product-id");
const notification = await notificationsController.create({ 
  user_id: "user-id", 
  title: "New notification" 
});
```

## 🔄 Migration Support

### Automatic Migrations

```typescript
const dbInitializer = new DatabaseInitializer({
  database: db,
  externalSchemas: [newSchema],
  migrationOptions: {
    autoMigrate: true,
    backupBeforeMigration: true,
    rollbackOnError: false
  }
});

// Migration result includes:
interface MigrationResult {
  success: boolean;
  migrationsApplied: string[];
  errors?: string[];
  rollbackSQL?: string;
}
```

### Manual Migration Control

```typescript
// Check pending migrations
const pendingMigrations = await dbInitializer.getPendingMigrations();

// Apply specific migration
const migrationResult = await dbInitializer.applyMigration("migration_name");

// Rollback migration
const rollbackResult = await dbInitializer.rollbackMigration("migration_name");

// Get migration history
const migrationHistory = await dbInitializer.getMigrationHistory();
```

### Custom Migration Scripts

```typescript
interface CustomMigration {
  name: string;
  version: string;
  description: string;
  up: (db: DatabaseConnection) => Promise<void>;
  down: (db: DatabaseConnection) => Promise<void>;
  dependencies?: string[];
}

const customMigration: CustomMigration = {
  name: "add_user_profiles",
  version: "1.0.0",
  description: "Add user profiles table",
  dependencies: ["create_users_table"],
  up: async (db) => {
    await db.execute(`
      CREATE TABLE user_profiles (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        user_id TEXT NOT NULL,
        bio TEXT,
        avatar_url TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
  },
  down: async (db) => {
    await db.execute("DROP TABLE user_profiles");
  }
};

await dbInitializer.registerMigration(customMigration);
```

## 🎯 Best Practices

### Schema Design

1. **Consistent Naming**: Use snake_case for table and column names
2. **Primary Keys**: Use TEXT with UUID generation for primary keys
3. **Foreign Keys**: Always define proper foreign key relationships
4. **Indexes**: Create appropriate indexes for query performance
5. **Constraints**: Use CHECK constraints for data validation
6. **Timestamps**: Always include created_at and updated_at columns

### Extension Management

1. **Version Control**: Track schema changes with version numbers
2. **Backward Compatibility**: Ensure new extensions don't break existing code
3. **Incremental Changes**: Make small, incremental schema changes
4. **Testing**: Test extensions in development before production
5. **Documentation**: Document all custom extensions and their purpose

### Performance Optimization

1. **Index Strategy**: Create indexes based on query patterns
2. **Column Types**: Use appropriate data types for storage efficiency
3. **Foreign Key Indexes**: Index foreign key columns for join performance
4. **Partial Indexes**: Use partial indexes for filtered queries
5. **Avoid Over-Indexing**: Don't create unnecessary indexes

### Security Considerations

1. **Data Validation**: Use CHECK constraints for data validation
2. **Access Control**: Consider access patterns in schema design
3. **Sensitive Data**: Use appropriate encryption for sensitive columns
4. **Audit Trail**: Include audit columns for important tables
5. **Soft Deletes**: Use soft deletes for data retention

### Migration Best Practices

1. **Backup First**: Always backup before migrations
2. **Test Migrations**: Test migrations in staging environment
3. **Rollback Plans**: Always have rollback strategies
4. **Zero Downtime**: Design migrations for zero downtime
5. **Monitor Performance**: Monitor migration performance and impact

## 🔍 Advanced Features

### BIT Type Support

Special handling for SQL Server BIT compatibility:

```typescript
const bitSchema: TableSchema = {
  tableName: "user_flags",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true },
    { name: "is_premium", type: "BIT", defaultValue: false },
    { name: "is_verified", type: "BIT", defaultValue: false },
    { name: "has_mfa", type: "BIT", defaultValue: false }
  ]
};

// Advanced filtering with BIT fields
const controller = dbInitializer.createController("user_flags");

// Find premium users
const premiumUsers = await controller.search({ 
  is_premium: { isTruthy: true } 
});

// Find users without MFA
const usersWithoutMFA = await controller.search({ 
  has_mfa: { isFalsy: true } 
});

// Mixed representations work
const results = await controller.search({
  is_premium: [true, 1, new Uint8Array([1]), Buffer.from([1])]
});
```

### JSON Column Support

For flexible metadata storage:

```typescript
const jsonSchema: TableSchema = {
  tableName: "flexible_data",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true },
    { name: "entity_id", type: "TEXT", notNull: true },
    { name: "entity_type", type: "TEXT", notNull: true },
    { name: "metadata", type: "JSON", defaultValue: "{}" },
    { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" }
  ]
};

// Query JSON fields
const controller = dbInitializer.createController("flexible_data");

// Query JSON properties (SQLite specific syntax)
const results = await controller.search({
  "metadata->>theme": "dark" // JSON path query
});
```

### Computed Columns

Virtual columns based on expressions:

```typescript
const computedSchema: TableSchema = {
  tableName: "users_with_computed",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true },
    { name: "email", type: "TEXT", notNull: true },
    { name: "full_name", type: "TEXT", computed: "first_name || ' ' || last_name" },
    { name: "is_active", type: "BOOLEAN", computed: "deleted_at IS NULL" },
    { name: "age", type: "INTEGER", computed: "(julianday('now') - julianday(birth_date)) / 365.25" }
  ]
};
```

---

**Relevant files**:
- [`src/database/database-initializer.ts`](src/database/database-initializer.ts:136) - Main initialization class
- [`src/database/base-controller.ts`](src/database/base-controller.ts) - Type definitions and base controller
- [`src/database/schema-builder.ts`](src/database/schema-builder.ts:339) - Dynamic schema builder
- [`src/database/oauth-schema-extensions.ts`](src/database/oauth-schema-extensions.ts:308) - OAuth 2.0 extensions