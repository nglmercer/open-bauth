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

### Schema Class

The `Schema` class is the core building block for defining database table structures with TypeScript type safety:

```typescript
import { Schema, SchemaDefinition, SchemaOptions } from "open-bauth/src/database/schema";

// Define a schema using TypeScript constructors
const userSchema = new Schema({
  id: { type: String, primaryKey: true, default: "(lower(hex(randomblob(16))))" },
  email: { type: String, required: true, unique: true },
  age: { type: Number, check: "age >= 0" },
  is_active: { type: Boolean, default: true },
  created_at: { type: Date, default: Date.now }
}, {
  indexes: [
    { name: "idx_users_email", columns: ["email"], unique: true },
    { name: "idx_users_active", columns: ["is_active"] }
  ]
});

// Convert to TableSchema for database initialization
const tableSchema = userSchema.toTableSchema("users");
```

#### Schema Types and Interfaces

```typescript
// Field definition types
interface SchemaTypeOptions {
  type: ConstructorType | ColumnType;
  required?: boolean;
  notNull?: boolean;
  unique?: boolean;
  primaryKey?: boolean;
  default?: any;
  ref?: string;
  references?: { table: string; column: string };
  check?: string;
}

// Schema definition
interface SchemaDefinition {
  [key: string]: SchemaField;
}

// Index definition
interface SchemaIndex {
  name: string;
  columns: string[];
  unique?: boolean;
}

// Schema options
interface SchemaOptions {
  indexes?: SchemaIndex[];
}
```

#### Advanced Schema Features

The Schema class provides several advanced features for complex table definitions:

```typescript
// Quick schema using only constructors
const quickSchema = new Schema({
  id: String,
  name: { type: String, required: true },
  metadata: Object,
  tags: Array,
  profile: {
    bio: String,
    avatar: String
  }
});

// Advanced schema with relationships and constraints
const advancedSchema = new Schema({
  user_id: { 
    type: String, 
    ref: "users" // Automatically creates references table: "users", column: "id"
  },
  status: { 
    type: String, 
    default: "active",
    check: "status IN ('active', 'inactive', 'pending')"
  },
  expires_at: { 
    type: Date, 
    notNull: true 
  },
  is_premium: { 
    type: Boolean, 
    default: false 
  }
});
```

#### Schema Class Methods

The Schema class provides several useful methods for schema manipulation:

```typescript
// Get columns as ColumnDefinition[]
const columns = userSchema.getColumns();

// Get the raw definition
const definition = userSchema.getDefinition();

// Get schema options
const options = userSchema.getOptions();

// Create a Schema from a TableSchema
const tableSchema = { /* ... */ };
const schemaInstance = Schema.fromTableSchema(tableSchema);

// Compare two schemas for equivalence
const isEqual = schema1.equals(schema2, "table_name");

// Static method to compare TableSchemas
const areSchemasEqual = Schema.compareTableSchemas(tableSchema1, tableSchema2);
```

#### Type Mapping

The Schema class automatically maps TypeScript types to SQL column types:

```typescript
// The following mappings are automatically applied:
// String → TEXT
// Number → INTEGER
// Boolean → BOOLEAN
// Date → DATETIME
// Object → TEXT (JSON)
// Array → TEXT (JSON)
// Buffer → BLOB

// You can also use direct SQL types:
const directTypeSchema = new Schema({
  id: { type: "INTEGER", primaryKey: true, autoIncrement: true },
  name: { type: "VARCHAR(100)", required: true },
  price: { type: "DECIMAL(10,2)", default: 0 }
});
```

#### Advanced Schema Features

```typescript
// Using constructor shortcuts
const quickSchema = new Schema({
  id: String, // Simple type definition
  name: { type: String, required: true },
  metadata: { /* object */ }, // Automatically becomes TEXT with "{}" default
  tags: [String], // Array becomes TEXT with "[]" default
  profile: {
    // Nested objects become TEXT with "{}" default
    bio: String,
    avatar: String
  }
});

// Complex field definitions
const advancedSchema = new Schema({
  user_id: { 
    type: String, 
    ref: "users" // Shortcut for references
  },
  status: { 
    type: String, 
    default: "active",
    check: "status IN ('active', 'inactive', 'suspended')"
  },
  expires_at: { 
    type: Date, 
    notNull: true 
  },
  is_premium: { 
    type: Boolean, 
    default: false 
  }
});
```

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

### 4. Schema Builder

Use the built-in schema builder for standard database schemas:

```typescript
import { buildDatabaseSchemas, getTableSchema, getTableSchemaByKey } from 'open-bauth/src/database/schema/schema-builder';

// Build all standard schemas
const allSchemas = buildDatabaseSchemas();

// Get a specific table schema by table name
const usersSchema = getTableSchema('users');

// Get a specific table schema by key (users, roles, permissions, etc.)
const rolesSchema = getTableSchemaByKey('roles');
```

#### Standard Base Schemas

The schema builder includes these base schemas:

```typescript
// Users table
{
  tableName: "users",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "email", type: "TEXT", required: true, unique: true },
    { name: "username", type: "TEXT" },
    { name: "password_hash", type: "TEXT", required: true },
    { name: "first_name", type: "TEXT" },
    { name: "last_name", type: "TEXT" },
    { name: "created_at", type: "DATETIME", defaultValue: Date.now },
    { name: "updated_at", type: "DATETIME", defaultValue: Date.now },
    { name: "last_login_at", type: "DATETIME" },
    { name: "is_active", type: "BOOLEAN", defaultValue: true }
  ],
  indexes: [
    { name: "idx_users_email", columns: ["email"], unique: true },
    { name: "idx_users_username", columns: ["username"], unique: true },
    { name: "idx_users_active", columns: ["is_active"] }
  ]
}

// Roles table
{
  tableName: "roles",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "name", type: "TEXT", required: true, unique: true },
    { name: "description", type: "TEXT" },
    { name: "created_at", type: "DATETIME", defaultValue: Date.now },
    { name: "updated_at", type: "DATETIME", defaultValue: Date.now },
    { name: "is_active", type: "BOOLEAN", defaultValue: true }
  ],
  indexes: [
    { name: "idx_roles_name", columns: ["name"], unique: true }
  ]
}

// Permissions table
{
  tableName: "permissions",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "name", type: "TEXT", required: true, unique: true },
    { name: "resource", type: "TEXT", required: true },
    { name: "action", type: "TEXT", required: true },
    { name: "description", type: "TEXT" },
    { name: "created_at", type: "DATETIME", defaultValue: Date.now }
  ],
  indexes: [
    { name: "idx_permissions_name", columns: ["name"], unique: true },
    { name: "idx_permissions_resource", columns: ["resource"] },
    { name: "idx_permissions_action", columns: ["action"] }
  ]
}

// User-roles junction table
{
  tableName: "user_roles",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "user_id", type: "TEXT", required: true },
    { name: "role_id", type: "TEXT", required: true },
    { name: "created_at", type: "DATETIME", defaultValue: Date.now },
    { name: "updated_at", type: "DATETIME", defaultValue: Date.now }
  ],
  indexes: [
    { name: "idx_user_roles_user_id", columns: ["user_id"] },
    { name: "idx_user_roles_role_id", columns: ["role_id"] },
    { name: "idx_user_roles_unique", columns: ["user_id", "role_id"], unique: true }
  ]
}

// Role-permissions junction table
{
  tableName: "role_permissions",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "role_id", type: "TEXT", required: true },
    { name: "permission_id", type: "TEXT", required: true },
    { name: "created_at", type: "DATETIME", defaultValue: Date.now },
    { name: "updated_at", type: "DATETIME", defaultValue: Date.now }
  ],
  indexes: [
    { name: "idx_role_permissions_role_id", columns: ["role_id"] },
    { name: "idx_role_permissions_permission_id", columns: ["permission_id"] },
    { name: "idx_role_permissions_unique", columns: ["role_id", "permission_id"], unique: true }
  ]
}

// Sessions table
{
  tableName: "sessions",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "user_id", type: "TEXT", required: true },
    { name: "token", type: "TEXT", required: true, unique: true },
    { name: "created_at", type: "DATETIME", defaultValue: Date.now },
    { name: "expires_at", type: "DATETIME", required: true },
    { name: "last_activity", type: "DATETIME", defaultValue: Date.now },
    { name: "ip_address", type: "TEXT" },
    { name: "user_agent", type: "TEXT" },
    { name: "is_active", type: "BOOLEAN", defaultValue: true }
  ],
  indexes: [
    { name: "idx_sessions_user_id", columns: ["user_id"] },
    { name: "idx_sessions_token", columns: ["token"], unique: true },
    { name: "idx_sessions_expires_at", columns: ["expires_at"] },
    { name: "idx_sessions_active", columns: ["is_active"] }
  ]
}
```

#### Schema Customization

Customize schemas with extensions and table name mapping:

```typescript
import { setDatabaseConfig } from 'open-bauth/src/database/config';

// Configure table names and extensions
setDatabaseConfig({
  tableNames: {
    users: "app_users",
    roles: "app_roles",
    permissions: "app_permissions",
    userRoles: "app_user_roles",
    rolePermissions: "app_role_permissions",
    sessions: "app_sessions"
  },
  schemaExtensions: {
    users: {
      additionalColumns: [
        { name: "profile_image", type: "TEXT" },
        { name: "phone_number", type: "TEXT" }
      ],
      additionalIndexes: [
        { name: "idx_app_users_phone", columns: ["phone_number"] }
      ]
    }
  }
});
```

#### Schema Extension Processing

The schema builder handles schema extensions automatically:

```typescript
// The schema builder processes:
// 1. Base schemas with standard fields
// 2. Applied schema extensions (add/remove/modify columns)
// 3. Updated table references based on custom table names
// 4. OAuth schema extensions if registered

// Example of how extensions are applied:
function applySchemaExtensions(baseSchema, extension) {
  let columns = [...baseSchema.columns];
  
  // Remove columns
  if (extension.removedColumns) {
    const toRemove = new Set(extension.removedColumns);
    columns = columns.filter(col => !toRemove.has(col.name));
  }
  
  // Modify columns
  if (extension.modifiedColumns) {
    const modifications = new Map(extension.modifiedColumns.map(c => [c.name, c]));
    columns = columns.map(col => modifications.get(col.name) || col);
  }
  
  // Add columns
  if (extension.additionalColumns) {
    columns.push(...extension.additionalColumns);
  }
  
  return { ...baseSchema, columns };
}
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

Complete OAuth 2.0 implementation with advanced security features:

```typescript
import { registerOAuthSchemaExtensions, getOAuthSchemas } from 'open-bauth/src/database/schema/oauth-schema-extensions';

// Register OAuth extensions
registerOAuthSchemaExtensions();

// Get all OAuth schemas
const oauthSchemas = getOAuthSchemas();

// Initialize with OAuth schemas
const dbInitializer = new DatabaseInitializer({
  database: db,
  externalSchemas: oauthSchemas
});
```

#### OAuth Clients Schema

```typescript
// oauth_clients table definition
{
  tableName: "oauth_clients",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "client_id", type: "TEXT", required: true, unique: true },
    { name: "client_secret", type: "TEXT" },
    { name: "client_secret_salt", type: "TEXT" },
    { name: "client_name", type: "TEXT", required: true },
    { name: "redirect_uris", type: "TEXT", required: true }, // JSON array
    { name: "grant_types", type: "TEXT", required: true },   // JSON array
    { name: "response_types", type: "TEXT", required: true },// JSON array
    { name: "scope", type: "TEXT", defaultValue: "" },
    { name: "logo_uri", type: "TEXT" },
    { name: "client_uri", type: "TEXT" },
    { name: "policy_uri", type: "TEXT" },
    { name: "tos_uri", type: "TEXT" },
    { name: "jwks_uri", type: "TEXT" },
    { name: "token_endpoint_auth_method", type: "TEXT", defaultValue: "client_secret_basic" },
    { name: "is_public", type: "BOOLEAN", defaultValue: false },
    { name: "is_active", type: "BOOLEAN", defaultValue: true },
    { name: "created_at", type: "DATETIME", defaultValue: Date.now },
    { name: "updated_at", type: "DATETIME", defaultValue: Date.now }
  ],
  indexes: [
    { name: "idx_oauth_clients_client_id", columns: ["client_id"], unique: true },
    { name: "idx_oauth_clients_active", columns: ["is_active"] }
  ]
}
```

#### Authorization Codes Schema

```typescript
// authorization_codes table definition
{
  tableName: "authorization_codes",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "code", type: "TEXT", required: true, unique: true },
    { name: "client_id", type: "TEXT", required: true },
    { name: "user_id", type: "TEXT", required: true },
    { name: "redirect_uri", type: "TEXT", required: true },
    { name: "scope", type: "TEXT", defaultValue: "" },
    { name: "state", type: "TEXT" },
    { name: "nonce", type: "TEXT" },
    { name: "code_challenge", type: "TEXT" },
    { name: "code_challenge_method", type: "TEXT" },
    { name: "expires_at", type: "DATETIME", required: true },
    { name: "is_used", type: "BOOLEAN", defaultValue: false },
    { name: "used_at", type: "DATETIME" },
    { name: "created_at", type: "DATETIME", defaultValue: Date.now }
  ],
  indexes: [
    { name: "idx_auth_codes_code", columns: ["code"], unique: true },
    { name: "idx_auth_codes_client_id", columns: ["client_id"] },
    { name: "idx_auth_codes_user_id", columns: ["user_id"] },
    { name: "idx_auth_codes_expires_at", columns: ["expires_at"] },
    { name: "idx_auth_codes_used", columns: ["is_used"] }
  ]
}
```

#### Refresh Tokens Schema

```typescript
// refresh_tokens table definition
{
  tableName: "refresh_tokens",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "token", type: "TEXT", required: true, unique: true },
    { name: "client_id", type: "TEXT", required: true },
    { name: "user_id", type: "TEXT", required: true },
    { name: "scope", type: "TEXT", defaultValue: "" },
    { name: "expires_at", type: "DATETIME", required: true },
    { name: "is_revoked", type: "BOOLEAN", defaultValue: false },
    { name: "revoked_at", type: "DATETIME" },
    { name: "rotation_count", type: "INTEGER", defaultValue: 0 },
    { name: "created_at", type: "DATETIME", defaultValue: Date.now }
  ],
  indexes: [
    { name: "idx_refresh_tokens_token", columns: ["token"], unique: true },
    { name: "idx_refresh_tokens_client_id", columns: ["client_id"] },
    { name: "idx_refresh_tokens_user_id", columns: ["user_id"] },
    { name: "idx_refresh_tokens_expires_at", columns: ["expires_at"] },
    { name: "idx_refresh_tokens_revoked", columns: ["is_revoked"] }
  ]
}
```

#### Device Secrets Schema

```typescript
// device_secrets table definition
{
  tableName: "device_secrets",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "user_id", type: "TEXT", required: true },
    { name: "device_id", type: "TEXT", required: true, unique: true },
    { name: "device_name", type: "TEXT", required: true },
    { name: "device_type", type: "TEXT", required: true },
    { name: "secret_hash", type: "TEXT", required: true },
    { name: "secret_salt", type: "TEXT" },
    { name: "is_trusted", type: "BOOLEAN", defaultValue: false },
    { name: "last_used_at", type: "DATETIME" },
    { name: "expires_at", type: "DATETIME" },
    { name: "created_at", type: "DATETIME", defaultValue: Date.now }
  ],
  indexes: [
    { name: "idx_device_secrets_user_id", columns: ["user_id"] },
    { name: "idx_device_secrets_device_id", columns: ["device_id"], unique: true },
    { name: "idx_device_secrets_trusted", columns: ["is_trusted"] },
    { name: "idx_device_secrets_expires_at", columns: ["expires_at"] }
  ]
}
```

#### Biometric Credentials Schema

```typescript
// biometric_credentials table definition
{
  tableName: "biometric_credentials",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "user_id", type: "TEXT", required: true },
    { name: "biometric_type", type: "TEXT", required: true },
    { name: "credential_data", type: "TEXT", required: true }, // Encrypted biometric data
    { name: "device_id", type: "TEXT" },
    { name: "is_active", type: "BOOLEAN", defaultValue: true },
    { name: "created_at", type: "DATETIME", defaultValue: Date.now },
    { name: "expires_at", type: "DATETIME" }
  ],
  indexes: [
    { name: "idx_biometric_creds_user_id", columns: ["user_id"] },
    { name: "idx_biometric_creds_type", columns: ["biometric_type"] },
    { name: "idx_biometric_creds_device_id", columns: ["device_id"] },
    { name: "idx_biometric_creds_active", columns: ["is_active"] },
    { name: "idx_biometric_creds_expires_at", columns: ["expires_at"] }
  ]
}
```

#### Anonymous Users Schema

```typescript
// anonymous_users table definition
{
  tableName: "anonymous_users",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "anonymous_id", type: "TEXT", required: true, unique: true },
    { name: "session_data", type: "TEXT", required: true }, // JSON
    { name: "created_at", type: "DATETIME", defaultValue: Date.now },
    { name: "promoted_to_user_id", type: "TEXT" },
    { name: "promoted_at", type: "DATETIME" },
    { name: "expires_at", type: "DATETIME", required: true }
  ],
  indexes: [
    { name: "idx_anon_users_anonymous_id", columns: ["anonymous_id"], unique: true },
    { name: "idx_anon_users_promoted_to", columns: ["promoted_to_user_id"] },
    { name: "idx_anon_users_expires_at", columns: ["expires_at"] }
  ]
}
```

#### User Devices Schema

```typescript
// user_devices table definition
{
  tableName: "user_devices",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "user_id", type: "TEXT", required: true },
    { name: "device_id", type: "TEXT", required: true, unique: true },
    { name: "device_name", type: "TEXT", required: true },
    { name: "device_type", type: "TEXT", required: true },
    { name: "platform", type: "TEXT" },
    { name: "user_agent", type: "TEXT" },
    { name: "is_trusted", type: "BOOLEAN", defaultValue: false },
    { name: "last_seen_at", type: "DATETIME" },
    { name: "created_at", type: "DATETIME", defaultValue: Date.now }
  ],
  indexes: [
    { name: "idx_user_devices_user_id", columns: ["user_id"] },
    { name: "idx_user_devices_device_id", columns: ["device_id"], unique: true },
    { name: "idx_user_devices_trusted", columns: ["is_trusted"] },
    { name: "idx_user_devices_last_seen", columns: ["last_seen_at"] }
  ]
}
```

#### MFA Configurations Schema

```typescript
// mfa_configurations table definition
{
  tableName: "mfa_configurations",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "user_id", type: "TEXT", required: true },
    { name: "mfa_type", type: "TEXT", required: true },
    { name: "is_enabled", type: "BOOLEAN", defaultValue: false },
    { name: "is_primary", type: "BOOLEAN", defaultValue: false },
    { name: "secret", type: "TEXT" },
    { name: "phone_number", type: "TEXT" },
    { name: "email", type: "TEXT" },
    { name: "backup_codes", type: "TEXT" }, // JSON array
    { name: "configuration_data", type: "TEXT" }, // JSON
    { name: "created_at", type: "DATETIME", defaultValue: Date.now },
    { name: "updated_at", type: "DATETIME", defaultValue: Date.now }
  ],
  indexes: [
    { name: "idx_mfa_configs_user_id", columns: ["user_id"] },
    { name: "idx_mfa_configs_type", columns: ["mfa_type"] },
    { name: "idx_mfa_configs_enabled", columns: ["is_enabled"] },
    { name: "idx_mfa_configs_primary", columns: ["is_primary"] }
  ]
}
```

#### Security Challenges Schema

```typescript
// security_challenges table definition
{
  tableName: "security_challenges",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "challenge_id", type: "TEXT", required: true, unique: true },
    { name: "challenge_type", type: "TEXT", required: true },
    { name: "challenge_data", type: "TEXT", required: true },
    { name: "expires_at", type: "DATETIME", required: true },
    { name: "is_solved", type: "BOOLEAN", defaultValue: false },
    { name: "solved_at", type: "DATETIME" },
    { name: "created_at", type: "DATETIME", defaultValue: Date.now }
  ],
  indexes: [
    { name: "idx_security_challenges_challenge_id", columns: ["challenge_id"], unique: true },
    { name: "idx_security_challenges_type", columns: ["challenge_type"] },
    { name: "idx_security_challenges_expires_at", columns: ["expires_at"] },
    { name: "idx_security_challenges_solved", columns: ["is_solved"] }
  ]
}
```

#### OAuth Sessions Schema

```typescript
// oauth_sessions table definition
{
  tableName: "oauth_sessions",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "session_id", type: "TEXT", required: true, unique: true },
    { name: "client_id", type: "TEXT", required: true },
    { name: "user_id", type: "TEXT" },
    { name: "auth_time", type: "DATETIME" },
    { name: "expires_at", type: "DATETIME", required: true },
    { name: "is_active", type: "BOOLEAN", defaultValue: true },
    { name: "session_data", type: "TEXT" }, // JSON
    { name: "created_at", type: "DATETIME", defaultValue: Date.now }
  ],
  indexes: [
    { name: "idx_oauth_sessions_session_id", columns: ["session_id"], unique: true },
    { name: "idx_oauth_sessions_client_id", columns: ["client_id"] },
    { name: "idx_oauth_sessions_user_id", columns: ["user_id"] },
    { name: "idx_oauth_sessions_expires_at", columns: ["expires_at"] },
    { name: "idx_oauth_sessions_active", columns: ["is_active"] }
  ]
}
```

#### Schema Integration

```typescript
// Complete OAuth schema registration
import { registerOAuthSchemaExtensions } from 'open-bauth/src/database/schema/oauth-schema-extensions';

// Register all OAuth schema extensions in the database config
registerOAuthSchemaExtensions();

// This creates the following tables:
// - oauth_clients: OAuth 2.0 client applications
// - authorization_codes: Authorization codes for PKCE flow
// - refresh_tokens: Refresh tokens with rotation support
// - device_secrets: Device secrets for SSO
// - biometric_credentials: Encrypted biometric credentials
// - anonymous_users: Anonymous user sessions with promotion
// - user_devices: User device registry
// - mfa_configurations: Multi-factor authentication configurations
// - security_challenges: Security challenges (CAPTCHA, etc.)
// - oauth_sessions: OAuth session management
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
- [`src/database/schema/schema-builder.ts`](src/database/schema/schema-builder.ts:339) - Dynamic schema builder
- [`src/database/schema/oauth-schema-extensions.ts`](src/database/schema/oauth-schema-extensions.ts:308) - OAuth 2.0 extensions
- [`src/database/schema/schema.ts`](src/database/schema/schema.ts:1) - Core Schema class and type definitions
