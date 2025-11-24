# Framework-Agnostic Authentication Library

[![Bun](https://img.shields.io/badge/Bun-%23FFEB3A?style=for-the-badge&logo=bun&logoColor=white)](https://bun.sh/)
[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![JWT](https://img.shields.io/badge/JWT-black?style=for-the-badge&logo=json-web-tokens&logoColor=white)](https://jwt.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
A comprehensive, framework-agnostic authentication and authorization library built with TypeScript, Bun, and SQLite. It provides JWT-based auth, RBAC (roles and permissions), framework-neutral middleware, and a flexible database layer.

- Runtime: Bun (Node.js compatible for most features)
- Storage: SQLite by default (via Bun), **extensible to other databases via adapter system**
- Language: TypeScript, with full type definitions
- Features: Schema extensions, BIT type support, advanced filtering, RBAC, JWT auth, **custom database adapters**

---

## Installation

Using Bun:

- Install as a dependency: `bun add open-bauth`
- Or clone this repository and work locally: `git clone https://github.com/nglmercer/open-bauth.git`

Build and test locally:

- Build: `bun run build`
- Test: `bun test`

---

## Quick Start

1) Initialize the database and seed defaults (users/roles/permissions tables):

```ts
import { Database } from 'bun:sqlite';
import { DatabaseInitializer } from 'open-bauth';

const db = new Database('auth.db');
const dbInitializer = new DatabaseInitializer({ database: db });
await dbInitializer.initialize();
await dbInitializer.seedDefaults();
```

2) Initialize services (JWT, Auth, Permissions):

```ts
import { JWTService, AuthService, PermissionService } from 'open-bauth';

const jwtService = new JWTService(process.env.JWT_SECRET || 'dev-secret', '24h');
const authService = new AuthService(dbInitializer, jwtService);
const permissionService = new PermissionService(dbInitializer);
```

3) Register and login:

```ts
const register = await authService.register({ email: 'user@example.com', password: 'StrongP@ssw0rd' });
if (!register.success) throw new Error(register.error?.message);

const login = await authService.login({ email: 'user@example.com', password: 'StrongP@ssw0rd' });
if (!login.success) throw new Error(login.error?.message);
console.log('JWT:', login.token);
```

4) Use advanced schema extensions and BIT type support:
```ts
import { setDatabaseConfig, SchemaExtensions } from 'open-bauth';

// Configure schema extensions
setDatabaseConfig({
  schemaExtensions: {
    users: SchemaExtensions.addUserProfileFields(), // Add phone, avatar, etc.
    roles: SchemaExtensions.addMetadata(), // Add metadata field
    sessions: SchemaExtensions.addSoftDelete(), // Add soft delete
  }
});

// Re-initialize with extensions
await dbInitializer.initialize();

// Use BIT type fields with advanced filtering
const notifications = dbInitializer.createController('notifications');
const activeNotifications = await notifications.search({
  read: { isTruthy: false }, // Find unread notifications
  priority: { isSet: true }, // Find notifications with priority set
});
```

5) Use framework-agnostic middleware (example with Hono):

```ts
import { Hono } from 'hono';
import { createAuthMiddleware, createPermissionMiddleware } from 'open-bauth';

const app = new Hono();

// Wire services into middleware
const authMw = createAuthMiddleware({ jwtService, authService, permissionService }, true);
const canEditContent = createPermissionMiddleware({ permissionService }, ['edit:content']);

app.use('*', async (c, next) => authMw(c, next));
app.get('/protected', async (c) => {
  if (!c.auth?.isAuthenticated) return c.json({ success: false }, 401);
  return c.json({ success: true, user: c.auth.user });
});
app.get('/moderate', async (c) => canEditContent(c));
```

---

## What’s Exported from the Library

This library’s public API is re-exported from the entrypoint so you can import from a single place.

- Middleware
  - authenticateRequest(request, services)
  - createAuthMiddleware(services, required?)
  - createPermissionMiddleware(services, requiredPermissions, options?)
  - createRoleMiddleware(requiredRoles)

- Services
  - AuthService
  - JWTService, initJWTService(secret, expiresIn?), getJWTService()
  - PermissionService

- Database
  - BaseController (generic CRUD + query helpers)
  - DatabaseInitializer (migrations, integrity checks, seeds, controllers)
  - Schema Extensions (addUserProfileFields, addSoftDelete, addMetadata, etc.)

- Configuration
  - setDatabaseConfig(), getDatabaseConfig()
  - SchemaExtensions helper functions
  - Custom table names support

- Logger
  - Logger class, getLogger(), defaultLogger, convenience log methods, configuration helpers

- Types (from src/types/auth)
  - User, Role, Permission, RegisterData, LoginData, UpdateUserData, AuthResult, AuthErrorType, AuthContext, AuthRequest, AuthResponse, PermissionOptions, AssignRoleData, JWTPayload, SessionInfo, and more


---

## Database Adapter System

The library now includes a flexible adapter system that allows you to use custom database implementations while maintaining the same API.

### Using Custom Adapters

```ts
import { BaseController } from 'open-bauth';
import { SimpleCustomAdapter } from './examples/custom-adapter-example';

// Create a custom adapter
const customAdapter = new SimpleCustomAdapter({
  connectionString: "custom://localhost"
});

// Use it with BaseController
const userController = new BaseController("users", {
  adapter: customAdapter
});

// All existing methods work the same
const users = await userController.findAll();
const user = await userController.findById(1);
```

### Creating Your Own Adapter

```ts
import { IDatabaseAdapter, DatabaseConnection } from 'open-bauth';

export class MyCustomAdapter implements IDatabaseAdapter {
  private connection: DatabaseConnection;
  
  constructor(config: any) {
    // Initialize your database connection
    this.connection = this.createConnection();
  }

  async initialize(): Promise<void> {
    // Initialize adapter
  }

  async close(): Promise<void> {
    // Close connection
  }

  isConnected(): boolean {
    return true; // Check connection status
  }

  getConnection(): DatabaseConnection {
    return this.connection;
  }

  getDatabaseType() {
    return {
      isSQLite: false,
      isSQLServer: false,
      isPostgreSQL: false,
      isMySQL: false
    };
  }

  getConfig() {
    return this.config;
  }

  getSqlHelpers() {
    return {
      mapDataType: (type: string) => type,
      formatDefaultValue: (value: any) => String(value),
      getRandomOrder: () => "ORDER BY RANDOM()",
      getPrimaryKeyQuery: (tableName: string) => `SELECT * FROM ${tableName} LIMIT 1`,
      getTableInfoQuery: (tableName: string) => `SELECT * FROM ${tableName} LIMIT 1`
    };
  }

  // Add your custom methods
  async getSimpleValue(): Promise<{ value: number; timestamp: string }> {
    return {
      value: 42,
      timestamp: new Date().toISOString()
    };
  }
}
```

**Documentation**: See `docs/adapter-usage.md` for complete adapter documentation and examples.

---

## Core Concepts and APIs

### AuthService
High-level auth flows: register, login, user lookup/update, role assignment, etc. Depends on the database layer and JWT service.

- register(data: RegisterData) -> AuthResult
- login(data: LoginData) -> AuthResult
- findUserById(id, options?) -> User | null
- assignRole(userId, roleName) / removeRole(userId, roleName)
- getUsers(page?, limit?, options?) -> { users, total }

### JWTService
Minimal, native Web Crypto–based JWT operations.

- generateToken(user)
- verifyToken(token)
- extractTokenFromHeader('Bearer ...')
- getTokenRemainingTime(token), isTokenExpired(token)
- refreshTokenIfNeeded(token, user, threshold?)

### PermissionService
Queries and helpers for roles and permissions (e.g., getRolePermissions, user permission checks).

### DatabaseInitializer and BaseController
- DatabaseInitializer handles table creation/migrations, integrity checks, seeding defaults, and creating controllers for tables.
- BaseController<T> provides CRUD and query utilities (findFirst, search, count, random, etc.).

---

## Schema Extensions

The library includes a powerful schema extension system that allows you to customize database tables without modifying the core library.

### Basic Schema Extensions

```ts
import { setDatabaseConfig, SchemaExtensions } from 'open-bauth';

// Add profile fields to users table
setDatabaseConfig({
  schemaExtensions: {
    users: SchemaExtensions.addUserProfileFields(), // Adds phone, avatar, timezone, language
    roles: SchemaExtensions.addMetadata(), // Adds metadata field for JSON data
    sessions: SchemaExtensions.addSoftDelete(), // Adds soft delete functionality
  }
});
```

### Available Schema Extensions

- **addUserProfileFields()**: Adds phone_number, avatar_url, timezone, language
- **addSoftDelete()**: Adds deleted_at and is_deleted fields
- **addAuditFields()**: Adds created_by and updated_by fields
- **addMetadata()**: Adds metadata field for storing JSON data
- **useStatusField()**: Replaces is_active with status field

### Custom Schema Extensions

```ts
setDatabaseConfig({
  schemaExtensions: {
    users: {
      additionalColumns: [
        { name: "age", type: "INTEGER" },
        { name: "bio", type: "TEXT" }
      ],
      removedColumns: ["is_active"], // Remove default column
      modifiedColumns: [
        { name: "email", type: "TEXT", notNull: true, unique: true }
      ]
    }
  }
});
```

### Custom Table Names

```ts
setDatabaseConfig({
  tableNames: {
    users: "app_users",
    roles: "user_roles",
    permissions: "app_permissions"
  }
});
```

---

## BIT Type Support and Advanced Filtering

The library supports BIT type fields for SQL Server compatibility and provides advanced filtering capabilities.

### BIT Type Handling

BIT fields automatically handle multiple boolean representations:

```ts
// All these are equivalent for BIT fields
create({ priority: true })
create({ priority: 1 })
create({ priority: new Uint8Array([1]) })
create({ priority: Buffer.from([1]) })
```

### Advanced Filters

Use advanced filters for complex boolean logic:

```ts
// Find records where field is truthy (equals 1 or true)
controller.search({ read: { isTruthy: true } })

// Find records where field is falsy (equals 0, false, or null)
controller.search({ priority: { isFalsy: true } })

// Find records where field is set (not null)
controller.search({ status: { isSet: true } })

// Find records where field is not set (null)
controller.search({ archived: { isSet: false } })
```

### Mixed Type Queries

Search with mixed boolean representations in IN queries:

```ts
// All these representations work together
controller.search({
  read: [true, 1, new Uint8Array([1]), Buffer.from([1])]
})
```

### External Schemas

Add completely custom tables to your database:

```ts
const customSchema = {
  tableName: "notifications",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true },
    { name: "user_id", type: "TEXT", notNull: true },
    { name: "title", type: "TEXT", notNull: true },
    { name: "read", type: "BIT", defaultValue: false },
    { name: "priority", type: "BIT" }
  ],
  indexes: [{ name: "idx_notifications_user", columns: ["user_id"] }]
};

const dbInitializer = new DatabaseInitializer({ 
  database: db, 
  externalSchemas: [customSchema] 
});
```

---

## Configuration Helpers

The library provides several helper functions for managing database configuration:

### Global Configuration
```ts
import { setDatabaseConfig, getDatabaseConfig, getAllTableNames } from 'open-bauth';

// Set global configuration
setDatabaseConfig({
  tableNames: { users: 'app_users' },
  schemaExtensions: { users: SchemaExtensions.addUserProfileFields() }
});

// Get current configuration
const config = getDatabaseConfig();

// Get all table names (including custom ones)
const tableNames = getAllTableNames();
```

### Common Columns
```ts
import { COMMON_COLUMNS } from 'open-bauth';

// Access predefined column definitions
const customExtension = {
  additionalColumns: [
    COMMON_COLUMNS.phoneNumber,
    COMMON_COLUMNS.avatarUrl,
    COMMON_COLUMNS.metadata
  ]
};
```

### Schema Registry
```ts
import { SchemaRegistry } from 'open-bauth';

// Create and manage schema registries
const registry1 = new SchemaRegistry([schema1, schema2]);
const registry2 = new SchemaRegistry([schema3, schema4]);

// Merge registries
const merged = SchemaRegistry.merge(registry1, registry2);

// Register additional schemas
registry1.registerMany([schema5, schema6]);
```

---

## Middleware (Framework-Agnostic)

- authenticateRequest(request, { jwtService, authService, permissionService })
  - Verifies JWT from Authorization header, loads user and permissions, returns an AuthContext.
- createAuthMiddleware(services, required = true)
  - Attaches auth context to request. When required is true, rejects if unauthenticated.
- createPermissionMiddleware(services, permissions, { requireAll = false })
  - Ensures the user has at least one (or all) of the required permissions.
- createRoleMiddleware(requiredRoles)
  - Ensures the user has at least one required role.

---

## Logging

A simple yet flexible logger is included:
- getLogger(), defaultLogger, convenience log.debug/info/warn/error/fatal
- Configuration helpers via createConfig and ENVIRONMENT_CONFIGS

---

## Type Safety

The library ships with rich TypeScript types for requests, responses, entities, config, and utility types. Import what you need from the package to get end-to-end type safety in your app.

---

## Complete Example

Here's a complete example using schema extensions and BIT type support:

```ts
import { Database } from 'bun:sqlite';
import { 
  DatabaseInitializer, 
  setDatabaseConfig, 
  SchemaExtensions,
  AuthService,
  JWTService,
  PermissionService 
} from 'open-bauth';

// 1. Configure schema extensions
setDatabaseConfig({
  schemaExtensions: {
    users: SchemaExtensions.addUserProfileFields(),
    roles: SchemaExtensions.addMetadata(),
    sessions: SchemaExtensions.addSoftDelete()
  }
});

// 2. Initialize database
const db = new Database('auth.db');
const dbInitializer = new DatabaseInitializer({ database: db });
await dbInitializer.initialize();
await dbInitializer.seedDefaults();

// 3. Add custom table with BIT fields
const notificationsSchema = {
  tableName: "notifications",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true },
    { name: "user_id", type: "TEXT", notNull: true },
    { name: "title", type: "TEXT", notNull: true },
    { name: "read", type: "BIT", defaultValue: false },
    { name: "priority", type: "BIT" }
  ]
};

const customInitializer = new DatabaseInitializer({ 
  database: db, 
  externalSchemas: [notificationsSchema] 
});
await customInitializer.initialize();

// 4. Initialize services
const jwtService = new JWTService('your-secret', '24h');
const authService = new AuthService(dbInitializer, jwtService);
const permissionService = new PermissionService(dbInitializer);

// 5. Use advanced filtering
const notifications = customInitializer.createController('notifications');
const unreadHighPriority = await notifications.search({
  read: { isFalsy: true },
  priority: { isTruthy: true }
});

console.log('Unread high priority notifications:', unreadHighPriority.data);
```

## 📚 Detailed Documentation

For in-depth guides and specifications, see the [docs/](./docs/) directory:

- [Adapter Usage](./docs/adapter-usage.md) - Custom database adapters
- [Database Extension Specification](./docs/database-extension-spec.md) - Extending schema
- [OAuth 2.0 Implementation](./docs/oauth-2.0-implementation.md) - Full OAuth 2.0 guide
- [Logger](./docs/logger.md) - Logging system
- [Services Overview](./docs/services.md) - Core services API
- [Middleware](./docs/middleware.md) - Framework-agnostic middleware
- [Testing](./docs/testing.md) - Running and writing tests
- [Deployment](./docs/deployment.md) - Production setup
- [Docs Index](./docs/README.md)

## Library Info

You can inspect metadata at runtime:

---

## Testing and Development

The library includes comprehensive test coverage for all features including schema extensions and BIT type support.

### Running Tests
```bash
# Run all tests
bun test

# Run tests with coverage
bun test --coverage

# Run specific test files
bun test tests/bit-data.test.ts
bun test tests/schema-extension.test.ts
```

### Test Features
- **Schema Extensions**: Tests all predefined extensions and custom schema modifications
- **BIT Type Support**: Tests boolean representations, IN queries, and advanced filtering
- **Database Integration**: Tests foreign key constraints, table relationships, and migrations
- **RBAC System**: Tests role-based access control, permissions, and user management
- **JWT Authentication**: Tests token generation, verification, and middleware integration

### Development Examples
See the `examples/` and `docs/` directories for comprehensive usage examples:

- `docs/usage-example.ts` - Complete usage examples with all features
- `docs/example-config.ts` - Configuration examples for different scenarios
- `examples/integrations/` - Framework integration examples

### BIT Type Testing Examples
```ts
// Test mixed boolean representations
const results = await controller.search({
  read: [true, false, 1, 0, new Uint8Array([1]), Buffer.from([0])]
});

// Test advanced filters
const truthy = await controller.search({ priority: { isTruthy: true } });
const falsy = await controller.search({ priority: { isFalsy: true } });
const isSet = await controller.search({ priority: { isSet: true } });
```

---

## License

MIT
