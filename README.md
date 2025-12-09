# Database ORM with Authentication and more

[![Bun](https://img.shields.io/badge/Bun-%23FFEB3A?style=for-the-badge&logo=bun&logoColor=white)](https://bun.sh/)
[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![JWT](https://img.shields.io/badge/JWT-black?style=for-the-badge&logo=json-web-tokens&logoColor=white)](https://jwt.io/)
[![OAuth 2.0](https://img.shields.io/badge/OAuth%202.0-5856D6?style=for-the-badge&logo=oauth&logoColor=white)](https://oauth.net/2/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

A comprehensive, framework-agnostic authentication and authorization library with complete OAuth 2.0 implementation. Built with TypeScript, Bun, and SQLite. It provides JWT-based auth, RBAC (roles and permissions), OAuth 2.0 flows, MFA support, biometric authentication, and advanced schema management.

- **Runtime**: Bun (Node.js compatible for most features)
- **Storage**: SQLite by default (via Bun), **extensible to other databases via adapter system**
- **Language**: TypeScript, with full type definitions
- **Features**: Schema extensions, BIT type support, advanced filtering, RBAC, JWT auth, **custom database adapters**, **OAuth 2.0**, **MFA**, **Biometric Authentication**

---

## ✨ Key Features

### 🔐 Core Authentication
- **JWT-based authentication** with secure token generation and validation
- **Role-Based Access Control (RBAC)** with flexible permissions system
- **Complete OAuth 2.0 implementation** with all standard flows
- **Multi-Factor Authentication (MFA)** support with various methods
- **Biometric Authentication** with secure credential storage

### 🗄️ Database & Schema Management
- **Advanced Schema Class** for flexible table definitions
- **Built-in Schema Builder** with standard authentication tables
- **OAuth 2.0 Schema Extensions** for complete implementation
- **Schema Extension System** for custom table modifications
- **Custom Database Adapters** for PostgreSQL, MySQL, and others
- **Cascade Delete Support** for defining relationships with automatic cleanup

### 🛡️ Security Features
- **PKCE support** (RFC 7636) for public clients
- **DPoP implementation** (RFC 9449) for token binding
- **Device secrets** for Single Sign-On (SSO)
- **Security challenges** for additional verification
- **Audit logging** for compliance and monitoring

### 🌐 Framework Integration
- **Refactored Core + Adapter Architecture** - Framework-agnostic core logic with framework-specific adapters
- **Framework adapters** for Hono, Bun, Express, Elysia, Fastify
- **Type-safe interfaces** for all framework integrations
- **Context injection** for request-scoped data
- **Error handling** with consistent responses

## Installation

Using Bun:

```bash
# Install as a dependency
bun add open-bauth

# Or clone this repository and work locally
git clone https://github.com/nglmercer/open-bauth.git
```

Build and test locally:

```bash
# Build
bun run build

# Test
bun test
```

---

## Quick Start

### 1) Initialize database and seed defaults (users/roles/permissions tables):

```typescript
import { Database } from 'bun:sqlite';
import { DatabaseInitializer } from 'open-bauth';

const db = new Database('auth.db');
const dbInitializer = new DatabaseInitializer({ database: db });
await dbInitializer.initialize();
await dbInitializer.seedDefaults();
```

### 2) Initialize services (JWT, Auth, Permissions):

```typescript
import { JWTService, AuthService, PermissionService } from 'open-bauth';

const jwtService = new JWTService(process.env.JWT_SECRET || 'dev-secret', '24h');
const authService = new AuthService(dbInitializer, jwtService);
const permissionService = new PermissionService(dbInitializer);
```

### 3) Register and login:

```typescript
const register = await authService.register({
  email: 'user@example.com',
  password: 'StrongP@ssw0rd',
  username: 'johndoe',
  first_name: 'John',
  last_name: 'Doe'
});

if (!register.success) throw new Error(register.error?.message);

const login = await authService.login({ 
  email: 'user@example.com', 
  password: 'StrongP@ssw0rd' 
});

if (!login.success) throw new Error(login.error?.message);
console.log('JWT:', login.token);
```

### 4) Extract schemas from an existing database:

```typescript
import { createSchemaExtractor, DatabaseInitializer } from 'open-bauth';

// Extract schemas from an existing database
const extractor = createSchemaExtractor("legacy.db");
const schemas = await extractor.extractAllSchemas();

// Use with DatabaseInitializer
const dbInitializer = new DatabaseInitializer({
  database: db,
  externalSchemas: schemas.map(s => s.tableSchema)
});

// Access generated Zod schemas
const userSchema = schemas.find(s => s.tableName === 'users')?.schema;
if (userSchema) {
  const validatedUser = userSchema.parse({ id: 1, email: "test@example.com" });
}
```

### 5) Use advanced schema extensions and BIT type support:

```typescript
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

### 6) Use framework-agnostic middleware with new Core + Adapter Architecture (example with Hono):

```typescript
import { Hono } from 'hono';
import {
  createHonoAuthMiddleware,
  createHonoPermissionMiddleware
} from 'open-bauth/src/middleware/adapters/hono.adapter';

const app = new Hono();

// Create framework-specific adapters that use core authentication logic
const authMiddleware = createHonoAuthMiddleware({
  jwtService,
  authService,
  permissionService
});

const editContentMiddleware = createHonoPermissionMiddleware({
  permissionService
}, ['edit:content']);

// Apply middleware to routes
app.use('/api/*', authMiddleware);
app.get('/protected', authMiddleware, (c) => {
  const auth = c.get('auth');
  return c.json({ success: true, user: auth.user });
});

app.get('/moderate', authMiddleware, editContentMiddleware, (c) => {
  return c.json({ success: true, message: 'Content moderation access' });
});
```

### Legacy middleware (still supported):
```typescript
import { createAuthMiddleware, createPermissionMiddleware } from 'open-bauth';

const authMw = createAuthMiddleware({ jwtService, authService, permissionService }, true);
const canEditContent = createPermissionMiddleware({ permissionService }, ['edit:content']);
```

---

## What's Exported from Library

This library's public API is re-exported from the entrypoint so you can import from a single place.

### Middleware (Core + Adapter Architecture)
#### Core Functions (Framework-Agnostic)
- [`authenticateRequest(request, services)`](docs/middleware.md#core-functions) - Core authentication logic
- [`authorizePermissions(request)`](docs/middleware.md#core-functions) - Core permission authorization
- [`authorizeRoles(request)`](docs/middleware.md#core-functions) - Core role authorization

#### Framework Adapters
- [`createHonoAuthMiddleware(services)`](docs/middleware.md#framework-adapters) - Hono-specific auth middleware
- [`createHonoPermissionMiddleware(services, permissions)`](docs/middleware.md#framework-adapters) - Hono permission middleware
- [`createHonoRoleMiddleware(services, roles)`](docs/middleware.md#framework-adapters) - Hono role middleware
- [`createBunAuthMiddleware(services)`](docs/middleware.md#framework-adapters) - Bun-specific auth middleware

#### Legacy Middleware (Still Supported)
- [`createAuthMiddleware(services, required?)`](docs/middleware.md#core-middleware) - Framework-agnostic auth middleware
- [`createPermissionMiddleware(services, requiredPermissions, options?)`](docs/middleware.md#core-middleware) - Permission middleware
- [`createRoleMiddleware(requiredRoles)`](docs/middleware.md#core-middleware) - Role middleware

### Services
- [`AuthService`](docs/services.md#authservice) - Registration, login, user management, role assignment
- [`JWTService, initJWTService(secret, expiresIn?), getJWTService()`](docs/services.md#jwtservice) - JWT generation/verification, DPoP, refresh rotation
- [`PermissionService`](docs/services.md#permissionservice) - RBAC - roles, permissions, checks
- [`OAuthService`](docs/services.md#oauthservice) - Full OAuth 2.0 flows, clients, tokens
- [`SecurityService`](docs/services.md#securityservice) - PKCE, DPoP, challenges, hashing
- [`EnhancedUserService`](docs/services.md#enhanceduserservice) - MFA, biometrics, devices

### Database
- [`BaseController`](docs/database-extension-spec.md#basecontroller) (generic CRUD + query helpers)
- [`DatabaseInitializer`](docs/database-extension-spec.md#databaseinitializer) (migrations, integrity checks, seeds, controllers)
- [`Schema Extensions`](docs/database-extension-spec.md#predefined-extensions) (addUserProfileFields, addSoftDelete, addMetadata, etc.)
- [`Schema Extractor`](docs/schema-extractor/schema-extractor.md) (automatic schema extraction from existing databases)

### Configuration
- [`setDatabaseConfig(), getDatabaseConfig()`](docs/database-extension-spec.md#global-configuration)
- [`SchemaExtensions`](docs/database-extension-spec.md#extension-functions) helper functions
- [`Custom table names`](docs/database-extension-spec.md#custom-table-names) support

### Database Adapters
- [`IDatabaseAdapter`](docs/adapter-usage.md#idatabaseadapter-interface) - Interface for custom database adapters
- [`JsonFileAdapter`](docs/adapter-usage.md#jsonfileadapter) - File-based JSON adapter
- [`MemoryAdapter`](docs/adapter-usage.md#memoryadapter) - In-memory adapter
- [`AdapterFactory`](docs/adapter-usage.md#adapter-factory) - Factory for creating adapters

### Logger
- [`Logger class, getLogger(), defaultLogger`](docs/logger.md#logger-class) - Complete logging system
- [`convenience log methods`](docs/logger.md#convenience-functions) - Quick logging functions
- [`configuration helpers`](docs/logger.md#configuration) - Setup and management helpers

### Types (from src/types/auth)
- [`User, Role, Permission`](docs/services.md#main-types) - Main entities
- [`RegisterData, LoginData, AuthResult`](docs/services.md#authresult) - Authentication types
- [`JWTPayload, OAuthClient, TokenResponse`](docs/services.md#oauth-types) - JWT and OAuth types
- [`AuthContext, AuthRequest`](docs/middleware.md#authentication-context) - Middleware context types

---

## Database Adapter System

The library now includes a flexible adapter system that allows you to use custom database implementations while maintaining the same API.

### Using Custom Adapters

```typescript
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

```typescript
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

**Documentation**: See [`docs/adapter-usage.md`](docs/adapter-usage.md) for complete adapter documentation and examples.

---

## Core Concepts and APIs

### Database Schema Management
Advanced schema system for defining and managing database tables:

```typescript
// Create custom schemas with the Schema class
const customSchema = new Schema({
  id: { type: String, primaryKey: true },
  name: { type: String, required: true },
  metadata: { type: Object, default: {} },
  is_active: { type: Boolean, default: true }
}, {
  indexes: [
    { name: "idx_custom_name", columns: ["name"] }
  ]
});

// Register OAuth 2.0 schema extensions
registerOAuthSchemaExtensions();

// Get built-in schemas
const usersSchema = getTableSchemaByKey('users');
const rolesSchema = getTableSchemaByKey('roles');

// Build all standard schemas
const allSchemas = buildDatabaseSchemas();
```

### OAuthService
Complete OAuth 2.0 implementation with all standard flows:

- `createClient(data: CreateOAuthClientData) -> OAuthClient`
- `handleAuthorizationRequest(request, user) -> AuthResponse`
- `handleTokenRequest(request) -> TokenResponse`
- `rotateRefreshToken(oldTokenId, newToken) -> RefreshToken`
- `revokeToken(tokenId) -> boolean`
- `introspectToken(token) -> TokenInfo`

### SecurityService
Advanced security features for modern authentication:

- `generatePKCEChallenge(method) -> PKCEChallenge`
- `generateDPoPProof(method, url, privateKey, jkt) -> DPoPProof`
- `createChallenge(type, data, ttl) -> SecurityChallenge`
- `verifyChallenge(challengeId, solution) -> ChallengeResult`
- `generateState() -> string`
- `generateNonce() -> string`

### AuthService
High-level auth flows: register, login, user lookup/update, role assignment, etc. Depends on the database layer and JWT service.

- `register(data: RegisterData) -> AuthResult`
- `login(data: LoginData) -> AuthResult`
- `findUserById(id, options?) -> User | null`
- `assignRole(userId, roleName) / removeRole(userId, roleName)`
- `getUsers(page?, limit?, options?) -> { users, total }`

### JWTService
Minimal, native Web Crypto–based JWT operations with DPoP support:

- `generateToken(user, options?) -> string`
- `verifyToken(token, options?) -> TokenPayload`
- `extractTokenFromHeader('Bearer ...') -> string`
- `getTokenRemainingTime(token) -> number`
- `isTokenExpired(token) -> boolean`
- `verifyDPoPProof(dpopHeader, method, url) -> DPoPResult`
- `refreshTokenIfNeeded(token, user, threshold?)`

### PermissionService
Queries and helpers for roles and permissions (e.g., getRolePermissions, user permission checks).

### DatabaseInitializer and BaseController
- `DatabaseInitializer` handles table creation/migrations, integrity checks, seeding defaults, and creating controllers for tables.
- `BaseController<T>` provides CRUD and query utilities (findFirst, search, count, random, etc.).

---

## Schema Extensions

The library includes a powerful schema extension system that allows you to customize database tables without modifying the core library.

### Basic Schema Extensions

```typescript
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

- **`addUserProfileFields()`**: Adds phone_number, avatar_url, timezone, language
- **`addSoftDelete()`**: Adds deleted_at and is_deleted fields
- **`addAuditFields()`**: Adds created_by and updated_by fields
- **`addMetadata()`**: Adds metadata field for storing JSON data
- **`useStatusField()`**: Replaces is_active with status field

### Custom Schema Extensions

```typescript
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

```typescript
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

```typescript
// All these are equivalent for BIT fields
create({ priority: true })
create({ priority: 1 })
create({ priority: new Uint8Array([1]) })
create({ priority: Buffer.from([1]) })
```

### Advanced Filters

Use advanced filters for complex boolean logic:

```typescript
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

```typescript
// All these representations work together
controller.search({
  read: [true, 1, new Uint8Array([1]), Buffer.from([1])]
})
```

### External Schemas

Add completely custom tables to your database:

```typescript
const customSchema = {
  tableName: "notifications",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true },
    { name: "user_id", type: "TEXT", notNull: true, references: { table: "users", column: "id" } },
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

```typescript
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

```typescript
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

```typescript
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

## Middleware (Refactored Core + Adapter Architecture)

### Core Functions (Framework-Agnostic)
- `authenticateRequest(request, { jwtService, authService, permissionService })`
  - Core authentication logic that verifies JWT and returns AuthContext
- `authorizePermissions(request, { userId, requiredPermissions, requireAll, dbInitializer })`
  - Core permission authorization logic
- `authorizeRoles(request, { userId, requiredRoles, requireAll, dbInitializer })`
  - Core role authorization logic

### Framework Adapters (New Architecture)
- `createHonoAuthMiddleware(services)` - Hono-specific auth middleware adapter
- `createHonoPermissionMiddleware(services, permissions, options?)` - Hono permission middleware adapter
- `createHonoRoleMiddleware(services, roles, options?)` - Hono role middleware adapter
- `createBunAuthMiddleware(services)` - Bun-specific auth middleware adapter

### Legacy Middleware (Still Supported)
- `createAuthMiddleware(services, required = true)`
  - Attaches auth context to request. When required is true, rejects if unauthenticated.
- `createPermissionMiddleware(services, permissions, { requireAll = false })`
  - Ensures user has at least one (or all) of required permissions.
- `createRoleMiddleware(requiredRoles)`
  - Ensures user has at least one required role.

---

## Logging

A simple yet flexible logger is included:
- `getLogger(), defaultLogger, convenience log.debug/info/warn/error/fatal`
- Configuration helpers via `createConfig` and `ENVIRONMENT_CONFIGS`

---

## Type Safety

The library ships with rich TypeScript types for requests, responses, entities, config, and utility types. Import what you need from package to get end-to-end type safety in your app.

---

## Complete Example

Here's a complete example using schema extensions and BIT type support:

```typescript
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

### 📖 Main Guides
- [**Services**](./docs/services.md) - Complete API of all services
- [**Middleware**](./docs/middleware.md) - Framework-agnostic middleware
- [**Database Adapters**](./docs/adapter-usage.md) - Custom database adapters
- [**Database Extensions**](./docs/database-extension-spec.md) - Schema extension specification

### 🔐 Security & Authentication
- [**OAuth 2.0 Implementation**](./docs/oauth-2.0-implementation.md) - Complete OAuth 2.0 guide
- [**Logger**](./docs/logger.md) - Logging system documentation
- [**Testing**](./docs/testing.md) - Running and writing tests

### 📋 Reference
- [**Docs Index**](./docs/README.md) - Complete documentation navigation
- [**Zod Usage**](./docs/zod-usage.md) - Zod integration and type mapping guide

---

## Library Info

You can inspect metadata at runtime:

---

## Testing and Development

The library includes comprehensive test coverage for all features including schema extensions and BIT type support.

### Running Tests

```bash
# Run all tests
bun test --preload tests/setup.ts

# Run tests with coverage
bun test --coverage --preload tests/setup.ts

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

See `examples/` and `docs/` directories for comprehensive usage examples:

- [`docs/usage-example.ts`](./docs/usage-example.ts) - Complete usage examples with all features
- [`docs/example-config.ts`](./docs/example-config.ts) - Configuration examples for different scenarios
- [`examples/integrations/`](./examples/integrations/) - Framework integration examples

### BIT Type Testing Examples

```typescript
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
