# Middleware System Documentation

## Overview

This middleware system provides a **framework-agnostic core** with **adapters** for different web frameworks. The design separates authentication/authorization logic from framework-specific implementations, making it easy to use the same security logic across different server frameworks.

## Architecture

```
src/middleware/
├── core/                      # Framework-agnostic logic
│   ├── types.ts              # Core interfaces and types
│   └── auth.core.ts          # Authentication & authorization logic
├── adapters/                  # Framework-specific implementations
│   ├── hono.adapter.ts       # Hono framework adapter
│   └── bun.adapter.ts        # Bun native HTTP adapter
└── index.ts                  # Barrel exports
```

## Features

✅ **Framework Agnostic Core** - Business logic independent of web framework  
✅ **Type-Safe** - Full TypeScript support with proper types  
✅ **Multiple Adapters** - Support for Hono and Bun HTTP out of the box  
✅ **Composable** - Chain multiple middleware together  
✅ **Tested** - Comprehensive test coverage (41 tests passing)  
✅ **Flexible Authorization** - Support for both role-based and permission-based access control

## Core Functions

### `authenticateRequest(request, services, required)`

Validates JWT token and constructs authentication context with user, roles, and permissions.

**Parameters:**
- `request: AuthRequest` - Framework-agnostic request object
- `services: AuthServices` - JWT, Auth, and Permission services
- `required: boolean` - Whether authentication is required (default: true)

**Returns:** `AuthResult` with success status and auth context

### `authorizePermissions(authContext, permissions, options)`

Checks if authenticated user has required permissions.

**Parameters:**
- `authContext: AuthContext` - Current auth context
- `permissions: string[]` - Required permissions
- `options: PermissionOptions` - Configure `requireAll` behavior

**Returns:** `AuthorizationResult` with allowed status

### `authorizeRoles(authContext, roles)`

Checks if authenticated user has at least one of the required roles.

**Parameters:**
- `authContext: AuthContext` - Current auth context
- `roles: string[]` - Required roles (user needs at least one)

**Returns:** `AuthorizationResult` with allowed status

---

## Adapters

### Hono Adapter

#### Basic Usage

```typescript
import { Hono } from "hono";
import { createHonoMiddleware } from "./middleware/adapters/hono.adapter";

const app = new Hono();
const middleware = createHonoMiddleware(services);

// Require authentication
app.get("/protected", middleware.requireAuth(), (c) => {
  const user = c.get("auth")?.user;
  return c.json({ message: `Hello ${user?.email}` });
});

// Optional authentication
app.get("/public", middleware.optionalAuth(), (c) => {
  const auth = c.get("auth");
  return c.json({ 
    isAuthenticated: auth?.isAuthenticated || false 
  });
});

// Require specific role
app.get(
  "/admin",
  middleware.requireAuth(),
  middleware.requireRole(["admin"]),
  (c) => c.json({ message: "Admin area" })
);

// Require specific permission
app.get(
  "/edit",
  middleware.requireAuth(),
  middleware.requirePermission(["content:edit"]),
  (c) => c.json({ message: "Edit content" })
);

// Chain multiple checks
app.delete(
  "/users/:id",
  middleware.requireAuth(),
  middleware.requireRole(["admin"]),
  middleware.requirePermission(["users:delete"]),
  (c) => c.json({ message: "User deleted" })
);
```

#### Legacy Compatibility Functions

For backward compatibility with existing code:

```typescript
import {
  createAuthMiddlewareForHono,
  createPermissionMiddlewareForHono,
  createRoleMiddlewareForHono,
} from "./middleware/adapters/hono.adapter";

// Required auth
app.use("/api/*", createAuthMiddlewareForHono(services, true));

// Optional auth
app.use("/public/*", createAuthMiddlewareForHono(services, false));

// Permission check (standalone)
app.use("/admin/*", createPermissionMiddlewareForHono(["admin:access"]));

// Role check (standalone)
app.use("/moderator/*", createRoleMiddlewareForHono(["moderator"]));
```

---

### Bun HTTP Adapter

#### Basic Usage

```typescript
import { createBunMiddleware, createBunServer } from "./middleware/adapters/bun.adapter";

const middleware = createBunMiddleware(services);

// Manual middleware composition
const handler = async (req: BunAuthRequest) => {
  return new Response(
    JSON.stringify({ 
      message: "Hello", 
      user: req.auth?.user?.email 
    }),
    { headers: { "Content-Type": "application/json" } }
  );
};

const protectedHandler = async (req: BunAuthRequest) => {
  return await middleware.requireAuth()(req, handler);
};

Bun.serve({
  port: 3000,
  fetch: protectedHandler,
});
```

#### Using `createBunServer` Helper

```typescript
import { createBunMiddleware, createBunServer } from "./middleware/adapters/bun.adapter";

const middleware = createBunMiddleware(services);

const handler = async (req: BunAuthRequest) => {
  return new Response(
    JSON.stringify({ 
      message: "Hello", 
      user: req.auth?.user?.email 
    }),
    { headers: { "Content-Type": "application/json" } }
  );
};

// Create server with middleware
const server = createBunServer(handler);
server.use(middleware.requireAuth());

// Start server
server.serve({ port: 3000 });
```

#### Composing Multiple Middleware

```typescript
import { 
  createBunMiddleware, 
  composeBunMiddleware 
} from "./middleware/adapters/bun.adapter";

const middleware = createBunMiddleware(services);

const handler = async (req: BunAuthRequest) => {
  return new Response(
    JSON.stringify({ message: "Admin area" }),
    { headers: { "Content-Type": "application/json" } }
  );
};

// Compose auth + role + permission checks
const secureHandler = composeBunMiddleware(
  middleware.requireAuth(),
  middleware.requireRole(["admin"]),
  middleware.requirePermission(["admin:access"])
);

Bun.serve({
  port: 3000,
  fetch: (req) => secureHandler(req as BunAuthRequest, handler),
});
```

---

## Service Initialization

All adapters require the same service dependencies:

```typescript
import { JWTService } from "./services/jwt";
import { AuthService } from "./services/auth";
import { PermissionService } from "./services/permissions";
import { DatabaseInitializer } from "./database/database-initializer";

// Initialize database
const db = new Database("./auth.db");
const dbInitializer = new DatabaseInitializer({ database: db });
await dbInitializer.initialize();
await dbInitializer.seedDefaults();

// Initialize services
const jwtService = new JWTService(process.env.JWT_SECRET || "secret");
const authService = new AuthService(dbInitializer, jwtService);
const permissionService = new PermissionService(dbInitializer);

// Create services object for adapters
const services = {
  jwtService,
  authService,
  permissionService,
};
```

---

## Permission Options

When checking permissions, you can specify whether all or any permissions are required:

```typescript
// User must have ALL listed permissions
middleware.requirePermission(
  ["users:read", "users:write"],
  { requireAll: true }
);

// User must have AT LEAST ONE listed permission (default)
middleware.requirePermission(
  ["users:read", "users:write"],
  { requireAll: false }
);
```

---

## Auth Context

After successful authentication, the auth context is available:

**Hono:**
```typescript
const auth = c.get("auth");
console.log(auth.user);          // User object
console.log(auth.token);         // JWT token
console.log(auth.permissions);   // Array of permission names
console.log(auth.isAuthenticated); // boolean
```

**Bun HTTP:**
```typescript
const auth = req.auth;
console.log(auth.user);          // User object
console.log(auth.token);         // JWT token
console.log(auth.permissions);   // Array of permission names
console.log(auth.isAuthenticated); // boolean
```

---

## Creating Custom Adapters

To create an adapter for a different framework, implement the `MiddlewareAdapter` interface:

```typescript
import type { MiddlewareAdapter } from "./core/types";

class MyFrameworkAdapter implements MiddlewareAdapter<MyContext, MyNext, MyResponse> {
  requireAuth(options?: AuthOptions) {
    return async (ctx: MyContext, next: MyNext) => {
      // Extract request
      const request = this.extractAuthRequest(ctx);
      
      // Authenticate using core function
      const result = await authenticateRequest(request, this.services, true);
      
      // Handle result
      if (result.success && result.context) {
        this.setAuthContext(ctx, result.context);
        return next();
      }
      
      // Return error response
      return this.errorResponse(ctx, result.error, result.statusCode);
    };
  }
  
  // Implement other methods...
}
```

---

## Testing

All tests use the same pattern with `beforeAll` and `seedDefaults()`:

```typescript
import { describe, test, expect, beforeAll, afterAll } from "bun:test";

describe("My Middleware Tests", () => {
  let db: Database;
  let dbInitializer: DatabaseInitializer;
  let services: AuthServices;

  beforeAll(async () => {
    db = new Database(":memory:");
    dbInitializer = new DatabaseInitializer({ database: db });
    await dbInitializer.initialize();
    await dbInitializer.seedDefaults(); // Seeds default roles and permissions
    
    // Initialize services...
    services = { jwtService, authService, permissionService };
  });

  afterAll(() => {
    db.close();
  });

  test("should authenticate valid request", async () => {
    // Your test...
  });
});
```

### Test Coverage

- ✅ Core authentication (7 tests)
- ✅ Permission-based authorization (6 tests)
- ✅ Role-based authorization (5 tests)
- ✅ Hono adapter (11 tests)
- ✅ Bun adapter (12 tests)

**Total: 41 passing tests**

---

## Error Handling

All middleware returns standardized error responses:

**401 Unauthorized:**
- Missing authorization header
- Invalid or expired token
- User not found or inactive
- Malformed Bearer token

**403 Forbidden:**
- Insufficient permissions
- Required role not found

---

## Best Practices

1. **Always chain `requireAuth()` first** when using role/permission checks
2. **Use `optionalAuth()` for public endpoints** that can benefit from auth context
3. **Prefer permission-based** authorization over role-based for fine-grained control
4. **Use `requireAll: true`** when multiple permissions must all be present
5. **Initialize database with `seedDefaults()`** to get default roles and permissions
6. **Close database connections** in `afterAll()` hooks in tests

---

## Future Enhancements

Potential additions to the middleware system:

- [ ] Rate limiting middleware
- [ ] Request logging middleware
- [ ] CORS middleware
- [ ] Express.js adapter
- [ ] Fastify adapter
- [ ] Elysia adapter
- [ ] Caching layer for permission lookups
- [ ] Webhook signature validation middleware

---

## License

Part of the open-bauth project.
