# Middleware Documentation

Comprehensive middleware system for authentication, authorization, and security that works across different web frameworks. The system has been **refactored** to separate core logic from framework-specific implementations.

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Core Middleware](#core-middleware)
- [Framework Adapters](#framework-adapters)
- [OAuth Security Middleware](#oauth-security-middleware)
- [Framework Integration](#framework-integration)
- [Security Features](#security-features)
- [Usage Examples](#usage-examples)
- [Best Practices](#best-practices)

## 🌟 Overview

The middleware system provides **framework-agnostic core logic** with **adapter-based framework integration**. This design allows the same authentication and authorization logic to work across different web frameworks while maintaining consistent behavior and security features.

### Key Benefits

- **Framework Agnostic Core**: Business logic independent of web framework
- **Adapter Pattern**: Framework-specific implementations separate from core logic
- **Type Safe**: Full TypeScript support with proper typing
- **Extensible**: Easy to add new framework adapters
- **Tested**: Comprehensive test coverage (41 tests passing)
- **Security First**: Built-in OAuth 2.0, JWT, DPoP, and rate limiting

## 🏗️ Architecture

### Core + Adapter Pattern

The middleware system follows a **core + adapter** architecture:

```
┌─────────────────────────────────────────────────────┐
│                    Request Flow                      │
└─────────────────────┬───────────────────────────┘
                      │ Framework Adapters
┌─────────────────────▼───────────────────────────┐
│  Hono Adapter │ Bun Adapter │ Express Adapter   │
│  (src/middleware/adapters/)                     │
└─────────────────────┬───────────────────────────┘
                      │ Core Middleware Functions
┌─────────────────────▼───────────────────────────┐
│  authenticateRequest() │ authorizePermissions() │
│  authorizeRoles()      │ OAuth Security         │
│  (src/middleware/core/)                         │
└─────────────────────┬───────────────────────────┘
                      │ Service Layer
┌─────────────────────▼───────────────────────────┐
│  AuthService │ JWTService │ PermissionService │ OAuthService │
│  (src/services/)                                │
└─────────────────────────────────────────────────────┘
```

### Key Components

1. **Core Functions** (`src/middleware/core/`): Framework-agnostic business logic
2. **Adapters** (`src/middleware/adapters/`): Framework-specific implementations
3. **Services** (`src/services/`): Business logic and data access
4. **Types** (`src/middleware/core/types.ts`): Shared type definitions

## 🔐 Core Middleware

### [`authenticateRequest(request, services)`](src/middleware/auth.ts:34)

Core authentication function that can be used directly or wrapped in framework-specific middleware.

**Parameters**:
- `request`: HTTP request object
- `services`: Service container with auth, JWT, and permission services

**Returns**: `Promise<AuthContext>`

**Usage Example**:
```typescript
import { authenticateRequest } from 'open-bauth/src/middleware/auth';

const authContext = await authenticateRequest(request, {
  jwtService,
  authService,
  permissionService
});

if (!authContext.isAuthenticated) {
  return { error: 'Unauthorized' };
}

return { user: authContext.user };
```

### [`createAuthMiddleware(services, required = true)`](src/middleware/auth.ts:88)

Creates authentication middleware that can be used with any framework.

**Parameters**:
- `services`: Service container
- `required`: Whether authentication is required (default: true)

**Returns**: Framework middleware function

**Usage Example**:
```typescript
import { createAuthMiddleware } from 'open-bauth/src/middleware/auth';

const authMiddleware = createAuthMiddleware({
  jwtService,
  authService,
  permissionService
}, true); // Required authentication

// Use in framework
app.use('/protected/*', authMiddleware);
```

### [`createPermissionMiddleware(services, permissions, { requireAll = false })`](src/middleware/auth.ts:122)

Creates authorization middleware for checking user permissions.

**Parameters**:
- `services`: Service container
- `permissions`: Array of required permissions
- `options`: Configuration object with `requireAll` flag

**Returns**: Framework middleware function

**Usage Example**:
```typescript
import { createPermissionMiddleware } from 'open-bauth/src/middleware/auth';

// Require at least one permission
const canEditContent = createPermissionMiddleware({
  permissionService
}, ['edit:content', 'moderate:content']);

// Require all permissions
const canDeleteContent = createPermissionMiddleware({
  permissionService
}, ['delete:content', 'admin:content'], { requireAll: true });
```

### [`createRoleMiddleware(roles)`](src/middleware/auth.ts:159)

Creates authorization middleware for checking user roles.

**Parameters**:
- `roles`: Array of required role names

**Returns**: Framework middleware function

**Usage Example**:
```typescript
import { createRoleMiddleware } from 'open-bauth/src/middleware/auth';

const requireAdmin = createRoleMiddleware(['admin']);
const requireModerator = createRoleMiddleware(['admin', 'moderator']);
```

## 🔌 Framework Adapters

Framework adapters provide **framework-specific implementations** that wrap the core middleware functions. Each adapter handles the unique request/response patterns of its target framework.

### Available Adapters

#### Hono Adapter (`src/middleware/adapters/hono.adapter.ts`)

```typescript
import { createHonoAuthMiddleware } from './middleware/adapters/hono.adapter';

// Create Hono-specific auth middleware
const honoAuthMiddleware = createHonoAuthMiddleware({
  jwtService,
  authService,
  permissionService
});

// Use in Hono app
app.use('/api/*', honoAuthMiddleware);

// With permissions
const requireAdmin = createHonoPermissionMiddleware({
  permissionService
}, ['admin:*']);

app.delete('/users/:id', honoAuthMiddleware, requireAdmin, (c) => {
  // User is authenticated and has admin permissions
  return c.json({ success: true });
});
```

#### Bun Adapter (`src/middleware/adapters/bun.adapter.ts`)

```typescript
import { createBunAuthMiddleware } from './middleware/adapters/bun.adapter';

// Create Bun-specific auth middleware
const bunAuthMiddleware = createBunAuthMiddleware({
  jwtService,
  authService,
  permissionService
});

// Use in Bun.serve
const server = Bun.serve({
  port: 3000,
  fetch: async (req) => {
    // Apply auth middleware
    const authResult = await bunAuthMiddleware(req);
    if (!authResult.success) {
      return new Response('Unauthorized', { status: 401 });
    }
    
    // Handle authenticated requests
    return new Response('Hello authenticated user!');
  }
});
```

### Creating Custom Adapters

To create a new framework adapter, follow this pattern:

```typescript
import { authenticateRequest, authorizePermissions, authorizeRoles } from '../core/auth.core';
import type { AuthRequest, PermissionRequest, RoleRequest } from '../core/types';

export function createCustomAuthMiddleware(services: ServiceContainer) {
  return async (request: CustomRequest, response: CustomResponse, next: NextFunction) => {
    try {
      // Extract token from custom request format
      const token = extractTokenFromCustomRequest(request);
      
      // Use core authentication function
      const authResult = await authenticateRequest({
        token,
        jwtSecret: services.jwtService.getSecret(),
        dbInitializer: services.dbInitializer
      });
      
      if (!authResult.success) {
        return handleCustomUnauthorized(response, authResult.error);
      }
      
      // Attach auth context to custom request format
      request.auth = authResult;
      await next();
    } catch (error) {
      return handleCustomError(response, error);
    }
  };
}
```

### Adapter Pattern Benefits

1. **Separation of Concerns**: Core logic separate from framework specifics
2. **Testability**: Core functions can be tested independently
3. **Reusability**: Same core logic across multiple frameworks
4. **Consistency**: Identical behavior across different frameworks
5. **Maintainability**: Framework changes don't affect core logic

## 🛡️ OAuth Security Middleware

### [`OAuthSecurityMiddleware`](src/middleware/oauth-security.ts:22)

Advanced OAuth 2.0 security middleware with comprehensive protection features.

#### Core Security Methods

##### [`validateAuthorizationRequest(req, client)`](src/middleware/oauth-security.ts:40)
Validates OAuth 2.0 authorization request parameters.

**Validates**:
- `response_type`: Supported OAuth 2.0 response types
- `client_id`: Valid client identifier
- `redirect_uri`: Authorized redirect URI
- `scope`: Requested scope format
- `state`: CSRF protection state parameter
- `code_challenge`: PKCE challenge (if required)
- `nonce`: Replay protection nonce

##### [`validateTokenRequest(req, client)`](src/middleware/oauth-security.ts:156)
Validates OAuth 2.0 token request parameters.

**Validates**:
- `grant_type`: Supported grant types
- `code`: Authorization code format and validity
- `redirect_uri`: Match with client configuration
- `code_verifier`: PKCE verification (if used)
- `client_secret`: Client authentication

##### [`verifyState(state, stored)`](src/middleware/oauth-security.ts:259)
Verifies OAuth 2.0 state parameter for CSRF protection.

**Features**:
- Cryptographic state generation
- Secure comparison with timing attack protection
- Automatic state cleanup
- Configurable state expiration

##### [`verifyNonce(nonce, usedNonces)`](src/middleware/oauth-security.ts:290)
Verifies OAuth 2.0 nonce parameter for replay protection.

**Features**:
- Cryptographically secure nonce generation
- Used nonce tracking with automatic cleanup
- Configurable nonce expiration
- Memory-efficient storage

##### [`verifyDPoP(req, token)`](src/middleware/oauth-security.ts:325)
Verifies DPoP (Demonstrating Proof of Possession) according to RFC 9449.

**Validates**:
- DPoP header format and structure
- Token binding verification
- HTTP method matching
- URI matching
- Proof freshness
- JWK thumbprint validation

##### [`createChallenge(type, data)`](src/middleware/oauth-security.ts:386)
Creates security challenges for additional verification.

**Challenge Types**:
- CAPTCHA: Visual or audio challenges
- TOTP: Time-based one-time passwords
- Email: Email verification codes
- SMS: SMS verification codes
- Custom: Application-specific challenges

##### [`verifyChallenge(id, solution)`](src/middleware/oauth-security.ts:424)
Verifies security challenge solutions.

**Features**:
- Rate limiting for challenge attempts
- Automatic challenge expiration
- Secure solution verification
- Attempt tracking and blocking

#### Advanced Security Features

##### [`detectSuspiciousActivity(userId, ip, agent)`](src/middleware/oauth-security.ts:494)
Detects patterns of suspicious activity.

**Detection Patterns**:
- Unusual login times or locations
- Multiple failed attempts
- Suspicious user agents
- Rapid password changes
- Concurrent sessions from different IPs

##### [`checkRateLimit(clientId?, userId?, ip)`](src/middleware/oauth-security.ts:560)
Applies rate limiting based on client, user, or IP.

**Rate Limiting Features**:
- Configurable limits per identifier type
- Sliding window or fixed window counting
- Progressive penalty for violations
- Automatic blocking for excessive violations

##### [`logSecurityEvent(event, details)`](src/middleware/oauth-security.ts:465)
Logs security events for audit trail.

**Event Types**:
- Authentication attempts (success/failure)
- Authorization requests
- Token operations
- Security violations
- Suspicious activities

### [`createOAuthSecurityMiddleware(oauthService, securityService, jwtService)`](src/middleware/oauth-security.ts:595)

Factory function to create OAuth security middleware with all services.

**Returns**: Complete OAuth security middleware instance

**Usage Example**:
```typescript
import { createOAuthSecurityMiddleware } from 'open-bauth/src/middleware/oauth-security';

const oauthSecurity = createOAuthSecurityMiddleware(
  oauthService,
  securityService,
  jwtService
);

// Use with framework
app.use('/oauth/*', oauthSecurity);
```

## 🔧 Framework Integration

### Modern Adapter-Based Integration

The refactored middleware system uses **framework adapters** that provide a cleaner, more idiomatic integration for each framework.

### Hono Integration

```typescript
import { Hono } from 'hono';
import { createHonoAuthMiddleware, createHonoPermissionMiddleware } from 'open-bauth/src/middleware/adapters/hono.adapter';

const app = new Hono();

// Create Hono-specific middleware
const authMiddleware = createHonoAuthMiddleware({
  jwtService,
  authService,
  permissionService
});

const adminMiddleware = createHonoPermissionMiddleware({
  permissionService
}, ['admin:*']);

// Apply to routes
app.use('/api/*', authMiddleware);
app.use('/admin/*', authMiddleware, adminMiddleware);

// Protected route with auth context
app.get('/protected', authMiddleware, (c) => {
  return c.json({
    user: c.get('auth').user,
    message: 'Hello authenticated user!'
  });
});

// Admin-only route
app.delete('/users/:id', authMiddleware, adminMiddleware, (c) => {
  return c.json({ success: true, message: 'User deleted' });
});
```

### Bun Integration

```typescript
import { createBunAuthMiddleware, createBunPermissionMiddleware } from 'open-bauth/src/middleware/adapters/bun.adapter';

// Create Bun-specific middleware
const authMiddleware = createBunAuthMiddleware({
  jwtService,
  authService,
  permissionService
});

const userMiddleware = createBunPermissionMiddleware({
  permissionService
}, ['users:read']);

// Use with Bun.serve
const server = Bun.serve({
  port: 3000,
  async fetch(req) {
    // Apply authentication
    const authResult = await authMiddleware(req);
    if (!authResult.success) {
      return new Response('Unauthorized', { status: 401 });
    }
    
    // Route handling
    const url = new URL(req.url);
    
    if (url.pathname === '/protected' && req.method === 'GET') {
      return new Response(JSON.stringify({
        user: authResult.user,
        message: 'Hello authenticated user!'
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    if (url.pathname.startsWith('/users/') && req.method === 'GET') {
      // Check permissions
      const permResult = await userMiddleware(req);
      if (!permResult.success) {
        return new Response('Forbidden', { status: 403 });
      }
      
      return new Response(JSON.stringify({ users: [] }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    return new Response('Not Found', { status: 404 });
  }
});
```

### Express Integration (Legacy)

```typescript
import express from 'express';
import { createAuthMiddleware, createPermissionMiddleware } from 'open-bauth/src/middleware/auth';

const app = express();

// Legacy approach - still supported
const authMw = createAuthMiddleware({ jwtService, authService, permissionService });
const canDelete = createPermissionMiddleware({ permissionService }, ['delete:content']);

app.use(authMw);

app.get('/protected', (req, res) => {
  if (!req.auth?.isAuthenticated) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  res.json({ user: req.auth.user });
});

app.delete('/content/:id', canDelete, (req, res) => {
  res.json({ success: true });
});
```

### Benefits of Adapter Pattern

1. **Framework-Native**: Adapters follow each framework's conventions
2. **Type Safety**: Proper TypeScript support for each framework
3. **Performance**: Optimized for each framework's request/response cycle
4. **Consistency**: Same core logic, different framework integration
5. **Maintainability**: Core changes automatically apply to all adapters

## 🔒 Security Features

### JWT Security

- **Token Validation**: Cryptographic signature verification
- **Expiration Checking**: Automatic token expiration handling
- **DPoP Support**: Demonstrating proof of possession
- **Token Binding**: Binding tokens to specific contexts

### OAuth 2.0 Security

- **PKCE Enforcement**: Required for public clients
- **State Management**: CSRF protection with secure state
- **Nonce Tracking**: Replay attack prevention
- **Redirect URI Validation**: Prevents open redirect attacks
- **Client Authentication**: Secure client credential verification

### Rate Limiting

- **Multiple Strategies**: Per-client, per-user, per-IP limiting
- **Configurable Windows**: Sliding or fixed time windows
- **Progressive Penalties**: Increasing penalties for violations
- **Automatic Blocking**: Temporary blocking for excessive violations

### Audit Logging

- **Security Events**: Comprehensive logging of all security events
- **Attempt Tracking**: Failed attempt monitoring and alerting
- **Pattern Detection**: Automatic detection of suspicious patterns
- **Compliance**: Logs suitable for security audits

## 💡 Usage Examples

### Modern Adapter-Based API Protection

```typescript
import { Hono } from 'hono';
import {
  createHonoAuthMiddleware,
  createHonoPermissionMiddleware,
  createHonoRoleMiddleware
} from 'open-bauth/src/middleware/adapters/hono.adapter';

const app = new Hono();

// Create framework-specific middleware
const authMiddleware = createHonoAuthMiddleware({
  jwtService,
  authService,
  permissionService
});

const adminMiddleware = createHonoPermissionMiddleware({
  permissionService
}, ['admin:*'], { requireAll: true });

const moderatorMiddleware = createHonoRoleMiddleware({
  permissionService
}, ['moderator', 'admin']);

const userMiddleware = createHonoPermissionMiddleware({
  permissionService
}, ['users:read']);

// Apply middleware to route groups
app.use('/api/*', authMiddleware);
app.use('/admin/*', authMiddleware, adminMiddleware);
app.use('/moderator/*', authMiddleware, moderatorMiddleware);
app.use('/user/*', authMiddleware, userMiddleware);

// Protected routes with clean syntax
app.get('/api/profile', authMiddleware, (c) => {
  const auth = c.get('auth');
  return c.json({ user: auth.user });
});

app.post('/admin/users', authMiddleware, adminMiddleware, (c) => {
  return c.json({ success: true, message: 'User created' });
});

app.put('/moderator/content/:id', authMiddleware, moderatorMiddleware, (c) => {
  return c.json({ success: true, message: 'Content moderated' });
});
```

### Cross-Framework Consistency

```typescript
// Same core logic, different framework adapters

// Hono version
import { createHonoAuthMiddleware } from 'open-bauth/src/middleware/adapters/hono.adapter';
const honoAuth = createHonoAuthMiddleware(services);

// Bun version
import { createBunAuthMiddleware } from 'open-bauth/src/middleware/adapters/bun.adapter';
const bunAuth = createBunAuthMiddleware(services);

// Both use the same core authentication logic
// but provide framework-native integration
```

### Custom Adapter Creation

```typescript
import { authenticateRequest, authorizePermissions } from 'open-bauth/src/middleware/core/auth.core';
import type { AuthRequest, PermissionRequest } from 'open-bauth/src/middleware/core/types';

// Create custom framework adapter
export function createCustomFrameworkAuthMiddleware(services: ServiceContainer) {
  return async (request: CustomFrameworkRequest, response: CustomFrameworkResponse) => {
    try {
      // Extract auth header in framework-specific way
      const authHeader = request.headers.get('authorization');
      const token = authHeader?.replace('Bearer ', '');
      
      // Use core authentication function
      const authResult = await authenticateRequest({
        token,
        jwtSecret: services.jwtService.getSecret(),
        dbInitializer: services.dbInitializer
      });
      
      if (!authResult.success) {
        return response.status(401).json({ error: authResult.error });
      }
      
      // Attach to framework-specific context
      request.auth = authResult;
      return request.next();
      
    } catch (error) {
      return response.status(500).json({ error: 'Internal server error' });
    }
  };
}
```

### Testing with Adapters

```typescript
import { describe, expect, test } from 'bun:test';
import { createHonoAuthMiddleware } from 'open-bauth/src/middleware/adapters/hono.adapter';
import { createTestContext } from 'open-bauth/tests/middleware/setup';

describe('Hono Adapter', () => {
  test('should authenticate valid token', async () => {
    const middleware = createHonoAuthMiddleware(testServices);
    const context = createTestContext({
      headers: { 'authorization': 'Bearer valid-token' }
    });
    
    await middleware(context, () => Promise.resolve());
    
    expect(context.get('auth').isAuthenticated).toBe(true);
    expect(context.get('auth').user).toBeDefined();
  });
});
```

## 🎯 Best Practices

### Architecture (Core + Adapter Pattern)

1. **Use Core Functions Directly**: When building custom solutions, use core functions from `src/middleware/core/`
2. **Create Framework Adapters**: Build adapters for new frameworks following the existing pattern
3. **Separate Concerns**: Keep framework-specific code in adapters, business logic in core
4. **Test Core Independently**: Core functions can be tested without framework dependencies
5. **Reuse Core Logic**: Same authentication/authorization logic across all frameworks

### Security

1. **Always Validate**: Never trust client input, validate in core functions
2. **Use HTTPS**: Always use TLS in production
3. **Secure Headers**: Set appropriate security headers in adapters
4. **Rate Limit**: Implement rate limiting in core functions
5. **Log Everything**: Comprehensive logging for security monitoring

### Performance

1. **Lazy Loading**: Load auth context only when needed in core functions
2. **Caching**: Cache frequently accessed permissions in services layer
3. **Async Operations**: Use async/await for non-blocking operations in core
4. **Connection Pooling**: Reuse database connections in service layer
5. **Minimal Overhead**: Keep adapters lightweight, core logic optimized

### Error Handling

1. **Consistent Errors**: Use standard error format from core functions
2. **Secure Errors**: Don't leak sensitive information in adapter responses
3. **Logging**: Log all security events in core functions
4. **Graceful Degradation**: Handle service failures gracefully in adapters
5. **User-Friendly**: Provide clear error messages from adapters

### Testing

1. **Test Core Functions**: Unit test core authentication/authorization logic
2. **Test Adapters Separately**: Test framework-specific adapter behavior
3. **Integration Tests**: Test complete middleware chains
4. **Mock Services**: Use mock services for testing core functions
5. **Cross-Framework Tests**: Ensure consistent behavior across adapters

### Migration from Legacy Middleware

If you're migrating from the old middleware system:

```typescript
// Old approach (still supported)
import { createAuthMiddleware } from 'open-bauth/src/middleware/auth';

// New approach (recommended)
import { createHonoAuthMiddleware } from 'open-bauth/src/middleware/adapters/hono.adapter';

// Both work, but adapters provide better framework integration
```

### Performance

1. **Lazy Loading**: Load auth context only when needed
2. **Caching**: Cache frequently accessed permissions
3. **Async Operations**: Use async/await for non-blocking operations
4. **Connection Pooling**: Reuse database connections
5. **Minimal Overhead**: Keep middleware lightweight

### Error Handling

1. **Consistent Errors**: Use standard error format
2. **Secure Errors**: Don't leak sensitive information
3. **Logging**: Log all security events
4. **Graceful Degradation**: Handle service failures gracefully
5. **User-Friendly**: Provide clear error messages

### Architecture

1. **Separation of Concerns**: Separate auth, authorization, and business logic
2. **Dependency Injection**: Use service containers for dependency management
3. **Configuration**: Externalize configuration for different environments
4. **Testing**: Write comprehensive tests for all middleware
5. **Monitoring**: Add metrics and monitoring for performance and security

---

See [`src/middleware/auth.ts`](src/middleware/auth.ts) and [`src/middleware/oauth-security.ts`](src/middleware/oauth-security.ts) for complete implementation.