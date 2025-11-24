# Middleware Documentation

Comprehensive middleware system for authentication, authorization, and security that works across different web frameworks.

## 📋 Table of Contents

- [Overview](#overview)
- [Core Middleware](#core-middleware)
- [OAuth Security Middleware](#oauth-security-middleware)
- [Framework Integration](#framework-integration)
- [Security Features](#security-features)
- [Usage Examples](#usage-examples)
- [Best Practices](#best-practices)

## 🌟 Overview

The middleware system provides framework-agnostic authentication and authorization that can be integrated with any web framework while maintaining consistent behavior and security features.

### Key Benefits

- **Framework Agnostic**: Works with Hono, Express, Elysia, Fastify, and custom frameworks
- **Security First**: Built-in OAuth 2.0, JWT, DPoP, and rate limiting
- **Type Safe**: Full TypeScript support with proper typing
- **Extensible**: Easy to add custom middleware and security features
- **Performance Optimized**: Minimal overhead with efficient caching

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Request Flow                      │
└─────────────────────┬───────────────────────────┘
                      │ Middleware Pipeline
┌─────────────────────▼───────────────────────────┐
│  Auth Middleware │ Permission │ OAuth Security │ Custom │
└─────────────────────┬───────────────────────────┘
                      │ Service Layer
┌─────────────────────▼───────────────────────────┐
│  AuthService │ JWTService │ PermissionService │ OAuthService │
└─────────────────────────────────────────────────────┘
```

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

### Hono Integration

```typescript
import { Hono } from 'hono';
import { createAuthMiddleware, createPermissionMiddleware } from 'open-bauth/src/middleware/auth';

const app = new Hono();

// Authentication middleware
const authMw = createAuthMiddleware({ jwtService, authService, permissionService });

// Permission middleware
const canEdit = createPermissionMiddleware({ permissionService }, ['edit:content']);

app.use('*', async (c, next) => {
  const result = await authMw(c, next);
  if (!result.success) {
    return c.json({ error: result.error }, 401);
  }
  
  c.auth = result.authContext;
  await next();
});

app.get('/protected', authMw, async (c) => {
  return c.json({ user: c.auth.user });
});

app.delete('/content/:id', authMw, canEdit, async (c) => {
  // User has edit permission
  return c.json({ success: true });
});
```

### Express Integration

```typescript
import express from 'express';
import { createAuthMiddleware, createPermissionMiddleware } from 'open-bauth/src/middleware/auth';

const app = express();

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
  // User has delete permission
  res.json({ success: true });
});
```

### Elysia Integration

```typescript
import { Elysia } from 'elysia';
import { createAuthMiddleware } from 'open-bauth/src/middleware/auth';

const app = new Elysia();

const authMw = createAuthMiddleware({ jwtService, authService, permissionService });

app.derive(({ request }) => {
  const authContext = authMw(request);
  return { authContext };
});

app.get('/protected', ({ authContext }) => {
  if (!authContext.isAuthenticated) {
    throw new Error('Unauthorized');
  }
  
  return { user: authContext.user };
});
```

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

### Complete API Protection

```typescript
import { createAuthMiddleware, createPermissionMiddleware, createOAuthSecurityMiddleware } from 'open-bauth/src/middleware';

// Create middleware instances
const authMw = createAuthMiddleware({ jwtService, authService, permissionService });
const adminMw = createPermissionMiddleware({ permissionService }, ['admin:*'], { requireAll: true });
const userMw = createPermissionMiddleware({ permissionService }, ['read:own']);
const oauthSecurity = createOAuthSecurityMiddleware(oauthService, securityService, jwtService);

// Apply to routes
app.use('/api/*', authMw);
app.use('/admin/*', authMw, adminMw);
app.use('/user/*', authMw, userMw);
app.use('/oauth/*', oauthSecurity);

// Protected admin route
app.post('/admin/users', authMw, adminMw, async (c) => {
  // User is authenticated and has admin permissions
  return c.json({ success: true });
});

// Protected user route
app.get('/user/profile', authMw, userMw, async (c) => {
  // User is authenticated and can read own data
  return c.json({ profile: c.auth.user });
});
```

### Custom Security Middleware

```typescript
import { createAuthMiddleware } from 'open-bauth/src/middleware/auth';

const authMw = createAuthMiddleware({ jwtService, authService, permissionService });

// Custom middleware for API key validation
const apiKeyMw = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || !isValidApiKey(apiKey)) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
  
  req.apiKey = apiKey;
  next();
};

// Chain middleware
app.use('/api/*', authMw, apiKeyMw, async (req, res) => {
  // User is authenticated and has valid API key
  return res.json({ user: req.auth.user });
});
```

### Context Enhancement

```typescript
import { createAuthMiddleware } from 'open-bauth/src/middleware/auth';

const authMw = createAuthMiddleware({ 
  jwtService, 
  authService, 
  permissionService 
});

// Enhanced middleware with additional context
const enhancedAuthMw = (req, res, next) => {
  const result = authMw(req, res, (error) => {
    if (error) return next(error);
    
    // Add additional context
    req.auth.sessionId = generateSessionId();
    req.auth.requestTime = Date.now();
    req.auth.clientInfo = parseClientInfo(req);
    
    next();
  });
  
  return result;
};

app.use(enhancedAuthMw, (req, res) => {
  // Enhanced context available
  console.log('Session:', req.auth.sessionId);
  console.log('Request time:', req.auth.requestTime);
  console.log('Client info:', req.auth.clientInfo);
});
```

## 🎯 Best Practices

### Security

1. **Always Validate**: Never trust client input
2. **Use HTTPS**: Always use TLS in production
3. **Secure Headers**: Set appropriate security headers
4. **Rate Limit**: Implement rate limiting for sensitive endpoints
5. **Log Everything**: Comprehensive logging for security monitoring

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