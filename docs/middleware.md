# Middleware

Framework-agnostic middleware for authentication, permissions, and OAuth security. Designed for Hono, Elysia, Express, etc.

## Authentication Middleware

### `authenticateRequest(request, services)`
Low-level function to authenticate a request.

Returns `{ success, context?, error? }`

### `createAuthMiddleware(services, required = true)`
Factory for auth middleware.

- `required: true`: 401 if no token
- `false`: attaches `c.auth` (guest if no token)

Usage (Hono):
```typescript
app.use('*', createAuthMiddleware({ jwtService, authService, permissionService }));
```

### `createPermissionMiddleware(services, permissions, { requireAll = false })`
Requires permissions.

- `requireAll: false`: any permission
- `true`: all permissions

### `createRoleMiddleware(roles)`
Requires roles (any match).

## OAuth Security Middleware

### `OAuthSecurityMiddleware` class
Advanced OAuth validation.

**Methods**:
- `validateAuthorizationRequest(req, client)`
- `validateTokenRequest(req, client)`
- `verifyState(state, stored)`
- `verifyNonce(nonce, usedNonces)`
- `verifyDPoP(req, token)`
- `createChallenge(type, data)`
- `verifyChallenge(id, solution)`
- `detectSuspiciousActivity(userId, ip, agent)`
- `checkRateLimit(clientId?, userId?, ip)`

Factory: `createOAuthSecurityMiddleware(oauthService, securityService, jwtService)`

## Usage Example (Hono)
```typescript
const authMw = createAuthMiddleware(services, true);
const oauthSecurity = createOAuthSecurityMiddleware(...);

app.use('/oauth/authorize', oauthSecurity.validateAuthorizationRequest);
app.use('*', authMw);
app.get('/admin', createPermissionMiddleware(services, ['admin']));
```

Attaches `c.auth` and `c.oauthContext`.

See [`src/middleware/auth.ts`](src/middleware/auth.ts), [`src/middleware/oauth-security.ts`](src/middleware/oauth-security.ts).