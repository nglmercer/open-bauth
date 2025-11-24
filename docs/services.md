# Services Overview

The library provides a comprehensive set of services for authentication, authorization, OAuth 2.0, security, and more. All services are initialized with [`DatabaseInitializer`](src/database/database-initializer.ts) and follow a consistent API.

## Core Services

### [`AuthService`](src/services/auth.ts:18)
**Purpose**: User registration, login, management, role assignment.

**Key Methods**:
- `register(data)` → [`AuthResult`](src/types/auth.ts)
- `login(data)` → [`AuthResult`](src/types/auth.ts)
- `findUserById(id)` → `User | null`
- `assignRole(userId, roleName)`
- `getUsers(page, limit)`

### [`JWTService`](src/services/jwt.ts:10)
**Purpose**: JWT generation/verification, DPoP, refresh rotation.

**Key Methods**:
- `generateToken(user)` → `string`
- `verifyToken(token)` → [`JWTPayload`](src/types/auth.ts)
- `verifyDPoPProof(dpop, method, uri)`
- `rotateRefreshToken(oldToken, user)`
- `extractTokenFromHeader(header)`

### [`PermissionService`](src/services/permissions.ts:20)
**Purpose**: RBAC - roles, permissions, checks.

**Key Methods**:
- `createPermission(data)`
- `assignPermissionToRole(roleId, permId)`
- `userHasPermission(userId, permName)` → `boolean`
- `userCanAccessResource(userId, resource, action)` → `boolean`

### [`OAuthService`](src/services/oauth.ts:35)
**Purpose**: Full OAuth 2.0 flows, clients, tokens.

**Key Methods**:
- `createClient(data)` → [`OAuthClient`](src/types/oauth.ts)
- `handleAuthorizationRequest(req, user)`
- `handleTokenRequest(req)` → [`TokenResponse`](src/types/oauth.ts)
- `handleIntrospectionRequest(req)`

### [`SecurityService`](src/services/security.ts:16)
**Purpose**: PKCE, DPoP, challenges, hashing.

**Key Methods**:
- `generatePKCEChallenge(method)`
- `verifyPKCEChallenge(verifier, challenge, method)` → `boolean`
- `generateDPoPProof(method, uri, key)`
- `createChallenge(type, data)`
- `hashPassword(password)` → `{hash, salt}`

### [`EnhancedUserService`](src/services/enhanced-user.ts)
**Purpose**: Advanced user features (MFA, biometrics, devices).

### Factory
- [`serviceFactory`](src/services/service-factory.ts): Dependency injection.

## Initialization Example
```typescript
const dbInitializer = new DatabaseInitializer({ database: db });
await dbInitializer.initialize();

const jwtService = new JWTService(secret);
const authService = new AuthService(dbInitializer, jwtService);
const permissionService = new PermissionService(dbInitializer);
const oauthService = new OAuthService(dbInitializer, securityService, jwtService);
```

## Best Practices
- Initialize services after DB setup.
- Use structured logging with services.
- Validate inputs with types.
- Handle `AuthResult.error` in all calls.

See individual source files for full API.