# Services Overview

The library provides a comprehensive set of services for authentication, authorization, OAuth 2.0, security, and more. All services are initialized with [`DatabaseInitializer`](src/database/database-initializer.ts) and follow a consistent API.

## 📋 Table of Contents

- [Core Services](#core-services)
- [Service Factory](#service-factory)
- [Type Definitions](#type-definitions)
- [Usage Examples](#usage-examples)
- [Best Practices](#best-practices)

## 🏗️ Core Services

### [`AuthService`](src/services/auth.ts:18)

**Purpose**: User registration, login, management, and role assignment.

**Key Methods**:
- `register(data)` → [`AuthResult`](src/types/auth.ts:402)
  - Registers a new user with email, password, username, and optional data
  - Validates unique email and automatically hashes password
- `login(data)` → [`AuthResult`](src/types/auth.ts:402)
  - Authenticates user with email or username and password
  - Returns JWT token on successful authentication
- `findUserById(id)` → `User | null`
  - Finds user by ID with optional role/permission inclusion
- `assignRole(userId, roleName)` → `Result`
  - Assigns role to user with validation
- `removeRole(userId, roleName)` → `Result`
  - Removes role from user with cleanup
- `getUsers(page?, limit?, options?)` → `{ users: User[], total: number }`
  - Paginated user listing with filtering options
- `updateUser(userId, data)` → `AuthResult`
  - Updates user data with validation
- `changePassword(userId, oldPassword, newPassword)` → `Result`
  - Secure password change with validation
- `deactivateUser(userId)` → `Result`
  - Deactivates user account
- `activateUser(userId)` → `Result`
  - Activates user account

**Usage Example**:
```typescript
const authService = new AuthService(dbInitializer, jwtService);

// Register new user
const registerResult = await authService.register({
  email: 'user@example.com',
  password: 'SecurePass123!',
  username: 'johndoe',
  first_name: 'John',
  last_name: 'Doe'
});

if (!registerResult.success) {
  console.error('Registration failed:', registerResult.error);
  return;
}

// Login user
const loginResult = await authService.login({
  email: 'user@example.com',
  password: 'SecurePass123!'
});

if (loginResult.success) {
  console.log('JWT Token:', loginResult.token);
  console.log('User:', loginResult.user);
}
```

### [`JWTService`](src/services/jwt.ts:10)

**Purpose**: JWT generation/verification, DPoP, and refresh token rotation.

**Key Methods**:
- `generateToken(user, expiresIn?)` → `string`
  - Generates JWT access token with user payload
  - Supports custom expiration time
  - Includes ID token for OpenID Connect
- `verifyToken(token)` → [`JWTPayload`](src/types/auth.ts:416)
  - Verifies and decodes JWT token
  - Validates signature and expiration
  - Returns user payload with roles/permissions
- `generateRefreshToken(userId, expiresIn?)` → `string`
  - Generates secure refresh token
  - Uses cryptographic random generation
- `verifyRefreshToken(token)` → `string | null`
  - Verifies refresh token validity
  - Returns user ID on success
- `rotateRefreshToken(oldToken, newToken)` → `Result`
  - Rotates refresh token securely
  - Invalidates old token immediately
- `extractTokenFromHeader(header)` → `string | null`
  - Extracts token from Authorization header
  - Supports Bearer and custom schemes
- `getTokenRemainingTime(token)` → `number`
  - Returns remaining time in seconds
- `isTokenExpired(token)` → `boolean`
  - Checks if token is expired
- `refreshTokenIfNeeded(token, user, threshold?)` → `string | null`
  - Auto-refreshes token if near expiration
- `verifyDPoPProof(dpop, method, uri)` → `Result`
  - Verifies DPoP proof according to RFC 9449

**Usage Example**:
```typescript
const jwtService = new JWTService('your-secret-key', '24h');

// Generate access token
const token = await jwtService.generateToken({
  id: user.id,
  email: user.email,
  roles: user.roles,
  permissions: user.permissions
});

// Verify token
const payload = await jwtService.verifyToken(token);
console.log('User ID:', payload.userId);
console.log('Roles:', payload.roles);

// Generate refresh token
const refreshToken = await jwtService.generateRefreshToken(user.id);
```

### [`PermissionService`](src/services/permissions.ts:20)

**Purpose**: RBAC - role management, permissions, and access checks.

**Key Methods**:
- `createPermission(data)` → [`PermissionResult`](src/types/auth.ts:444)
  - Creates new permission with name, resource, and action
  - Validates permission uniqueness
- `updatePermission(permissionId, data)` → [`PermissionResult`](src/types/auth.ts:444)
  - Updates existing permission
  - Maintains audit trail
- `deletePermission(permissionId)` → [`PermissionResult`](src/types/auth.ts:444)
  - Deletes permission and its assignments
  - Cleans up role associations
- `createRole(data)` → [`RoleResult`](src/types/auth.ts:458)
  - Creates new role with name and description
- `updateRole(roleId, data)` → [`RoleResult`](src/types/auth.ts:458)
  - Updates existing role
  - Preserves permissions
- `deleteRole(roleId)` → [`RoleResult`](src/types/auth.ts:458)
  - Deletes role and its assignments
  - Removes from all users
- `assignPermissionToRole(roleId, permissionId)` → [`PermissionResult`](src/types/auth.ts:444)
  - Assigns permission to role
  - Validates existence of both
- `removePermissionFromRole(roleId, permissionId)` → [`PermissionResult`](src/types/auth.ts:444)
  - Removes permission from role
  - Maintains consistency
- `updateRolePermissions(roleId, permissionIds)` → [`PermissionResult`](src/types/auth.ts:444)
  - Updates all permissions for a role
  - Replaces entire permission set
- `assignRoleToUser(userId, roleId)` → `Result`
  - Assigns role to user
  - Validates role existence
- `removeRoleFromUser(userId, roleId)` → `Result`
  - Removes role from user
  - Updates user permissions cache
- `userHasPermission(userId, permissionName)` → `boolean`
  - Checks if user has specific permission
  - Evaluates through role assignments
- `userCanAccessResource(userId, resource, action)` → `boolean`
  - Checks resource-level access
  - Supports wildcard permissions
- `getUserRoles(userId)` → `Role[]`
  - Gets all user roles
  - Includes inherited roles
- `getUserPermissions(userId)` → `Permission[]`
  - Gets all user permissions
  - Includes role-based and direct permissions
- `getRolePermissions(roleId)` → `Permission[]`
  - Gets all permissions for a role
  - Resolves permission hierarchy

**Usage Example**:
```typescript
const permissionService = new PermissionService(dbInitializer);

// Create permission
const createResult = await permissionService.createPermission({
  name: 'users:read',
  resource: 'users',
  action: 'read',
  description: 'Read user information'
});

// Create role
const roleResult = await permissionService.createRole({
  name: 'admin',
  description: 'Administrator with full access'
});

// Assign permission to role
await permissionService.assignPermissionToRole(roleResult.role!.id, createResult.permission!.id);

// Check user permission
const canRead = await permissionService.userHasPermission(userId, 'users:read');
```

### [`OAuthService`](src/services/oauth.ts:35)

**Purpose**: Complete OAuth 2.0 flows, client management, and token handling.

**Key Methods**:
- `createClient(data)` → [`OAuthClient`](src/types/oauth.ts:8)
  - Creates new OAuth client with full configuration
  - Validates client metadata
- `updateClient(id, data)` → [`OAuthClient`](src/types/oauth.ts:8)
  - Updates existing OAuth client
  - Maintains client secrets
- `findClientByClientId(clientId)` → `OAuthClient | null`
  - Finds client by client ID
  - Includes active status check
- `authenticateClient(clientId, clientSecret)` → `OAuthClient | null`
  - Authenticates client credentials
  - Validates secret hash
- `validateRedirectUri(clientId, redirectUri)` → `boolean`
  - Validates client redirect URI
  - Prevents open redirect attacks
- `handleAuthorizationRequest(request, user)` → [`AuthorizationResponse`](src/types/oauth.ts:255)
  - Handles OAuth 2.0 authorization request
  - Supports PKCE and state parameters
- `handleTokenRequest(request)` → [`TokenResponse`](src/types/oauth.ts:282)
  - Handles OAuth 2.0 token request
  - Supports all grant types
- `handleDeviceAuthorizationRequest(request)` → [`DeviceAuthorizationResponse`](src/types/oauth.ts:299)
  - Handles device authorization flow
  - RFC 8628 compliant
- `handleIntrospectionRequest(request)` → [`IntrospectionResponse`](src/types/oauth.ts:313)
  - Handles token introspection
  - RFC 7662 compliant
- `handleRevocationRequest(request)` → `Result`
  - Handles token revocation
  - RFC 7009 compliant
- `createAuthCode(data)` → [`AuthorizationCode`](src/types/oauth.ts:65)
  - Creates authorization code
  - Supports PKCE binding
- `createRefreshToken(data)` → [`RefreshToken`](src/types/oauth.ts:84)
  - Creates refresh token
  - With rotation support
- `rotateRefreshToken(id, newToken)` → [`RefreshToken`](src/types/oauth.ts:84)
  - Rotates refresh token
  - Invalidates previous token

**Usage Example**:
```typescript
const oauthService = new OAuthService(dbInitializer, securityService, jwtService);

// Create OAuth client
const client = await oauthService.createClient({
  client_id: 'my-app',
  client_secret: 'secret-key',
  client_name: 'My Application',
  redirect_uris: ['https://myapp.com/callback'],
  grant_types: [OAuthGrantType.AUTHORIZATION_CODE, OAuthGrantType.REFRESH_TOKEN],
  response_types: [OAuthResponseType.CODE],
  scope: 'read write profile'
});

// Handle authorization request
const authResponse = await oauthService.handleAuthorizationRequest({
  response_type: OAuthResponseType.CODE,
  client_id: 'my-app',
  redirect_uri: 'https://myapp.com/callback',
  scope: 'read write',
  state: 'random-state',
  code_challenge: pkceChallenge.code_challenge,
  code_challenge_method: PKCEMethod.S256
}, user);
```

### [`SecurityService`](src/services/security.ts:16)

**Purpose**: PKCE, DPoP, security challenges, hashing, and encryption.

**Key Methods**:
- `generatePKCEChallenge(method)` → [`PKCEChallenge`](src/types/oauth.ts:376)
  - Generates PKCE challenge (RFC 7636)
  - Supports S256 and plain methods
- `verifyPKCEChallenge(verifier, challenge, method)` → `boolean`
  - Verifies PKCE challenge
  - Cryptographically secure validation
- `generateState(length?)` → `string`
  - Generates cryptographically secure state
  - For CSRF protection
- `generateNonce(length?)` → `string`
  - Generates nonce for replay protection
  - With entropy validation
- `generateDPoPProof(method, uri, key, jwkThumbprint?)` → `string`
  - Generates DPoP proof
  - RFC 9449 compliant
- `verifyDPoPProof(dpop, method, uri)` → `Result`
  - Verifies DPoP proof
  - With header validation
- `registerVerifier(type, verifier)` → `void`
  - Registers a custom challenge verifier
  - Supports Strategy pattern for extensibility
- `createChallenge(type, data, expirationMinutes?)` → [`SecurityChallenge`](src/types/oauth.ts:400)
  - Creates security challenge
  - Supports multiple challenge types
- `verifyChallenge(challengeId, solution)` → `Result`
  - Verifies challenge solution
  - With rate limiting
- `hashPassword(password)` → `{ hash: string, salt: string }`
  - Secure password hashing
  - Uses bcrypt with configurable rounds
- `verifyPassword(password, hash, salt)` → `boolean`
  - Verifies password against hash
  - Constant-time comparison
- `encrypt(data, key)` → `string`
  - Encrypts data with AES-GCM
  - With authenticated encryption
- `decrypt(encryptedData, key)` → `string`
  - Decrypts AES-GCM encrypted data
  - With authentication verification
- `generateSecureToken(length?)` → `string`
  - Generates cryptographically secure token
  - Uses Web Crypto API

**Usage Example**:
```typescript
const securityService = new SecurityService();

// Generate PKCE challenge
const pkceChallenge = securityService.generatePKCEChallenge(PKCEMethod.S256);
console.log('Code Challenge:', pkceChallenge.code_challenge);
console.log('Code Verifier:', pkceChallenge.code_verifier);

// Verify PKCE
const isValid = securityService.verifyPKCEChallenge(
  pkceChallenge.code_verifier,
  pkceChallenge.code_challenge,
  PKCEMethod.S256
);

// Hash password
const { hash, salt } = await securityService.hashPassword('user-password');
console.log('Hash:', hash);
console.log('Salt:', salt);

// Register Custom Verifier
securityService.registerVerifier('math_puzzle', {
  verify: (data, solution) => {
    return { valid: parseInt(solution.answer) === data.expected };
});
```

#### 🔐 **MFA and Security Challenges**

The SecurityService provides a **pluggable** architecture for security challenges using the **Strategy pattern**. This enables flexible MFA implementations:

**Built-in Verifiers**:
- `TOTPVerifier` - TOTP/MFA (RFC 6238) for Google Authenticator, Authy
- `SecureCodeVerifier` - Email/SMS verification codes (SHA-256 hashed)
- `BackupCodeVerifier` - Backup recovery codes

**Custom Verifiers** (placeholders for implementation):
- `CAPTCHAVerifier` - reCAPTCHA, hCaptcha integration
- `BiometricVerifier` - Fingerprint, Face ID verification
- `DeviceVerifier` - Device-based authentication

**How it Works**:
```typescript
// SecurityService internally:
// 1. Registers default verifiers
this.registerVerifier(ChallengeType.MFA, new TOTPVerifier());
this.registerVerifier(ChallengeType.EMAIL_VERIFICATION, new SecureCodeVerifier());

// 2. Verifies challenges by delegating to the appropriate verifier
async verifyChallenge(challenge, solution) {
  const verifier = this.verifiers.get(challenge.challenge_type);
  return await verifier.verify(challengeData, solution);
}
```

**Integration with EnhancedUserService**:
- `verifyMFA()` uses SecurityService for TOTP verification (stateless)
- `generateMFAChallenge()` creates and persists Email/SMS challenges
- `verifyMFACode()` uses SecurityService to verify and marks challenges as solved
- Challenges are **never deleted immediately** - marked as `is_solved: true` for audit


### [`EnhancedUserService`](src/services/enhanced-user.ts:21)

**Purpose**: Advanced user features (MFA, biometrics, device management).

**Key Methods**:
- `createAnonymousUser(sessionData)` → `Result`
  - Creates anonymous user with session data
  - Supports promotion to full user
- `promoteAnonymousUser(anonymousId, userData)` → `Result`
  - Promotes anonymous user to full user
  - Preserves session data
- `registerDevice(userId, deviceId, deviceName, deviceType)` → `Result`
  - Registers device for user
  - With trust level tracking
- `trustDevice(userId, deviceId)` → `Result`
  - Marks device as trusted
  - For SSO purposes
- `removeDevice(userId, deviceId)` → `Result`
  - Removes device from user
  - Revokes all sessions for device
- `getUserDevices(userId)` → `UserDevice[]`
  - Gets all user devices
  - With trust status
- `createDeviceSecret(userId, deviceId, deviceName, deviceType)` → `Result`
  - Creates device secret for SSO
  - One-time return of secret
- `verifyDeviceSecret(deviceId, secret)` → `Result`
  - Verifies device secret for SSO
  - With rate limiting
- `registerBiometricCredential(userId, biometricType, encryptedData, deviceId)` → `Result`
  - Registers biometric credential
  - With secure storage
- `verifyBiometricCredential(userId, biometricType, providedData)` → `Result`
  - Verifies biometric authentication
  - With anti-replay protection
- `getUserBiometricCredentials(userId)` → `BiometricCredential[]`
  - Gets all user biometric credentials
  - With device association
- `setupMFA(userId, mfaType, config)` → `Result`
  - Sets up MFA for user
  - Supports TOTP, SMS, email
- `enableMFA(mfaConfigId)` → `Result`
  - Enables MFA configuration
  - Updates enabled status
- `disableMFA(mfaConfigId)` → `Result`
  - Disables MFA configuration
  - Requires re-authentication
- `setPrimaryMFA(mfaConfigId)` → `Result`
  - Sets MFA as primary method
  - Unsets other primary configurations
- `verifyMFA(userId, code, mfaType?)` → `Result`
  - **NEW**: Verifies TOTP-based MFA (Google Authenticator, Authy)
  - Stateless verification using SecurityService
  - No database persistence (TOTP is time-based)
  - Default mfaType: `MFAType.TOTP`
- `generateMFAChallenge(userId, mfaType, codeLength?)` → `Result`
  - **NEW**: Generates MFA challenge for Email/SMS
  - Creates 6-digit verification code
  - Hashes code with SHA-256 + salt
  - Stores challenge in database with 10-minute expiry
  - Returns plain text code (only once)
- `verifyMFACode(userId, code, challengeId)` → `Result`
  - **NEW**: Verifies Email/SMS MFA code
  - Validates against stored challenge
  - Marks challenge as solved (maintains audit trail)
  - Uses SecurityService for verification
- `cleanupExpiredChallenges(retentionDays?)` → `number`
  - **NEW**: Cleans up old security challenges
  - Only removes solved challenges older than retention period
  - Default retention: 7 days
  - Returns count of cleaned challenges
- `getEnabledMFAConfigurations(userId)` → `MFAConfiguration[]`
  - Gets user's active MFA configurations
  - With backup methods
- `getPrimaryMFAConfiguration(userId)` → `MFAConfiguration | null`
  - Gets user's primary MFA configuration
  - For default authentication

**Usage Example**:
```typescript
const enhancedUserService = new EnhancedUserService(dbInitializer, securityService);

// Create anonymous user
const anonymousResult = await enhancedUserService.createAnonymousUser({
  sessionId: 'session-123',
  preferences: { theme: 'dark', language: 'en' }
});

// Promote to full user
const promoteResult = await enhancedUserService.promoteAnonymousUser(
  anonymousResult.anonymousUser!.anonymous_id,
  {
    email: 'user@example.com',
    password: 'SecurePass123!',
    username: 'johndoe',
    first_name: 'John',
    last_name: 'Doe'
  }
);

// Setup TOTP MFA (Google Authenticator)
const mfaResult = await enhancedUserService.setupMFA(
  promoteResult.user!.id,
  MFAType.TOTP,
  {
    secret: 'JBSWY3DPEHPK3PXP',
    is_primary: true
  }
);

// Verify TOTP code
const verifyResult = await enhancedUserService.verifyMFA(
  promoteResult.user!.id,
  '123456' // 6-digit code from authenticator app
);

if (verifyResult.success) {
  console.log('✅ MFA verified successfully');
}

// Setup Email MFA and send code
const emailMFA = await enhancedUserService.setupMFA(
  promoteResult.user!.id,
  MFAType.EMAIL,
  { email: 'user@example.com' }
);

// Generate and send email verification code
const challengeResult = await enhancedUserService.generateMFAChallenge(
  promoteResult.user!.id,
  MFAType.EMAIL
);

if (challengeResult.success) {
  // Send email with challengeResult.code
  console.log('Send this code by email:', challengeResult.code);
  
  // Later, when user enters the code
  const emailVerifyResult = await enhancedUserService.verifyMFACode(
    promoteResult.user!.id,
    '123456', // Code entered by user
    challengeResult.challenge!.challenge_id
  );
  
  if (emailVerifyResult.success) {
    console.log('✅ Email code verified');
    // Challenge is now marked as is_solved: true (not deleted)
  }
}
```

## 🏭 Service Factory

### [`ServiceFactory`](src/services/service-factory.ts:11)

**Purpose**: Dependency injection and centralized service management.

**Key Methods**:
- `getService<T>(serviceName)` → `T`
  - Gets service instance by name
  - With type safety
- `registerService(name, service)` → `void`
  - Registers custom service
  - With dependency injection
- `initializeServices(config)` → `Promise<void>`
  - Initializes all registered services
  - With error handling

**Usage Example**:
```typescript
import { Database } from 'bun:sqlite';
import { DatabaseInitializer } from 'open-bauth';
import { JWTService, AuthService, PermissionService } from 'open-bauth';

const db = new Database('auth.db');
const dbInitializer = new DatabaseInitializer({ database: db });
const jwtService = new JWTService(process.env.JWT_SECRET || 'dev-secret', '7d');
const authService = new AuthService(dbInitializer, jwtService);
const permissionService = new PermissionService(dbInitializer);
//await dbInitializer.initialize();
```

## 📝 Type Definitions

### [`AuthResult`](src/types/auth.ts:402)
Result of authentication operations with success/failure status.

```typescript
interface AuthResult {
  success: boolean;
  user?: User;
  token?: string;
  error?: {
    type: AuthErrorType;
    message: string;
    details?: any;
  };
}
```

### [`JWTPayload`](src/types/auth.ts:416)
JWT payload structure with user information and roles.

```typescript
interface JWTPayload {
  userId: string;
  email: string;
  username?: string;
  roles: string[];
  permissions: string[];
  iat: number;
  exp: number;
  iss?: string;
  aud?: string;
}
```

### [`OAuthClient`](src/types/oauth.ts:8)
Complete OAuth 2.0 client configuration.

```typescript
interface OAuthClient {
  client_id: string;
  client_secret?: string;
  client_name: string;
  redirect_uris: string[];
  grant_types: OAuthGrantType[];
  response_types: OAuthResponseType[];
  scope: string;
  is_public: boolean;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}
```

### [`TokenResponse`](src/types/oauth.ts:282)
Standard OAuth 2.0 token response.

```typescript
interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
}
```

### [`PermissionResult`](src/types/auth.ts:444) and [`RoleResult`](src/types/auth.ts:458)
Results of permission and role operations.

```typescript
interface PermissionResult {
  success: boolean;
  permission?: Permission;
  error?: {
    type: string;
    message: string;
  };
}

interface RoleResult {
  success: boolean;
  role?: Role;
  error?: {
    type: string;
    message: string;
  };
}
```

## 💡 Usage Examples

### Complete Authentication Setup

```typescript
import { DatabaseInitializer } from './src/database/database-initializer';
import { initializeServices } from './src/services/service-factory';
import { SecurityService } from './src/services/security';

// Initialize database
const dbInitializer = new DatabaseInitializer({ database: db });
await dbInitializer.initialize();
await dbInitializer.seedDefaults();

// Create all services
const services = await initializeServices({
  database: db,
  jwtSecret: process.env.JWT_SECRET || 'dev-secret',
  jwtExpiration: '24h'
});

// Extract services
const { authService, jwtService, permissionService, oauthService, securityService, enhancedUserService } = services;

// Use services
const registerResult = await authService.register({
  email: 'user@example.com',
  password: 'SecurePass123!',
  username: 'johndoe',
  first_name: 'John',
  last_name: 'Doe'
});

if (registerResult.success) {
  console.log('User registered successfully');
  console.log('JWT Token:', registerResult.token);
}
```

### OAuth 2.0 Flow

```typescript
// Create OAuth service
import { OAuthService } from './src/services/oauth';
const oauthService = new OAuthService(dbInitializer, securityService, jwtService);

// Create enhanced user service
import { EnhancedUserService } from './src/services/enhanced-user';
const enhancedUserService = new EnhancedUserService(dbInitializer, securityService);

// Setup MFA for user
const mfaResult = await enhancedUserService.setupMFA(
  userId,
  MFAType.TOTP,
  {
    secret: 'JBSWY3DPEHPK3PXP',
    is_primary: true
  }
);

// Handle OAuth authorization
const authResponse = await oauthService.handleAuthorizationRequest({
  response_type: OAuthResponseType.CODE,
  client_id: 'my-app',
  redirect_uri: 'https://myapp.com/callback',
  scope: 'read write profile',
  state: securityService.generateState(),
  code_challenge: pkceChallenge.code_challenge,
  code_challenge_method: PKCEMethod.S256
}, user);
```

## 🎯 Best Practices

### Service Initialization

1. **Initialize Database First**: Always initialize database before services
2. **Use Service Factory**: Prefer factory over manual instantiation
3. **Handle Dependencies**: Let factory manage service dependencies
4. **Error Handling**: Always check `success` property in results

### Security Considerations

1. **JWT Security**: Use strong secrets and appropriate expiration
2. **Password Security**: Always hash passwords with salt (use Bun.password or Argon2)
3. **OAuth Security**: Implement PKCE for public clients
4. **Rate Limiting**: Implement rate limiting for sensitive operations
5. **Audit Logging**: Log all security-relevant events

### MFA and Challenge Management

1. **Challenge Lifecycle**:
   - ❌ **DON'T**: Delete challenges immediately with `db.run("DELETE...")`
   - ✅ **DO**: Mark as `is_solved: true` for audit trail
   ```typescript
   // Correct approach
   await challengeController.update(challenge.id, {
     is_solved: true,
     solved_at: new Date().toISOString()
   });
   ```

2. **TOTP vs Email/SMS**:
   - **TOTP**: Use `verifyMFA()` - stateless, no DB persistence needed
   - **Email/SMS**: Use `generateMFAChallenge()` + `verifyMFACode()` - requires DB

3. **Challenge Cleanup**:
   - Run periodic cleanup with `cleanupExpiredChallenges()`
   - Recommend 7-day retention for compliance
   - Schedule as daily cron job

4. **Security Service Integration**:
   - Always use `SecurityService.verifyChallenge()` for verification
   - Never implement verification logic from scratch
   - Leverage existing verifiers (TOTP, SecureCode, BackupCode)

5. **Code Generation**:
   - Use cryptographically secure random generation
   - Hash codes before storage (SHA-256 + salt)
   - Never store plain text codes in database


### Performance Optimization

1. **Connection Pooling**: Use database connection pooling
2. **Caching**: Cache frequently accessed permissions
3. **Lazy Loading**: Load services only when needed
4. **Batch Operations**: Use batch operations for multiple items

### Error Handling

1. **Consistent Errors**: Use standardized error format
2. **Error Types**: Provide specific error types for different scenarios
3. **Logging**: Log errors with appropriate context
4. **User-Friendly**: Return user-friendly error messages

---

For complete implementation examples, see the [examples directory](../examples/) and [usage examples](./usage-example.ts).