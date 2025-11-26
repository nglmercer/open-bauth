# OAuth 2.0 Implementation Guide

Esta guía documenta la implementación completa de OAuth 2.0 y funcionalidades de seguridad avanzada añadidas al sistema de autenticación existente.

## 🎯 Objetivos

- Implementar compatibilidad total con OAuth 2.0 y OpenID Connect
- Soportar PKCE (RFC 7636) para seguridad mejorada
- Implementar DPoP (RFC 9449) para prevención de tokens robados
- Añadir autenticación biométrica
- Soportar usuarios anónimos con promoción
- Implementar SSO nativo con device secrets
- Sistema MFA completo
- Migración gradual sin romper cambios existentes

## 📁 Estructura de Archivos

### Tipos (`src/types/oauth.ts`)
- **OAuth 2.0 Client Types**: `OAuthClient`, `CreateOAuthClientData`, `UpdateOAuthClientData`
- **Authorization Codes**: `AuthorizationCode` con soporte PKCE
- **Refresh Tokens**: `RefreshToken` con rotación automática
- **Device Secrets**: `DeviceSecret` para SSO
- **Biometric Credentials**: `BiometricCredential` para autenticación biométrica
- **Anonymous Users**: `AnonymousUser` con capacidad de promoción
- **User Devices**: `UserDevice` para gestión de dispositivos
- **MFA Configurations**: `MFAConfiguration` para múltiples factores
- **Security Challenges**: `SecurityChallenge` para validaciones adicionales
- **OAuth 2.0 Requests/Responses**: Tipos completos para todos los flujos

### Base de Datos (`src/database/schema/oauth-schema-extensions.ts`)
- **oauth_clients**: Clientes OAuth 2.0 con configuración completa
- **authorization_codes**: Códigos de autorización con PKCE
- **refresh_tokens**: Tokens de refresco con rotación
- **device_secrets**: Secretos de dispositivo para SSO
- **biometric_credentials**: Credenciales biométricas encriptadas
- **anonymous_users**: Usuarios anónimos con datos de sesión
- **user_devices**: Dispositivos registrados por usuario
- **mfa_configurations**: Configuraciones MFA por usuario
- **security_challenges**: Desafíos de seguridad
- **oauth_sessions**: Sesiones OAuth 2.0

### Servicios

#### Security Service (`src/services/security.ts`)
- **PKCE Implementation**: Generación y verificación de challenges
- **DPoP Support**: Creación y verificación de proofs
- **State/Nonce Generation**: Parámetros anti-CSRF y replay
- **Security Challenges**: Creación y verificación de desafíos
- **Encryption/Decryption**: Manejo seguro de datos sensibles
- **Password Hashing**: Hashing seguro con salt

#### OAuth Service (`src/services/oauth.ts`)
- **Complete OAuth 2.0 Flows**:
  - Authorization Code Flow con PKCE
  - Implicit Flow (no recomendado)
  - Client Credentials Flow
  - Resource Owner Password Credentials Flow
  - Refresh Token Flow con rotación
  - Device Authorization Flow
- **Token Management**: Generación, verificación y revocación
- **Client Management**: Creación, actualización y autenticación
- **Introspection**: Verificación de tokens
- **Revocation**: Revocación de tokens

#### Enhanced User Service (`src/services/enhanced-user.ts`)
- **Anonymous User Management**: Creación y promoción
- **Device Management**: Registro y confianza de dispositivos
- **Biometric Authentication**: Registro y verificación biométrica
- **MFA Management**: Configuración y validación MFA
- **Device Secrets**: SSO con secretos de dispositivo

#### JWT Service (Mejorado)
- **DPoP Support**: Verificación de proofs DPoP
- **OIDC Claims**: Tokens con claims estándar
- **Refresh Token Rotation**: Rotación automática y segura
- **Token Introspection**: Verificación completa de tokens

### Middleware (`src/middleware/oauth-security.ts`)
- **OAuth 2.0 Validation**: Validación completa de requests
- **Security Verification**: State, nonce, DPoP
- **Auditoría**: Logging de eventos de seguridad
- **Rate Limiting**: Límite de solicitudes
- **Suspicious Activity Detection**: Detección de patrones anómalos

## 🚀 Funcionalidades Implementadas

### 1. Fundamentos OAuth 2.0 (Alta Prioridad)

#### ✅ Authorization Code Flow con PKCE
```typescript
// Generar PKCE challenge
const pkceChallenge = securityService.generatePKCEChallenge(PKCEMethod.S256);

// Crear solicitud de autorización
const authRequest = {
  response_type: OAuthResponseType.CODE,
  client_id: "your-client-id",
  redirect_uri: "https://your-app.com/callback",
  scope: "read write profile",
  state: securityService.generateState(),
  code_challenge: pkceChallenge.code_challenge,
  code_challenge_method: pkceChallenge.code_challenge_method,
};

// Manejar solicitud
const authResponse = await oauthService.handleAuthorizationRequest(authRequest, user);
```

#### ✅ Token Management con Rotación
```typescript
// Generar access token
const tokenResponse = await oauthService.handleTokenRequest({
  grant_type: OAuthGrantType.AUTHORIZATION_CODE,
  code: authorizationCode,
  client_id: "your-client-id",
  client_secret: "your-client-secret",
  code_verifier: pkceChallenge.code_verifier,
});

// Rotación automática de refresh tokens
const newRefreshToken = await oauthService.rotateRefreshToken(oldRefreshTokenId, newToken);
```

#### ✅ Client Management
```typescript
// Crear cliente OAuth 2.0
const client = await oauthService.createClient({
  client_id: "your-client-id",
  client_secret: "your-client-secret",
  client_name: "Your Application",
  redirect_uris: ["https://your-app.com/callback"],
  grant_types: [OAuthGrantType.AUTHORIZATION_CODE, OAuthGrantType.REFRESH_TOKEN],
  response_types: [OAuthResponseType.CODE],
  scope: "read write profile",
});

// Autenticar cliente
const authenticatedClient = await oauthService.authenticateClient(
  "your-client-id", 
  "your-client-secret"
);
```

### 2. Seguridad Mejorada (Media Prioridad)

#### ✅ PKCE (RFC 7636)
- **S256 Method**: SHA256 con base64url encoding
- **Plain Method**: Para compatibilidad con clientes legacy
- **Automatic Verification**: Validación transparente en token exchange

#### ✅ DPoP (RFC 9449)
```typescript
// Generar DPoP proof
const dpopProof = await securityService.generateDPoPProof(
  "POST",
  "https://api.example.com/protected",
  privateKey,
  "jwk-thumbprint"
);

// Verificar DPoP en middleware
const dpopResult = await jwtService.verifyDPoPProof(
  dpopHeader,
  "POST",
  "https://api.example.com/protected"
);
```

#### ✅ State/Nonce Management
- **State Generation**: Strings criptográficamente seguras
- **Nonce Generation**: Para prevención de replay attacks
- **Automatic Validation**: Verificación en middleware

#### ✅ Security Challenges
```typescript
// Crear desafío CAPTCHA
const challenge = await securityService.createChallenge(
  ChallengeType.CAPTCHA,
  { expectedCode: "123456" },
  10 // expira en 10 minutos
);

// Verificar solución
const result = await securityService.verifyChallenge(challenge, {
  code: "123456"
});
```

### 3. Funcionalidades Avanzadas (Baja Prioridad)

#### ✅ Autenticación Biométrica
```typescript
// Registrar credencial biométrica
const biometricResult = await enhancedUserService.registerBiometricCredential(
  userId,
  BiometricType.FINGERPRINT,
  encryptedBiometricData,
  "device-123"
);

// Verificar autenticación biométrica
const authResult = await enhancedUserService.verifyBiometricCredential(
  userId,
  BiometricType.FINGERPRINT,
  providedBiometricData
);
```

#### ✅ Usuarios Anónimos con Promoción
```typescript
// Crear usuario anónimo
const anonymousUser = await enhancedUserService.createAnonymousUser({
  sessionId: "session-123",
  preferences: { theme: "dark" }
});

// Promocionar a usuario completo
const promotedUser = await enhancedUserService.promoteAnonymousUser(
  anonymousUser.anonymous_id,
  {
    email: "user@example.com",
    password: "SecurePassword123!"
  }
);
```

#### ✅ SSO Nativo con Device Secrets
```typescript
// Registrar dispositivo para SSO
const deviceResult = await enhancedUserService.registerDevice(
  userId,
  "device-unique-id",
  "iPhone 14 Pro",
  DeviceType.MOBILE
);

// Marcar como confiable para SSO
await enhancedUserService.trustDevice(userId, "device-unique-id");

// Verificar SSO con device secret
const ssoResult = await enhancedUserService.verifyDeviceSecret(
  "device-unique-id",
  "device-secret-stored-securely"
);
```

#### ✅ Sistema MFA Completo
```typescript
// Configurar MFA TOTP
const mfaResult = await enhancedUserService.setupMFA(
  userId,
  MFAType.TOTP,
  {
    secret: "JBSWY3DPEHPK3PXP", // Secreto TOTP
    is_primary: true
  }
);

// Obtener configuraciones MFA activas
const activeMFA = await enhancedUserService.getEnabledMFAConfigurations(userId);
```

## 🔐 Características de Seguridad

### Validación OAuth 2.0
- **Request Validation**: Validación completa de parámetros
- **Redirect URI Validation**: Verificación estricta de URIs
- **Scope Validation**: Validación de scopes solicitados
- **PKCE Enforcement**: PKCE requerido para clientes públicos
- **Grant Type Validation**: Validación de tipos de grant soportados

### Prevención de Ataques
- **CSRF Protection**: Parámetros state obligatorios
- **Replay Protection**: Nonces y validación temporal
- **Token Theft Prevention**: DPoP binding de tokens
- **Brute Force Protection**: Rate limiting y detección
- **Session Hijacking**: Binding de tokens a dispositivos

### Auditoría y Logging
- **Security Events**: Logging completo de eventos
- **Access Patterns**: Detección de patrones anómalos
- **Risk Scoring**: Evaluación automática de riesgo
- **Compliance Logging**: Logs para auditoría

## 📊 Endpoints HTTP

### OAuth 2.0 Endpoints
```
POST   /oauth2/authorize          # Authorization endpoint
POST   /oauth2/token             # Token endpoint
POST   /oauth2/device_authorize  # Device authorization
POST   /oauth2/introspect        # Token introspection
POST   /oauth2/revoke           # Token revocation
GET    /oauth2/jwks              # JSON Web Key Set
```

### Security Endpoints
```
POST   /api/challenge             # Create security challenge
POST   /api/challenge/verify     # Verify challenge solution
GET    /api/biometric/types       # Get supported biometric types
POST   /api/biometric/register    # Register biometric credential
POST   /api/biometric/verify      # Verify biometric authentication
GET    /api/devices               # Get user devices
POST   /api/devices/register       # Register new device
POST   /api/devices/trust         # Trust device for SSO
GET    /api/mfa                  # Get MFA configurations
POST   /api/mfa/setup            # Setup MFA
POST   /api/mfa/verify           # Verify MFA
DELETE /api/mfa/disable          # Disable MFA
```

## 🔄 Migración Gradual

### Fase 1: Fundamentos OAuth 2.0
1. **Tipos y Interfaces**: Definir tipos OAuth 2.0
2. **Base de Datos**: Extensiones para tablas OAuth
3. **Servicios**: Implementar OAuthService básico
4. **Middleware**: Validación OAuth 2.0

### Fase 2: Seguridad Mejorada
1. **PKCE**: Implementar completo soporte PKCE
2. **DPoP**: Añadir soporte para DPoP proofs
3. **Challenges**: Sistema de desafíos de seguridad
4. **Auditoría**: Logging y detección

### Fase 3: Funcionalidades Avanzadas
1. **Biométrica**: Autenticación biométrica completa
2. **SSO**: Device secrets y confianza
3. **MFA**: Sistema multi-factor completo
4. **Anónimos**: Usuarios anónimos con promoción

## 🧪 Ejemplo de Uso Completo

Ver `examples/oauth-usage-example.ts` para un ejemplo completo que demuestra:

1. Configuración de servicios OAuth 2.0
2. Creación de clientes OAuth 2.0
3. Flujo completo de Authorization Code con PKCE
4. Intercambio de código por token
5. Refresh token con rotación
6. Device Authorization Flow
7. Autenticación biométrica
8. SSO con device secrets
9. MFA TOTP
10. Detección de actividad sospechosa
11. Rate limiting
12. Auditoría completa

## 🔧 Configuración

### Variables de Entorno
```bash
# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key
JWT_ISSUER=https://your-auth-server.com
JWT_AUDIENCE=your-api

# OAuth 2.0 Configuration
OAUTH_DEFAULT_SCOPE=read write profile
OAUTH_ACCESS_TOKEN_LIFETIME=3600
OAUTH_REFRESH_TOKEN_LIFETIME=2592000

# Security Configuration
BIOMETRIC_ENCRYPTION_KEY=your-biometric-encryption-key
MFA_ISSUER=your-mfa-issuer
RATE_LIMIT_WINDOW=900
RATE_LIMIT_MAX=100
```

### Configuración de Base de Datos
```typescript
// Registrar extensiones OAuth
import { registerOAuthSchemaExtensions } from "./src/database/oauth-schema-extensions";

// Aplicar a configuración existente
registerOAuthSchemaExtensions();

// Inicializar con esquemas extendidos
await dbInitializer.initialize();
```

## 📚 Referencias y Estándares

### RFCs Implementadas
- **RFC 6749**: OAuth 2.0 Authorization Framework
- **RFC 7636**: PKCE (Proof Key for Code Exchange)
- **RFC 7009**: OAuth 2.0 Token Revocation
- **RFC 7662**: OAuth 2.0 Token Introspection
- **RFC 8628**: OAuth 2.0 Device Authorization Grant
- **RFC 9449**: DPoP (Demonstrating Proof of Possession)
- **OpenID Connect**: Core 1.0 Specification

### Estándares de Seguridad
- **OWASP OAuth 2.0 Security Cheat Sheet**
- **NIST SP 800-63B**: Digital Identity Guidelines
- **ISO/IEC 30107-3**: Biometric Performance Testing

## 🚀 Próximos Pasos

1. **Testing Suite**: Tests unitarios y de integración completos
2. **Documentation**: API docs con OpenAPI/Swagger
3. **Monitoring**: Métricas y alertas de seguridad
4. **Compliance**: Validación de cumplimiento normativo
5. **Performance**: Optimización de consultas y caching

## 🤝 Contribución

Para contribuir a esta implementación:

1. **Code Style**: Seguir las convenciones establecidas
2. **Testing**: Incluir tests con buena cobertura
3. **Documentation**: Documentar cambios y nuevas funcionalidades
4. **Security**: Reportar vulnerabilidades responsablemente
5. **Reviews**: Solicitar code review para cambios críticos

---

Esta implementación proporciona una base sólida y segura para sistemas OAuth 2.0 modernos, con todas las funcionalidades de seguridad recomendadas por los estándares actuales.
