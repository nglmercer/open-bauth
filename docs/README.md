# Framework-Agnostic Authentication Library - Documentation

## 📚 Overview

Detailed guides for advanced features.

See the main [README](../README.md) for basics and quick start.

## 🚀 Quick Navigation

### 🌟 For Beginners
- [**Main README**](../README.md) - Complete quick start guide
- [**Services**](./services.md) - Complete API of all services
- [**Middleware**](./middleware.md) - Framework-agnostic middleware

### 🔧 For Intermediate Developers
- [**Database Adapters**](./adapter-usage.md) - Custom database adapters
- [**OAuth 2.0**](./oauth-2.0-implementation.md) - Complete OAuth 2.0 implementation
- [**Logger**](./logger.md) - Flexible logging system

### 🏗️ For Advanced Users
- [**Database Extensions**](./database-extension-spec.md) - Schema extension specification
- [**Testing**](./testing.md) - Complete testing guide

### 🛠️ For Development
- [**Examples**](../examples/) - Code examples and integrations

## 📖 Guides

### 🔐 Authentication & Authorization
- [**Services**](./services.md) - Complete API of AuthService, JWTService, PermissionService, OAuthService, SecurityService, and EnhancedUserService
- [**Middleware**](./middleware.md) - Framework-agnostic middleware for authentication, authorization, and OAuth security
- [**OAuth 2.0**](./oauth-2.0-implementation.md) - Complete OAuth 2.0 and OpenID Connect implementation guide

### 🗄️ Database & Storage
- [**Database Adapters**](./adapter-usage.md) - Customizable database adapter system
- [**Database Extensions**](./database-extension-spec.md) - Specification for extending initial tables

### 🛠️ Development Tools
- [**Logger**](./logger.md) - Configurable and flexible logging system
- [**Testing**](./testing.md) - Running and writing tests guide

## 💻 Examples

### Framework Integrations
- [**Hono**](../examples/hono.ts) - Complete Hono example
- [**Express**](../examples/express.ts) - Express example (if available)
- [**Elysia**](../examples/elysia.ts) - Elysia example (if available)

### Feature Examples
- [**OAuth Usage**](../examples/oauth-usage-example.ts) - Complete OAuth 2.0 flow example
- [**Custom Adapter**](../examples/custom-adapter-example.ts) - Custom adapter example
- [**Seed Data**](../examples/seed.ts) - Database seeding example

### Controllers & Routes
- [**Auth Controller**](../examples/controllers/auth.controller.ts) - Authentication controller
- [**Product Controller**](../examples/controllers/product.controller.ts) - CRUD example
- [**OAuth Controller**](../examples/controllers/oauth/oauth.controller.ts) - OAuth controller

## 📋 Library Information

| Feature | Description |
|---------|-------------|
| **Version** | 1.3.2 |
| **Runtime** | Bun |
| **Database** | SQLite + adapters |
| **Authentication** | JWT + RBAC + OAuth 2.0 |
| **Middleware** | Framework-agnostic |
| **TypeScript** | Full type safety |
| **Testing** | 94% coverage |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Application Layer                      │
└─────────────────────┬───────────────────────────────────┘
                      │ Middleware Layer
┌─────────────────────▼───────────────────────────────────┐
│  Auth Middleware │ Permission │ OAuth Security │ Custom │
└─────────────────────┬───────────────────────────────────┘
                      │ Service Layer
┌─────────────────────▼───────────────────────────────────┐
│  AuthService │ JWTService │ PermissionService │ OAuthService │
└─────────────────────┬───────────────────────────────────┘
                      │ Database Layer
┌─────────────────────▼───────────────────────────────────┐
│  DatabaseInitializer │ BaseController │ Schema Extensions │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Quick Setup

### 1. Installation

```bash
# Install the library
bun add open-bauth

# Or clone the repository
git clone https://github.com/nglmercer/open-bauth.git
```

### 2. Database Initialization

```typescript
import { DatabaseInitializer } from 'open-bauth';

const dbInitializer = new DatabaseInitializer({ database: db });
await dbInitializer.initialize();
await dbInitializer.seedDefaults();
```

### 3. Service Creation

```typescript
import { createServices } from 'open-bauth/src/services/service-factory';

const services = await createServices({
  database: db,
  jwtSecret: 'your-secret-key',
  jwtExpiration: '24h'
});
```

### 4. Middleware Setup

```typescript
import { createAuthMiddleware } from 'open-bauth/src/middleware/auth';

const authMw = createAuthMiddleware({ 
  jwtService: services.jwtService,
  authService: services.authService,
  permissionService: services.permissionService 
});
```

## 🎯 Core Features

### 🔐 Authentication & Authorization

- **JWT-based authentication** with secure token generation
- **Role-Based Access Control (RBAC)** with flexible permissions
- **Complete OAuth 2.0** implementation with all standard flows
- **Enhanced user features**: MFA, biometrics, device management
- **Multi-factor authentication** support with various methods

### 🗄️ Database System

- **SQLite by default** with Bun runtime optimization
- **Custom adapter system** for PostgreSQL, MySQL, and custom databases
- **Schema extensions** for custom table definitions
- **Automatic migrations** with rollback support
- **Advanced querying** with complex filtering and pagination

### 🛡️ Security Features

- **PKCE support** (RFC 7636) for public clients
- **DPoP implementation** (RFC 9449) for token binding
- **Rate limiting** with multiple strategies
- **Security challenges** for additional verification
- **Audit logging** for compliance and monitoring

### 🌐 Framework Integration

- **Framework-agnostic middleware** for Hono, Express, Elysia, Fastify
- **Type-safe interfaces** for all framework integrations
- **Context injection** for request-scoped data
- **Error handling** with consistent responses

## 📊 Performance & Monitoring

### Built-in Metrics

- **Query performance tracking** with execution times
- **Authentication metrics** for login attempts and success rates
- **Database connection pooling** for optimal performance
- **Memory usage monitoring** for resource optimization

### Logging System

- **Structured logging** with JSON and text formats
- **Log rotation** based on size and time
- **Multiple outputs** (console, file, external services)
- **Performance-optimized** with minimal overhead

## 🧪 Testing

### Comprehensive Test Suite

- **94% code coverage** across all features
- **Integration tests** for complete workflows
- **Unit tests** for individual components
- **Performance tests** for load handling
- **Security tests** for vulnerability prevention

### Test Categories

- **Service tests**: Auth, JWT, permissions, OAuth, security
- **Database tests**: Schema extensions, migrations, adapters
- **Middleware tests**: Authentication, authorization, security
- **End-to-end tests**: Complete user journeys
- **Edge case tests**: Error handling and boundary conditions

## 🔧 Configuration

### Environment-Based Setup

```typescript
import { setDatabaseConfig } from 'open-bauth';

// Development configuration
setDatabaseConfig({
  schemaExtensions: {
    users: SchemaExtensions.addUserProfileFields()
  },
  tableNames: {
    users: "dev_users"
  }
});

// Production configuration
setDatabaseConfig({
  schemaExtensions: {
    users: SchemaExtensions.addAuditFields()
  },
  tableNames: {
    users: "app_users"
  }
});
```

### Service Configuration

```typescript
import { createServices } from 'open-bauth/src/services/service-factory';

const services = await createServices({
  database: db,
  jwtSecret: process.env.JWT_SECRET,
  jwtExpiration: '24h',
  bcryptRounds: 12,
  enableRateLimiting: true,
  enableAuditLogging: true
});
```

## 🚀 Advanced Usage Examples

### Complete OAuth 2.0 Implementation

```typescript
import { OAuthService, SecurityService } from 'open-bauth';

const oauthService = new OAuthService(dbInitializer, securityService, jwtService);

// Create OAuth client
const client = await oauthService.createClient({
  client_id: 'my-app',
  client_name: 'My Application',
  redirect_uris: ['https://myapp.com/callback'],
  grant_types: [OAuthGrantType.AUTHORIZATION_CODE, OAuthGrantType.REFRESH_TOKEN],
  response_types: [OAuthResponseType.CODE],
  scope: 'read write profile'
});

// Handle authorization flow
const authResponse = await oauthService.handleAuthorizationRequest({
  response_type: OAuthResponseType.CODE,
  client_id: 'my-app',
  redirect_uri: 'https://myapp.com/callback',
  scope: 'read write',
  state: securityService.generateState(),
  code_challenge: pkceChallenge.code_challenge,
  code_challenge_method: PKCEMethod.S256
}, user);
```

### Custom Database Adapter

```typescript
import { IDatabaseAdapter, AdapterFactory } from 'open-bauth';

class PostgreSQLAdapter implements IDatabaseAdapter {
  // Implementation details...
}

const adapter = AdapterFactory.createWithClass(PostgreSQLAdapter, {
  host: 'localhost',
  port: 5432,
  database: 'auth_db'
});
```

### Advanced Middleware Usage

```typescript
import { createOAuthSecurityMiddleware } from 'open-bauth/src/middleware/oauth-security';

const oauthSecurity = createOAuthSecurityMiddleware(
  oauthService,
  securityService,
  jwtService
);

// Apply to routes with comprehensive security
app.use('/oauth/*', oauthSecurity);
```

## 🎯 Best Practices

### Security

1. **Always use HTTPS** in production environments
2. **Validate all inputs** with proper sanitization
3. **Implement rate limiting** for sensitive endpoints
4. **Use secure defaults** for cryptographic operations
5. **Log security events** for audit and monitoring

### Performance

1. **Use connection pooling** for database operations
2. **Implement caching** for frequently accessed data
3. **Optimize queries** with proper indexes
4. **Use lazy loading** for expensive operations
5. **Monitor performance** with built-in metrics

### Development

1. **Write comprehensive tests** for all features
2. **Use TypeScript** for type safety
3. **Follow established patterns** for consistency
4. **Document custom extensions** clearly
5. **Test migrations** in staging environments

## 📚 Documentation Structure

```
docs/
├── README.md                    # This file - documentation overview
├── services.md                  # Complete API documentation
├── middleware.md                # Framework-agnostic middleware
├── adapter-usage.md             # Database adapter system
├── database-extension-spec.md     # Schema extension specification
├── oauth-2.0-implementation.md  # OAuth 2.0 implementation guide
├── logger.md                    # Logging system documentation
└── testing.md                   # Testing guide and best practices
```

## 🤝 Contributing

We welcome contributions! Please see the [main README](../README.md) for contribution guidelines.

### Areas for Contribution

1. **Core Services**: Authentication, authorization, OAuth features
2. **Database Layer**: Adapters, extensions, migrations
3. **Middleware**: Framework integrations and security
4. **Documentation**: Guides, examples, and API reference
5. **Testing**: Test coverage and new test scenarios

### Contribution Process

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Update documentation
5. Submit a pull request with detailed description

## 📞 Support & Community

### Getting Help

- **Documentation**: Start with the [main README](../README.md)
- **Issues**: Report bugs via [GitHub Issues](https://github.com/nglmercer/open-bauth/issues)
- **Discussions**: Join [GitHub Discussions](https://github.com/nglmercer/open-bauth/discussions)
- **Examples**: See [examples/](../examples/) directory

### Community Resources

- **GitHub Repository**: [https://github.com/nglmercer/open-bauth](https://github.com/nglmercer/open-bauth)
- **Documentation Website**: [https://nglmercer.github.io/Open_Bauth/](https://nglmercer.github.io/Open_Bauth/) 
- **NPM Package**: [https://www.npmjs.com/package/open-bauth](https://www.npmjs.com/package/open-bauth)