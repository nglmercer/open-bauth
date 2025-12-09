/**
 * OAuth 2.0 Refactored Router Example
 *
 * This is a cleaned up version of the original OAuth router implementation
 * with better error handling, structure, and maintainability
 */

import { Hono } from "hono";
import { z } from "zod";
import { DatabaseInitializer } from "../src/database/database-initializer";
import { Database } from "bun:sqlite";
import { JWTService } from "../src/services/jwt";
import { AuthService } from "../src/services/auth";
import { PermissionService } from "../src/services/permissions";
import { OAuthService } from "../src/services/oauth";
import { SecurityService } from "../src/services/security";
import { createAuthMiddlewareForHono } from "./middleware/auth.middleware";
import { PKCEMethod, OAuthGrantType, OAuthResponseType } from "../src/types/oauth";
import { defaultLogger } from "../src/logger";
import { OAuthErrorType } from "../src/types/oauth";
import { registerOAuthSchemaExtensions } from "../src/database/schema/oauth-schema-extensions";

// Initialize services
const db = new Database(":memory:");

// Get OAuth schemas
const { getOAuthSchemas } = await import("../src/database/schema/oauth-schema-extensions");
const oauthSchemas = getOAuthSchemas();

const dbInitializer = new DatabaseInitializer({
  database: db,
  externalSchemas: oauthSchemas
});

// Initialize database
await dbInitializer.initialize();

// Initialize services
const jwtService = new JWTService("your-super-secret-jwt-key");
const securityService = new SecurityService();
const authService = new AuthService(dbInitializer, jwtService);
const permissionService = new PermissionService(dbInitializer);
const oauthService = new OAuthService(dbInitializer, securityService, jwtService, authService);

// Services container
const services = {
  jwtService,
  authService,
  permissionService,
  securityService,
  oauthService,
};

export const oauth = new Hono();

// Validation schemas
const authorizationSchema = z.object({
  response_type: z.enum(["code", "token"]),
  client_id: z.string(),
  redirect_uri: z.string().url(),
  scope: z.string().optional(),
  state: z.string().optional(),
  code_challenge: z.string().optional(),
  code_challenge_method: z.enum(["S256", "plain"]).optional(),
  nonce: z.string().optional()
});

const tokenSchema = z.object({
  grant_type: z.enum(["authorization_code", "refresh_token", "client_credentials", "password"]),
  code: z.string().optional(),
  refresh_token: z.string().optional(),
  client_id: z.string(),
  client_secret: z.string().optional(),
  redirect_uri: z.string().url().optional(),
  code_verifier: z.string().optional(),
  username: z.string().optional(),
  password: z.string().optional(),
  scope: z.string().optional()
});

const introspectionSchema = z.object({
  token: z.string(),
  token_type_hint: z.enum(["access_token", "refresh_token"]).optional()
});

const revocationSchema = z.object({
  token: z.string(),
  token_type_hint: z.enum(["access_token", "refresh_token"]).optional()
});

// GET /api/v1/oauth/authorize - OAuth authorization endpoint
oauth.get("/authorize", async (c) => {
  try {
    const query = c.req.query();
    const validated = authorizationSchema.parse(query);

    // Verify client
    const client = oauthService ? await oauthService.findClientByClientId(validated.client_id) : null;
    if (!client || !client.is_active) {
      return c.json({
        error: "invalid_client",
        error_description: "Client not found or inactive"
      }, 400);
    }

    // Verify redirect URI
    const redirectUris = Array.isArray(client.redirect_uris)
      ? client.redirect_uris
      : JSON.parse(client.redirect_uris || '[]');

    if (!redirectUris.includes(validated.redirect_uri)) {
      return c.json({
        error: "invalid_request",
        error_description: "Invalid redirect URI not registered for this client"
      }, 400);
    }

    // Handle different response types
    if (validated.response_type === "code") {
      return await handleAuthorizationCodeFlow(validated, client, c);
    } else if (validated.response_type === "token") {
      return await handleImplicitFlow(validated, client, c);
    }

    return c.json({
      error: "unsupported_response_type",
      error_description: "Response type not supported"
    }, 400);

  } catch (error) {
    return handleAuthorizationError(error, c);
  }
});

// POST /api/v1/oauth/token - OAuth token endpoint
oauth.post("/token", async (c) => {
  try {
    const body = await c.req.parseBody();
    const validated = tokenSchema.parse(body);

    // Client authentication
    const client = await authenticateClient(validated.client_id, validated.client_secret);
    if (!client) {
      return c.json({
        error: "invalid_client",
        error_description: "Client authentication failed"
      }, 401);
    }

    // Handle different grant types
    let result;
    switch (validated.grant_type) {
      case "authorization_code":
        result = await handleAuthorizationCodeGrant(validated, client);
        break;
      case "refresh_token":
        result = await handleRefreshTokenGrant(validated, client);
        break;
      case "client_credentials":
        result = await handleClientCredentialsGrant(validated, client);
        break;
      case "password":
        result = await handlePasswordGrant(validated, client);
        break;
      default:
        return c.json({
          error: "unsupported_grant_type",
          error_description: "Grant type not supported"
        }, 400);
    }

    // Check if result contains an error
    if (result.error) {
      return c.json(result, 400);
    }

    return c.json(result);

  } catch (error) {
    return handleTokenError(error, c);
  }
});

// POST /api/v1/oauth/revoke - Revoke token
oauth.post("/revoke", async (c) => {
  try {
    const body = await c.req.parseBody();
    const validated = revocationSchema.parse(body);

    // Try to revoke token (access or refresh)
    await revokeToken(validated.token);

    // OAuth spec requires 200 OK even if token was not found
    return c.json({ success: true });

  } catch (error) {
    defaultLogger.error("Token revocation error", error as Error);
    return c.json({ success: true }); // Always return success per OAuth spec
  }
});

// POST /api/v1/oauth/introspect - Introspect token
oauth.post("/introspect", async (c) => {
  try {
    const body = await c.req.parseBody();
    const validated = introspectionSchema.parse(body);

    const tokenInfo = await introspectToken(validated.token, validated.token_type_hint);
    return c.json(tokenInfo);

  } catch (error) {
    defaultLogger.error("Token introspection error", error as Error);
    return c.json({ active: false });
  }
});

// GET /api/v1/oauth/jwks - JSON Web Key Set
oauth.get("/jwks", async (c) => {
  try {
    return c.json({
      keys: [
        {
          kty: "RSA",
          kid: "default",
          use: "sig",
          alg: "RS256",
          n: "placeholder",
          e: "AQAB"
        }
      ]
    });
  } catch (error) {
    defaultLogger.error("JWKS error", error as Error);
    return c.json({
      error: "server_error",
      error_description: "Failed to retrieve keys"
    }, 500);
  }
});

// GET /api/v1/oauth/userinfo - OIDC UserInfo endpoint
oauth.get("/userinfo", createAuthMiddlewareForHono(services), async (c) => {
  try {
    const auth = (c as any).auth;
    const user = auth.user;
    const scopes = auth.permissions || [];

    const userInfo = buildUserInfo(user, scopes);
    return c.json(userInfo);

  } catch (error) {
    defaultLogger.error("UserInfo error", error as Error);
    return c.json({
      error: "server_error",
      error_description: "Failed to retrieve user info"
    }, 500);
  }
});

// Helper Functions

async function handleAuthorizationCodeFlow(validated: any, client: any, c: any) {
  // Generate authorization code
  const generatedCode = securityService ? await securityService.generateSecureToken(32) : Math.random().toString(36).substring(2, 15);
  
  // Get or create test user
  const userId = await getOrCreateTestUser();
  
  // Create authorization code
  const authCode = oauthService ? await oauthService.createAuthCode({
    code: generatedCode,
    client_id: validated.client_id,
    user_id: userId,
    redirect_uri: validated.redirect_uri,
    scope: validated.scope || "",
    expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(), // 10 minutes
    code_challenge: validated.code_challenge || "",
    code_challenge_method: (validated.code_challenge_method || PKCEMethod.S256),
    state: validated.state || "",
    nonce: validated.nonce || ""
  }) : null;

  if (authCode) {
    defaultLogger.info("Authorization code created", {
      code: authCode.code,
      id: authCode.id,
      client_id: authCode.client_id
    });

    // Build redirect URL
    const redirectUrl = new URL(validated.redirect_uri);
    redirectUrl.searchParams.set("code", authCode.code);
  if (validated.state) {
    redirectUrl.searchParams.set("state", validated.state);
  }

    return redirectUrl.toString();
  }
  
  throw new Error("Failed to create authorization code");
}

async function handleImplicitFlow(validated: any, client: any, c: any) {
  // Generate access token directly
  const accessToken = await services.jwtService.generateToken({
    id: "simulated-user-id",
    email: "user@example.com",
    username: "simulated-user",
    first_name: "Simulated",
    last_name: "User",
    is_active: true,
    roles: []
  });

  // Build redirect URL with fragment
  const redirectUrl = new URL(validated.redirect_uri);
  redirectUrl.hash = `access_token=${accessToken}&token_type=Bearer&expires_in=3600`;
  if (validated.state) {
    redirectUrl.hash += `&state=${validated.state}`;
  }

  return redirectUrl.toString();
}

async function authenticateClient(clientId: string, clientSecret?: string) {
  const client = oauthService ? await oauthService.findClientByClientId(clientId) : null;
  
  if (!client || !client.is_active) {
    return null;
  }

  // Public clients don't need authentication
  if (client.is_public) {
    return client;
  }

  // Private clients need secret verification
  if (!clientSecret || !client.client_secret) {
    return null;
  }

  return await verifyClientSecret(client, clientSecret);
}

async function verifyClientSecret(client: any, clientSecret: string) {
  try {
    // Try Bun.password.verify first
    const isValid = await Bun.password.verify(clientSecret, client.client_secret);
    return isValid ? client : null;
  } catch (bunError) {
    defaultLogger.error("Bun.password.verify failed", bunError as Error);
    
    // Fallback to bcrypt
    try {
      const bcrypt = await import('bcrypt');
      const isValid = await bcrypt.compare(clientSecret, client.client_secret);
      return isValid ? client : null;
    } catch (bcryptError) {
      defaultLogger.error("bcrypt comparison failed", bcryptError as Error);
      return null;
    }
  }
}

async function handleAuthorizationCodeGrant(validated: any, client: any) {
  if (!validated.code || !validated.redirect_uri) {
    return {
      error: "invalid_grant",
      error_description: "Missing required parameters"
    };
  }

  // Verify authorization code
  const authCode = oauthService ? await oauthService.findAuthCodeByCode(validated.code) : null;
  
  if (!authCode || authCode.is_used || new Date() > new Date(authCode.expires_at)) {
    return {
      error: "invalid_grant",
      error_description: "Invalid or expired authorization code"
    };
  }

  // Validate client and redirect URI
  if (authCode.client_id !== client.client_id) {
    return {
      error: "invalid_grant",
      error_description: "Authorization code was issued for a different client"
    };
  }

  if (validated.redirect_uri !== authCode.redirect_uri) {
    return {
      error: "invalid_grant",
      error_description: "Redirect URI does not match the authorization request"
    };
  }

  // Verify PKCE if present
  if (authCode.code_challenge && validated.code_verifier) {
    const isValid = securityService ? securityService.verifyPKCEChallenge(
      validated.code_verifier,
      authCode.code_challenge,
      authCode.code_challenge_method || PKCEMethod.S256
    ) : false;

    if (!isValid) {
      return {
        error: "invalid_grant",
        error_description: "PKCE verification failed"
      };
    }
  }

  // Get user
  const user = await services.authService.findUserById(authCode.user_id);
  if (!user || !user.is_active) {
    return {
      error: "invalid_grant",
      error_description: "User not found or inactive"
    };
  }

  // Mark authorization code as used
  if (oauthService) await oauthService.markAuthCodeAsUsed(authCode.id);

  // Generate tokens
  const accessToken = await services.jwtService.generateToken(user);
  const refreshToken = await services.jwtService.generateRefreshToken(user.id);

  // Create refresh token record
  await createRefreshTokenRecord(refreshToken, user.id, client.client_id, authCode.scope);

  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: refreshToken,
    scope: authCode.scope
  };
}

async function handleRefreshTokenGrant(validated: any, client: any) {
  if (!validated.refresh_token) {
    return {
      error: "invalid_request",
      error_description: "Missing refresh token"
    };
  }

  // Verify refresh token
  const refreshToken = oauthService ? await oauthService.findRefreshTokenByToken(validated.refresh_token) : null;
  
  if (!refreshToken || refreshToken.is_revoked || new Date() > new Date(refreshToken.expires_at)) {
    return {
      error: "invalid_grant",
      error_description: "Invalid or expired refresh token"
    };
  }

  // Validate client
  if (client.client_id !== refreshToken.client_id) {
    return {
      error: "invalid_client",
      error_description: "Client mismatch for refresh token"
    };
  }

  // Get user
  const user = await services.authService.findUserById(refreshToken.user_id);
  if (!user || !user.is_active) {
    return {
      error: "invalid_grant",
      error_description: "User not found or inactive"
    };
  }

  // Generate new access token
  const accessToken = await services.jwtService.generateToken(user);

  // Rotate refresh token if configured
  if (process.env['ENABLE_REFRESH_TOKEN_ROTATION'] === "true") {
    const newRefreshToken = await services.jwtService.generateRefreshToken(user.id);
    
    // Revoke old refresh token
    if (oauthService) await oauthService.revokeRefreshToken(refreshToken.id);
    
    // Create new refresh token record
    await createRefreshTokenRecord(newRefreshToken, user.id, client.client_id, refreshToken.scope);

    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: newRefreshToken,
      scope: validated.scope || refreshToken.scope
    };
  }

  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    scope: validated.scope || refreshToken.scope
  };
}

async function handleClientCredentialsGrant(validated: any, client: any) {
  if (client.is_public) {
    return {
      error: "unauthorized_client",
      error_description: "Public clients cannot use client credentials grant"
    };
  }

  // Generate access token for client
  const accessToken = await services.jwtService.generateToken({
    id: client.client_id,
    email: `${client.client_id}@client.local`,
    username: client.client_name,
    first_name: "Client",
    last_name: "Application",
    is_active: true,
    roles: []
  });

  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    scope: validated.scope || client.scope
  };
}

async function handlePasswordGrant(validated: any, client: any) {
  if (!validated.username || !validated.password) {
    return {
      error: "invalid_request",
      error_description: "Missing username or password"
    };
  }

  // Authenticate user
  let loginResult;
  try {
    loginResult = await services.authService.login({
      email: validated.username,
      password: validated.password
    });
  } catch (error) {
    defaultLogger.error("Password grant authentication error", error as Error);
    return {
      error: "invalid_grant",
      error_description: "Invalid credentials"
    };
  }

  if (!loginResult.success) {
    return {
      error: "invalid_grant",
      error_description: "Invalid credentials"
    };
  }

  // Generate tokens
  const accessToken = await services.jwtService.generateToken(loginResult.user!);
  const refreshToken = await services.jwtService.generateRefreshToken(loginResult.user!.id);

  // Create refresh token record
  await createRefreshTokenRecord(refreshToken, loginResult.user!.id, client.client_id, validated.scope || "");

  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: refreshToken,
    scope: validated.scope || ""
  };
}

async function revokeToken(token: string) {
  // Try to revoke as access token first
  try {
    const accessToken = await services.jwtService.verifyToken(token);
    if (accessToken) {
      // In a real implementation, you would maintain a token blacklist
      // Token revoked successfully
    }
  } catch (error) {
    // Not a valid access token, try refresh token
    const refreshToken = oauthService ? await oauthService.findRefreshTokenByToken(token) : null;
    if (refreshToken) {
      if (oauthService) await oauthService.revokeRefreshToken(refreshToken.id);
    }
  }
}

async function introspectToken(token: string, tokenTypeHint?: string) {
  // Try to introspect as access token first
  try {
    const payload = await services.jwtService.verifyToken(token);
    return {
      active: true,
      scope: (payload as any).scope || "",
      client_id: (payload as any).client_id,
      username: (payload as any).email,
      token_type: "Bearer",
      exp: (payload as any).exp,
      iat: (payload as any).iat,
      sub: (payload as any).sub,
      aud: (payload as any).aud,
      iss: (payload as any).iss,
      jti: (payload as any).jti
    };
  } catch (error) {
    // Not a valid access token, try refresh token
    const refreshToken = oauthService ? await oauthService.findRefreshTokenByToken(token) : null;
    if (refreshToken && !refreshToken.is_revoked && new Date() <= new Date(refreshToken.expires_at)) {
      return {
        active: true,
        scope: refreshToken.scope,
        client_id: refreshToken.client_id,
        token_type: "Bearer",
        exp: Math.floor(new Date(refreshToken.expires_at).getTime() / 1000),
        sub: refreshToken.user_id
      };
    }
  }

  return { active: false };
}

async function createRefreshTokenRecord(token: string, userId: string, clientId: string, scope: string) {
  const refreshTokenRecord = {
    token: token,
    user_id: userId,
    client_id: clientId,
    scope: scope,
    expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days
    is_revoked: false,
    id: `rt-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
  };

  if (oauthService) await oauthService.createRefreshToken(refreshTokenRecord);
}

async function getOrCreateTestUser() {
  try {
    // First try to find an existing test user
    const testUsers = await services.authService.getUsers(1, 10, { search: "oauth-test@example.com" });
    
    if (testUsers.users && testUsers.users.length > 0) {
      return testUsers.users[0].id;
    }
    
    // Create a test user for OAuth flows
    const registerResult = await services.authService.register({
      email: "oauth-test@example.com",
      password: "test-password-123",
      username: "oauth-test-user",
      first_name: "OAuth",
      last_name: "Test User"
    });
    
    if (registerResult.success && registerResult.user) {
      return registerResult.user.id;
    }
    
    throw new Error("Failed to create test user");
  } catch (error) {
    defaultLogger.error("Could not create/find test user", error as Error);
    throw error;
  }
}

function buildUserInfo(user: any, scopes: string[]) {
  const userInfo: any = { sub: user.id };

  if (scopes.includes("profile")) {
    userInfo.name = `${user.first_name || ""} ${user.last_name || ""}`.trim();
    userInfo.given_name = user.first_name;
    userInfo.family_name = user.last_name;
    userInfo.preferred_username = user.username;
    userInfo.picture = user.avatar_url;
    userInfo.zoneinfo = user.timezone;
    userInfo.locale = user.language;
  }

  if (scopes.includes("email")) {
    userInfo.email = user.email;
    userInfo.email_verified = user.is_active;
  }

  if (scopes.includes("phone")) {
    userInfo.phone_number = user.phone_number;
    userInfo.phone_number_verified = false;
  }

  return userInfo;
}

function handleAuthorizationError(error: any, c: any) {
  if (error instanceof z.ZodError) {
    return c.json({
      error: "invalid_request",
      error_description: "Invalid request parameters",
      details: (error as any).errors
    }, 400);
  }

  defaultLogger.error("Authorization error", error);
  return c.json({
    error: "server_error",
    error_description: "Internal server error"
  }, 500);
}

function handleTokenError(error: any, c: any) {
  if (error instanceof z.ZodError) {
    return c.json({
      error: "invalid_request",
      error_description: "Invalid request parameters",
      details: (error as any).errors
    }, 400);
  }

  defaultLogger.error("Token error", error);
  return c.json({
    error: "server_error",
    error_description: "Internal server error"
  }, 500);
}

export { oauth as oauthRoutes };

// Main function to test the OAuth router
async function main() {
  console.log("🚀 Testing OAuth 2.0 Refactored Router Example...");
  
  try {
    // Create a test client
    const testClient = await oauthService.createClient({
      client_id: "test-client",
      client_secret: "test-secret",
      client_name: "Test Client",
      redirect_uris: ["https://example.com/callback"],
      grant_types: [OAuthGrantType.AUTHORIZATION_CODE, OAuthGrantType.REFRESH_TOKEN],
      response_types: [OAuthResponseType.CODE],
      scope: "read write",
      is_public: false,
      is_active: true
    });
    
    console.log("✅ Test client created:", testClient.client_id);
    
    
  } catch (error) {
    console.error("❌ Error testing OAuth router:", error);
  }
}

// Run if executed directly
if (import.meta.main) {
  main();
}