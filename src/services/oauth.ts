// src/services/oauth.ts

import type { DatabaseInitializer } from "../database/database-initializer";
import type { BaseController } from "../database/base-controller";
import type { User } from "../types/auth";
import {
  OAuthClient,
  CreateOAuthClientData,
  UpdateOAuthClientData,
  AuthorizationCode,
  RefreshToken,
  AuthorizationRequest,
  AuthorizationResponse,
  TokenRequest,
  TokenResponse,
  DeviceAuthorizationRequest,
  DeviceAuthorizationResponse,
  IntrospectionRequest,
  IntrospectionResponse,
  RevocationRequest,
  OAuthContext,
  OAuthErrorType,
  OAuthGrantType,
  OAuthResponseType,
  TokenEndpointAuthMethod,
  OAuthJWTPayload,
  PKCEMethod,
} from "../types/oauth";
import { SecurityService } from "./security";
import { JWTService } from "./jwt";
import { AuthService } from "./auth";
import { ServiceErrors } from "./constants";

/**
 * OAuth 2.0 Service for handling complete OAuth 2.0 flows
 */
export class OAuthService {
  private clientController: BaseController<OAuthClient>;
  private authCodeController: BaseController<AuthorizationCode>;
  private refreshTokenController: BaseController<RefreshToken>;
  private securityService: SecurityService;
  private jwtService: JWTService;
  private authService: AuthService;

  constructor(
    dbInitializer: DatabaseInitializer,
    securityService: SecurityService,
    jwtService: JWTService,
    authService: AuthService,
  ) {
    this.clientController =
      dbInitializer.createController<OAuthClient>("oauth_clients");
    this.authCodeController = dbInitializer.createController<AuthorizationCode>(
      "authorization_codes",
    );
    this.refreshTokenController =
      dbInitializer.createController<RefreshToken>("refresh_tokens");
    this.securityService = securityService;
    this.jwtService = jwtService;
    this.authService = authService;
  }

  // --- OAuth Client Management ---

  async findAllClients(): Promise<OAuthClient[]> {
    const result = await this.clientController.findAll();
    return result.data || [];
  }

  async findClientById(id: string): Promise<OAuthClient | null> {
    const result = await this.clientController.findById(id);
    return result.data || null;
  }

  async findClientByClientId(clientId: string): Promise<OAuthClient | null> {
    const result = await this.clientController.findFirst({
      client_id: clientId,
    });
    return result.data || null;
  }

  async createClient(data: CreateOAuthClientData): Promise<OAuthClient> {
    // Hash client secret if provided and not already hashed
    let clientSecret = data.client_secret;
    let clientSecretSalt = "";

    if (clientSecret) {
      // Check if the secret looks like it's already hashed (bcrypt format)
      const isAlreadyHashed = clientSecret.startsWith('$2') || clientSecret.length > 60;

      if (!isAlreadyHashed) {
        // Hash the plain text secret
        const { hash, salt } = await this.securityService.hashPassword(clientSecret);
        clientSecret = hash;
        clientSecretSalt = salt;
      } else {
        // Secret is already hashed, extract salt if possible
        // For bcrypt, the salt is embedded in the hash, so we'll store it as is
        clientSecretSalt = ""; // Salt is embedded in bcrypt hash
      }
    }

    const result = await this.clientController.create({
      ...data,
      client_secret: clientSecret,
      client_secret_salt: clientSecretSalt,
      grant_types: JSON.stringify(
        data.grant_types || [OAuthGrantType.AUTHORIZATION_CODE],
      ),
      response_types: JSON.stringify(
        data.response_types || [OAuthResponseType.CODE],
      ),
      redirect_uris: JSON.stringify(data.redirect_uris),
      token_endpoint_auth_method:
        data.token_endpoint_auth_method ||
        TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
      is_active: data.is_active !== undefined ? data.is_active : true,
    });

    if (!result.success || !result.data) {
      const errorMessage = typeof result.error === 'string' ? result.error : (result.error as any)?.message || 'Unknown error';
      throw new Error(`${ServiceErrors.CLIENT_CREATE_FAILED}: ${errorMessage}`);
    }

    return result.data;
  }

  async updateClient(
    id: string,
    data: UpdateOAuthClientData,
  ): Promise<OAuthClient> {
    // Hash client secret if provided
    let updateData: any = { ...data };
    if ((data as any).client_secret) {
      const { hash, salt } = await this.securityService.hashPassword(
        (data as any).client_secret,
      );
      updateData.client_secret = hash;
      updateData.client_secret_salt = salt;
    }

    if (data.grant_types) {
      updateData.grant_types = JSON.stringify(data.grant_types);
    }

    if (data.response_types) {
      updateData.response_types = JSON.stringify(data.response_types);
    }

    if (data.redirect_uris) {
      updateData.redirect_uris = JSON.stringify(data.redirect_uris);
    }

    const result = await this.clientController.update(id, updateData);

    if (!result.success || !result.data) {
      throw new Error(ServiceErrors.CLIENT_UPDATE_FAILED);
    }

    return result.data;
  }

  async deleteClient(id: string): Promise<boolean> {
    const result = await this.clientController.delete(id);
    return result.success;
  }

  async authenticateClient(
    clientId: string,
    clientSecret?: string,
  ): Promise<OAuthClient | null> {
    const client = await this.findClientByClientId(clientId);

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

    let isValid: boolean;

    // Check if the stored secret is already hashed (bcrypt format)
    if (client.client_secret.startsWith('$2')) {
      // Use Bun's built-in password verification only
      try {
        isValid = await Bun.password.verify(clientSecret, client.client_secret);
      } catch (bunError) {
        console.error('Bun.password.verify failed:', bunError);
        return null;
      }
    } else {
      // Use the security service for other hashing methods
      isValid = await this.securityService.verifyPassword(
        clientSecret,
        client.client_secret,
        (client as any).client_secret_salt || "",
      );
    }

    return isValid ? client : null;
  }

  async validateRedirectUri(
    clientId: string,
    redirectUri: string,
  ): Promise<boolean> {
    const client = await this.findClientByClientId(clientId);

    if (!client) {
      return false;
    }

    const redirectUris = JSON.parse((client as any).redirect_uris || "[]");
    return redirectUris.includes(redirectUri);
  }

  // --- Authorization Code Management ---

  async findAuthCodeById(id: string): Promise<AuthorizationCode | null> {
    const result = await this.authCodeController.findById(id);
    return result.data || null;
  }

  async findAuthCodeByCode(code: string): Promise<AuthorizationCode | null> {
    const result = await this.authCodeController.findFirst({ code });
    return result.data || null;
  }

  async createAuthCode(
    data: Partial<AuthorizationCode>,
  ): Promise<AuthorizationCode> {
    const code = this.securityService.generateSecureToken(64);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    const result = await this.authCodeController.create({
      code,
      client_id: data.client_id!,
      user_id: data.user_id!,
      redirect_uri: data.redirect_uri!,
      scope: data.scope || "",
      state: data.state,
      nonce: data.nonce,
      code_challenge: data.code_challenge,
      code_challenge_method: data.code_challenge_method,
      expires_at: expiresAt.toISOString(),
      is_used: false,
    });

    if (!result.success || !result.data) {
      throw new Error(ServiceErrors.AUTH_CODE_CREATE_FAILED);
    }

    return result.data;
  }

  async markAuthCodeAsUsed(id: string): Promise<boolean> {
    const result = await this.authCodeController.update(id, {
      is_used: true,
      used_at: new Date().toISOString(),
    });

    return result.success;
  }

  async deleteAuthCode(id: string): Promise<boolean> {
    const result = await this.authCodeController.delete(id);
    return result.success;
  }

  async cleanupExpiredAuthCodes(): Promise<number> {
    // This would require a custom query implementation
    // For now, return 0 as a placeholder
    return 0;
  }

  // --- Refresh Token Management ---

  async findRefreshTokenById(id: string): Promise<RefreshToken | null> {
    const result = await this.refreshTokenController.findById(id);
    return result.data || null;
  }

  async findRefreshTokenByToken(token: string): Promise<RefreshToken | null> {
    const result = await this.refreshTokenController.findFirst({ token });
    return result.data || null;
  }

  async createRefreshToken(data: Partial<RefreshToken>): Promise<RefreshToken> {
    const token = this.securityService.generateSecureToken(128);
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

    const result = await this.refreshTokenController.create({
      token,
      client_id: data.client_id!,
      user_id: data.user_id!,
      scope: data.scope || "",
      expires_at: expiresAt.toISOString(),
      is_revoked: false,
      rotation_count: 0,
    });

    if (!result.success || !result.data) {
      throw new Error(ServiceErrors.REFRESH_TOKEN_CREATE_FAILED);
    }

    return result.data;
  }

  async revokeRefreshToken(id: string): Promise<boolean> {
    const result = await this.refreshTokenController.update(id, {
      is_revoked: true,
      revoked_at: new Date().toISOString(),
    });

    return result.success;
  }

  async revokeRefreshTokensByUserId(userId: string): Promise<number> {
    // This would require a custom query implementation
    // For now, return 0 as a placeholder
    return 0;
  }

  async rotateRefreshToken(
    id: string,
    newToken: string,
  ): Promise<RefreshToken> {
    const currentToken = await this.findRefreshTokenById(id);
    if (!currentToken) {
      throw new Error(ServiceErrors.REFRESH_TOKEN_NOT_FOUND);
    }

    // Revoke current token
    await this.revokeRefreshToken(id);

    // Create new token
    const result = await this.createRefreshToken({
      client_id: currentToken.client_id,
      user_id: currentToken.user_id,
      scope: currentToken.scope,
    });

    // Update rotation count
    await this.refreshTokenController.update(result.id, {
      rotation_count: (currentToken.rotation_count || 0) + 1,
    });

    return result;
  }

  async cleanupExpiredRefreshTokens(): Promise<number> {
    // This would require a custom query implementation
    // For now, return 0 as a placeholder
    return 0;
  }

  // --- OAuth 2.0 Flows ---

  /**
   * Handle authorization request (Authorization Code Flow)
   */
  async handleAuthorizationRequest(
    request: AuthorizationRequest,
    user?: User,
  ): Promise<AuthorizationResponse> {
    try {
      // Validate client
      const client = await this.findClientByClientId(request.client_id);
      if (!client || !client.is_active) {
        return {
          error: OAuthErrorType.UNAUTHORIZED_CLIENT,
          error_description: ServiceErrors.UNAUTHORIZED_CLIENT,
          state: request.state,
        };
      }

      // Validate redirect URI
      if (
        request.redirect_uri &&
        !(await this.validateRedirectUri(
          request.client_id,
          request.redirect_uri,
        ))
      ) {
        return {
          error: OAuthErrorType.INVALID_REQUEST,
          error_description: ServiceErrors.INVALID_REDIRECT_URI,
          state: request.state,
        };
      }

      // Validate response type
      const responseTypes = JSON.parse((client as any).response_types || "[]");
      if (!responseTypes.includes(request.response_type)) {
        return {
          error: OAuthErrorType.UNSUPPORTED_RESPONSE_TYPE,
          error_description: ServiceErrors.UNSUPPORTED_RESPONSE_TYPE,
          state: request.state,
        };
      }

      // If user is not authenticated, return error for prompt=none
      if (!user && request.prompt === "none") {
        return {
          error: OAuthErrorType.ACCESS_DENIED,
          error_description: ServiceErrors.USER_AUTH_REQUIRED,
          state: request.state,
        };
      }

      // If user is authenticated, proceed with authorization
      if (user) {
        return await this.grantAuthorization(request, client, user);
      }

      // User needs to authenticate/consent
      return {
        // This would typically redirect to login/consent page
        // For API usage, we'll create a mock user for testing
        error: OAuthErrorType.TEMPORARILY_UNAVAILABLE,
        error_description: ServiceErrors.USER_AUTH_REQUIRED,
        state: request.state,
      };
    } catch (error: any) {
      return {
        error: OAuthErrorType.SERVER_ERROR,
        error_description: error.message,
        state: request.state,
      };
    }
  }

  /**
   * Grant authorization after user authentication and consent
   */
  private async grantAuthorization(
    request: AuthorizationRequest,
    client: OAuthClient,
    user: User,
  ): Promise<AuthorizationResponse> {
    if (request.response_type === OAuthResponseType.CODE) {
      // Authorization Code Flow
      const authCode = await this.createAuthCode({
        client_id: client.client_id,
        user_id: user.id,
        redirect_uri:
          request.redirect_uri ||
          (JSON.parse((client as any).redirect_uris || "[]") as string[])[0] ||
          "",
        scope: request.scope || client.scope,
        state: request.state,
        nonce: request.nonce,
        code_challenge: request.code_challenge,
        code_challenge_method: request.code_challenge_method,
      });

      return {
        code: authCode.code,
        state: request.state,
      };
    } else if (request.response_type === OAuthResponseType.TOKEN) {
      // Implicit Flow (not recommended)
      const accessToken = await this.generateAccessToken(
        client,
        user,
        request.scope || client.scope,
      );

      return {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 3600,
        scope: request.scope || client.scope,
        state: request.state,
      };
    }

    return {
      error: OAuthErrorType.UNSUPPORTED_RESPONSE_TYPE,
      error_description: "Unsupported response type",
      state: request.state,
    };
  }

  /**
   * Handle token request
   */
  async handleTokenRequest(request: TokenRequest): Promise<TokenResponse> {
    try {
      switch (request.grant_type) {
        case OAuthGrantType.AUTHORIZATION_CODE:
          return await this.handleAuthorizationCodeGrant(request);
        case OAuthGrantType.REFRESH_TOKEN:
          return await this.handleRefreshTokenGrant(request);
        case OAuthGrantType.CLIENT_CREDENTIALS:
          return await this.handleClientCredentialsGrant(request);
        case OAuthGrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS:
          return await this.handlePasswordGrant(request);
        default:
          return {
            error: OAuthErrorType.UNSUPPORTED_GRANT_TYPE,
            error_description: ServiceErrors.UNSUPPORTED_GRANT_TYPE,
            access_token: "",
            token_type: "Bearer",
            expires_in: 0,
          };
      }
    } catch (error: any) {
      return {
        error: OAuthErrorType.SERVER_ERROR,
        error_description: error.message,
        access_token: "",
        token_type: "Bearer",
        expires_in: 0,
      };
    }
  }

  /**
   * Handle Authorization Code Grant
   */
  private async handleAuthorizationCodeGrant(
    request: TokenRequest,
  ): Promise<TokenResponse> {
    if (!request.code) {
      return {
        error: OAuthErrorType.INVALID_REQUEST,
        error_description: ServiceErrors.AUTH_CODE_REQUIRED,
        access_token: "",
        token_type: "Bearer",
        expires_in: 0,
      };
    }

    // Validate authorization code
    const authCode = await this.findAuthCodeByCode(request.code);

    // ✅ VALIDACIÓN MEJORADA: Verificar si el código ya fue usado PRIMERO
    if (!authCode) {
      return {
        error: OAuthErrorType.INVALID_GRANT,
        error_description: ServiceErrors.INVALID_AUTH_CODE,
        access_token: "",
        token_type: "Bearer",
        expires_in: 0,
      };
    }

    if (authCode.is_used) {
      return {
        error: OAuthErrorType.INVALID_GRANT,
        error_description: ServiceErrors.AUTH_CODE_USED,
        access_token: "",
        token_type: "Bearer",
        expires_in: 0,
      };
    }

    if (new Date() > new Date(authCode.expires_at)) {
      return {
        error: OAuthErrorType.INVALID_GRANT,
        error_description: ServiceErrors.AUTH_CODE_EXPIRED,
        access_token: "",
        token_type: "Bearer",
        expires_in: 0,
      };
    }

    // Validate client
    const client = await this.authenticateClient(
      request.client_id!,
      request.client_secret,
    );
    if (!client) {
      return {
        error: OAuthErrorType.INVALID_CLIENT,
        error_description: ServiceErrors.INVALID_CLIENT,
        access_token: "",
        token_type: "Bearer",
        expires_in: 0,
      };
    }

    // Validate redirect URI
    if (
      request.redirect_uri &&
      request.redirect_uri !== authCode.redirect_uri
    ) {
      return {
        error: OAuthErrorType.INVALID_GRANT,
        error_description: ServiceErrors.REDIRECT_URI_MISMATCH,
        access_token: "",
        token_type: "Bearer",
        expires_in: 0,
      };
    }

    // Validate PKCE if present
    if (authCode.code_challenge && request.code_verifier) {
      const isValid = this.securityService.verifyPKCEChallenge(
        request.code_verifier,
        authCode.code_challenge,
        authCode.code_challenge_method || PKCEMethod.PLAIN,
      );

      if (!isValid) {
        return {
          error: OAuthErrorType.INVALID_GRANT,
          error_description: ServiceErrors.INVALID_PKCE,
          access_token: "",
          token_type: "Bearer",
          expires_in: 0,
        };
      }
    }

    // ✅ Marcar el código como usado ANTES de generar tokens
    await this.markAuthCodeAsUsed(authCode.id);

    // Get user (this would typically use the AuthService)
    // For now, we'll create a mock user object
    const user = { id: authCode.user_id, email: "user@example.com" } as User;

    // Generate tokens
    const accessToken = await this.generateAccessToken(
      client,
      user,
      authCode.scope,
    );
    const refreshToken = await this.createRefreshToken({
      client_id: client.client_id,
      user_id: user.id,
      scope: authCode.scope,
    });

    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: refreshToken.token,
      scope: authCode.scope,
    };
  }

  /**
   * Handle Refresh Token Grant
   */
  private async handleRefreshTokenGrant(
    request: TokenRequest,
  ): Promise<TokenResponse> {
    if (!request.refresh_token) {
      return {
        error: OAuthErrorType.INVALID_REQUEST,
        error_description: ServiceErrors.REFRESH_TOKEN_REQUIRED,
        access_token: "",
        token_type: "Bearer",
        expires_in: 0,
      };
    }

    // Validate refresh token
    const refreshToken = await this.findRefreshTokenByToken(
      request.refresh_token,
    );

    // ✅ VALIDACIÓN MEJORADA
    if (!refreshToken) {
      return {
        error: OAuthErrorType.INVALID_GRANT,
        error_description: ServiceErrors.INVALID_REFRESH_TOKEN_FORMAT, // Using generic format or invalid refresh token message
        access_token: "",
        token_type: "Bearer",
        expires_in: 0,
      };
    }

    if (refreshToken.is_revoked) {
      return {
        error: OAuthErrorType.INVALID_GRANT,
        error_description: ServiceErrors.REFRESH_TOKEN_REVOKED,
        access_token: "",
        token_type: "Bearer",
        expires_in: 0,
      };
    }

    if (new Date() > new Date(refreshToken.expires_at)) {
      return {
        error: OAuthErrorType.INVALID_GRANT,
        error_description: ServiceErrors.REFRESH_TOKEN_EXPIRED,
        access_token: "",
        token_type: "Bearer",
        expires_in: 0,
      };
    }

    // Validate client
    const client = await this.authenticateClient(
      request.client_id!,
      request.client_secret,
    );

    // ✅ VALIDACIÓN MEJORADA del cliente
    if (!client) {
      return {
        error: OAuthErrorType.INVALID_CLIENT,
        error_description: ServiceErrors.INVALID_CLIENT,
        access_token: "",
        token_type: "Bearer",
        expires_in: 0,
      };
    }

    if (client.client_id !== refreshToken.client_id) {
      return {
        error: OAuthErrorType.INVALID_CLIENT,
        error_description: ServiceErrors.CLIENT_MISMATCH,
        access_token: "",
        token_type: "Bearer",
        expires_in: 0,
      };
    }

    // ✅ ROTACIÓN MEJORADA de refresh token
    let newRefreshToken: RefreshToken;
    try {
      newRefreshToken = await this.rotateRefreshToken(
        refreshToken.id,
        refreshToken.token,
      );
    } catch (error) {
      return {
        error: OAuthErrorType.SERVER_ERROR,
        error_description: ServiceErrors.REFRESH_TOKEN_ROTATE_FAILED,
        access_token: "",
        token_type: "Bearer",
        expires_in: 0,
      };
    }

    // Get user (this would typically use the AuthService)
    const user = {
      id: refreshToken.user_id,
      email: "user@example.com",
    } as User;

    // Generate new access token
    const accessToken = await this.generateAccessToken(
      client,
      user,
      request.scope || refreshToken.scope,
    );

    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: newRefreshToken.token,
      scope: request.scope || refreshToken.scope,
    };
  }

  /**
   * Handle Client Credentials Grant
   */
  private async handleClientCredentialsGrant(
    request: TokenRequest,
  ): Promise<TokenResponse> {
    // Validate client
    const client = await this.authenticateClient(
      request.client_id!,
      request.client_secret,
    );
    if (!client) {
      return {
        error: OAuthErrorType.INVALID_CLIENT,
        error_description: ServiceErrors.INVALID_CLIENT,
        access_token: "",
        token_type: "Bearer",
        expires_in: 0,
      };
    }

    // Check if client is public (public clients cannot use client credentials)
    if (client.is_public) {
      return {
        error: OAuthErrorType.UNAUTHORIZED_CLIENT,
        error_description: ServiceErrors.PUBLIC_CLIENT_NO_CREDENTIALS,
        access_token: "",
        token_type: "Bearer",
        expires_in: 0,
      };
    }

    // Generate access token (no user context)
    const accessToken = await this.generateAccessToken(
      client,
      undefined,
      request.scope || client.scope,
    );

    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      scope: request.scope || client.scope,
    };
  }

  /**
   * Handle Resource Owner Password Credentials Grant
   */
  private async handlePasswordGrant(
    request: TokenRequest,
  ): Promise<TokenResponse> {
    try {
      // Validate client credentials
      const client = await this.authenticateClient(
        request.client_id!,
        request.client_secret,
      );
      if (!client) {
        return {
          error: OAuthErrorType.INVALID_CLIENT,
          error_description: "Invalid client credentials",
          access_token: "",
          token_type: "Bearer",
          expires_in: 0,
        };
      }

      // For password grant, we need username and password from the request
      // These are not in the standard TokenRequest type, but are passed in the request
      const username = (request as any).username;
      const password = (request as any).password;

      if (!username || !password) {
        return {
          error: OAuthErrorType.INVALID_REQUEST,
          error_description: "Username and password are required for password grant",
          access_token: "",
          token_type: "Bearer",
          expires_in: 0,
        };
      }

      // Validate user credentials using AuthService
      const loginResult = await this.authService.login({ email: username, password });

      if (!loginResult.success || !loginResult.user) {
        return {
          error: OAuthErrorType.INVALID_GRANT,
          error_description: "Invalid user credentials",
          access_token: "",
          token_type: "Bearer",
          expires_in: 0,
        };
      }

      // Generate tokens
      const accessToken = await this.generateAccessToken(
        client,
        loginResult.user,
        request.scope || client.scope,
      );
      const refreshToken = await this.createRefreshToken({
        client_id: client.client_id,
        user_id: loginResult.user.id,
        scope: request.scope || client.scope,
      });

      return {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: refreshToken.token,
        scope: request.scope || client.scope,
      };
    } catch (error: any) {
      return {
        error: OAuthErrorType.SERVER_ERROR,
        error_description: error.message,
        access_token: "",
        token_type: "Bearer",
        expires_in: 0,
      };
    }
  }

  /**
   * Generate access token
   */
  private async generateAccessToken(
    client: OAuthClient,
    user?: User,
    scope?: string,
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const payload: OAuthJWTPayload = {
      iss: "https://your-auth-server.com", // Should be configurable
      sub: user?.id || client.client_id,
      aud: [client.client_id],
      exp: now + 3600, // 1 hour
      iat: now,
      jti: this.securityService.generateSecureToken(16),
      scope: scope || "",
      client_id: client.client_id,
      token_type: "access_token",
    };

    // Add user claims if available
    if (user) {
      payload.name = `${user.first_name} ${user.last_name}`.trim();
      payload.email = user.email;
    }

    return await this.jwtService.generateTokenWithPayload(payload);
  }

  /**
   * Handle device authorization request
   */
  async handleDeviceAuthorizationRequest(
    request: DeviceAuthorizationRequest,
  ): Promise<DeviceAuthorizationResponse> {
    // Validate client
    const client = await this.findClientByClientId(request.client_id);
    if (!client || !client.is_active) {
      return {
        device_code: "",
        user_code: "",
        verification_uri: "",
        verification_uri_complete: "",
        expires_in: 0,
        interval: 0,
      };
    }

    // Generate device and user codes
    const deviceCode = this.securityService.generateSecureToken(32);
    const userCode = this.generateUserCode();

    // Store device authorization (would typically use a separate table)
    // For now, return the response

    return {
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: "https://your-auth-server.com/device",
      verification_uri_complete: `https://your-auth-server.com/device?user_code=${userCode}`,
      expires_in: 1800, // 30 minutes
      interval: 5, // Poll every 5 seconds
    };
  }

  /**
   * Generate user-friendly device code
   */
  private generateUserCode(): string {
    const chars = "BCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz23456789";
    let code = "";
    for (let i = 0; i < 8; i++) {
      if (i === 4) code += "-";
      code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
  }

  /**
   * Handle introspection request
   */
  async handleIntrospectionRequest(
    request: IntrospectionRequest,
  ): Promise<IntrospectionResponse> {
    try {
      // Try to verify as access token first
      try {
        const payload = await this.jwtService.verifyToken(request.token);
        return {
          active: true,
          scope: (payload as unknown as { scope?: string }).scope || "",
          client_id: (payload as unknown as { client_id?: string }).client_id,
          username: (payload as unknown as { email?: string }).email,
          token_type: "Bearer",
          exp: (payload as unknown as { exp?: number }).exp,
          iat: (payload as unknown as { iat?: number }).iat,
          sub: (payload as unknown as { sub?: string }).sub,
          aud: (payload as unknown as { aud?: string | string[] })
            .aud as string,
          iss: (payload as unknown as { iss?: string }).iss,
          jti: (payload as unknown as { jti?: string }).jti,
        };
      } catch (error) {
        // Not a valid access token, try refresh token
        const refreshToken = await this.findRefreshTokenByToken(request.token);
        if (
          refreshToken &&
          !refreshToken.is_revoked &&
          new Date() <= new Date(refreshToken.expires_at)
        ) {
          return {
            active: true,
            scope: refreshToken.scope,
            client_id: refreshToken.client_id,
            token_type: "Bearer",
            exp: Math.floor(new Date(refreshToken.expires_at).getTime() / 1000),
            sub: refreshToken.user_id,
          };
        }
      }

      return { active: false };
    } catch (error: any) {
      return { active: false };
    }
  }

  /**
   * Handle revocation request
   */
  async handleRevocationRequest(
    request: RevocationRequest,
  ): Promise<{ success: boolean; error?: string }> {
    try {
      // Try to revoke as access token first
      try {
        const payload = await this.jwtService.verifyToken(request.token);
        // Access tokens are stateless, so we can't directly revoke them
        // In a real implementation, you might use a token blacklist or short expiration times
        return { success: true };
      } catch (error) {
        // Not a valid access token, try refresh token
        const refreshToken = await this.findRefreshTokenByToken(request.token);
        if (refreshToken) {
          await this.revokeRefreshToken(refreshToken.id);
          return { success: true };
        }
      }

      return { success: true }; // Always return success for revocation per RFC 7009
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }
}
