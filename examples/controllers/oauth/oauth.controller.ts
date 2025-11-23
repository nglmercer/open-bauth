import { Hono } from "hono";
import { Context } from "hono";
import type {
  OAuthClient,
  CreateOAuthClientData,
  OAuthGrantType,
  OAuthResponseType,
} from "../../../src/types/oauth";
import type { OAuthService } from "../../../src/services/oauth";
import type { SecurityService } from "../../../src/services/security";
import { ApiError } from "../../../examples/api.types";
import type { AppContext } from "../../app";

export class OAuthController {
  constructor(
    private oauthService: OAuthService,
    private securityService: SecurityService,
  ) {}

  // Get OAuth clients
  getClients = async (c: Context<AppContext>) => {
    try {
      const clients = await this.oauthService.findAllClients();
      return c.json({
        success: true,
        data: clients,
      });
    } catch (error) {
      throw new ApiError(500, "Failed to fetch OAuth clients");
    }
  };

  // Create OAuth client
  createClient = async (c: Context<AppContext>) => {
    try {
      const clientData: CreateOAuthClientData = await c.req.json();
      const client = await this.oauthService.createClient(clientData);

      return c.json({
        success: true,
        data: client,
      });
    } catch (error: any) {
      throw new ApiError(400, error.message || "Failed to create OAuth client");
    }
  };

  // Update OAuth client
  updateClient = async (c: Context<AppContext>) => {
    try {
      const clientId = c.req.param("id");
      const updateData = await c.req.json();
      const client = await this.oauthService.updateClient(
        String(clientId),
        updateData,
      );

      return c.json({
        success: true,
        data: client,
      });
    } catch (error: any) {
      throw new ApiError(400, error.message || "Failed to update OAuth client");
    }
  };

  // Delete OAuth client
  deleteClient = async (c: Context<AppContext>) => {
    try {
      const clientId = c.req.param("id");
      await this.oauthService.deleteClient(String(clientId));

      return c.json({
        success: true,
        message: "OAuth client deleted successfully",
      });
    } catch (error: any) {
      throw new ApiError(400, error.message || "Failed to delete OAuth client");
    }
  };

  // Handle authorization request
  handleAuthorization = async (c: Context<AppContext>) => {
    try {
      const authRequest = await c.req.json();
      const auth = c.get("auth"); // Get authenticated user from middleware

      if (!auth || !auth.isAuthenticated || !auth.user) {
        throw new ApiError(401, "User authentication required");
      }

      const response = await this.oauthService.handleAuthorizationRequest(
        authRequest,
        auth.user,
      );
      return c.json(response);
    } catch (error: any) {
      throw new ApiError(400, error.message || "Authorization request failed");
    }
  };

  // Handle token request
  handleToken = async (c: Context<AppContext>) => {
    try {
      const tokenRequest = await c.req.json();
      const response = await this.oauthService.handleTokenRequest(tokenRequest);
      return c.json(response);
    } catch (error: any) {
      throw new ApiError(400, error.message || "Token request failed");
    }
  };

  // Handle device authorization request
  handleDeviceAuthorization = async (c: Context<AppContext>) => {
    try {
      const deviceRequest = await c.req.json();
      const response =
        await this.oauthService.handleDeviceAuthorizationRequest(deviceRequest);
      return c.json(response);
    } catch (error: any) {
      throw new ApiError(
        400,
        error.message || "Device authorization request failed",
      );
    }
  };

  // Handle token introspection
  handleIntrospection = async (c: Context<AppContext>) => {
    try {
      const introspectionRequest = await c.req.json();
      const response =
        await this.oauthService.handleIntrospectionRequest(
          introspectionRequest,
        );
      return c.json(response);
    } catch (error: any) {
      throw new ApiError(400, error.message || "Token introspection failed");
    }
  };

  // Handle token revocation
  handleRevocation = async (c: Context<AppContext>) => {
    try {
      const revocationRequest = await c.req.json();
      const response =
        await this.oauthService.handleRevocationRequest(revocationRequest);
      return c.json(response);
    } catch (error: any) {
      throw new ApiError(400, error.message || "Token revocation failed");
    }
  };

  // Generate PKCE challenge
  generatePKCEChallenge = async (c: Context<AppContext>) => {
    try {
      const pkceChallenge = this.securityService.generatePKCEChallenge();
      const codeVerifier = pkceChallenge.code_verifier;

      return c.json({
        success: true,
        data: {
          code_verifier: codeVerifier,
          code_challenge: pkceChallenge.code_challenge,
          code_challenge_method: pkceChallenge.code_challenge_method,
        },
      });
    } catch (error: any) {
      throw new ApiError(500, "Failed to generate PKCE challenge");
    }
  };
}
