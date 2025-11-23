import { Hono } from "hono";
import { Context } from "hono";
import { OAuthController } from "../../controllers/oauth/oauth.controller";
import { Services } from "../../app";
import type { AppContext } from "../../app";

// Type definitions for route handlers
type ClientParams = {
  id: string;
};

export function createOAuthRoutes(services: Services) {
  const router = new Hono<AppContext>();
  const { oauthService, securityService } = services;

  if (!oauthService || !securityService) {
    throw new Error(
      "OAuthService and SecurityService must be provided to create OAuth routes",
    );
  }

  const oauthController = new OAuthController(oauthService, securityService);

  // OAuth Client Management Routes
  router.get("/clients", oauthController.getClients);
  router.post("/clients", oauthController.createClient);
  router.put("/clients/:id", oauthController.updateClient);
  router.delete("/clients/:id", oauthController.deleteClient);

  // OAuth 2.0 Flow Routes
  router.post("/authorize", oauthController.handleAuthorization);
  router.post("/token", oauthController.handleToken);
  router.post("/device/authorize", oauthController.handleDeviceAuthorization);
  router.post("/introspect", oauthController.handleIntrospection);
  router.post("/revoke", oauthController.handleRevocation);

  // PKCE Support
  router.post("/pkce/challenge", oauthController.generatePKCEChallenge);

  return router;
}
