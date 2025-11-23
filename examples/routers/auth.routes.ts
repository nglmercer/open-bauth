// src/routes/auth.routes.ts
import { Hono } from "hono";
import { AuthController } from "../controllers/auth.controller";
import { AppContext, Services } from "../app"; // We'll define this type next
import { createAuthMiddlewareForHono } from "../middleware/auth.middleware";
import { ApiError } from "../api.types";
import { AuthErrorType } from "../../src/index";

export const createAuthRouter = (services: Services): Hono<AppContext> => {
  const router = new Hono<AppContext>();
  const authController = new AuthController(services.authService);
  const requireAuth = createAuthMiddlewareForHono(services, true);

  // Public routes
  router.post("/register", authController.register);
  router.post("/login", authController.login);

  // Protected routes
  router.get("/profile", requireAuth, authController.getProfile);
  router.post("/refresh", authController.refreshToken);

  return router;
};

// Alternative public router for superuser auth methods
// This endpoint is intentionally public and does not require auth.
// It supports filtering via the `fields` query param, e.g.
// /auth-methods?fields=mfa,otp,password,oauth2
export const createSuperuserAuthMethodsRouter = (
  services: Services,
): Hono<AppContext> => {
  const router = new Hono<AppContext>();
  const authController = new AuthController(services.authService);

  router.get("/auth-methods", (c) => {
    const url = new URL(c.req.url);
    const fieldsParam = url.searchParams.get("fields");

    // Basic example values for available auth methods
    const available: Record<string, any> = {
      mfa: {
        enabled: false,
      },
      otp: {
        enabled: true,
      },
      password: {
        enabled: true,
        identityFields: ["email", "username"], // Specify allowed identity fields
      },
      oauth2: {
        enabled: true,
        providers: ["google", "github"],
      },
    };

    // Filter data based on requested fields
    const data = fieldsParam
      ? fieldsParam
          .split(",")
          .map((f) => f.trim())
          .filter(Boolean)
          .reduce((acc: Record<string, any>, key: string) => {
            if (available[key] !== undefined) {
              acc[key] = available[key];
            }
            return acc;
          }, {})
      : available;

    return c.json(data);
  });
  //identity:string|email,password:string
  router.post("/auth-with-password", async (c) => {
    const body = await c.req.json();
    const { identity, password } = body;

    // Create login data object that matches LoginData interface
    const loginData = {
      email: identity as string,
      password: password as string,
    };

    // Call the AuthService directly with transformed data
    const result = await services.authService.login(loginData);

    if (!result.success || !result.user?.id) {
      // Devolver respuesta JSON directa en lugar de lanzar excepción
      return c.json(
        {
          success: false,
          error: {
            message: result.error?.message || "Authentication failed",
            type: result.error?.type || AuthErrorType.INVALID_CREDENTIALS,
            timestamp: new Date().toISOString(),
          },
        },
        401,
      );
    }

    // Generate refresh token using jwtService
    const refreshToken = await services.jwtService.generateRefreshToken(
      result.user?.id || "",
    );

    return c.json({
      success: true,
      data: {
        user: result.user,
        token: result.token,
        refreshToken,
      },
      token: result.token,
      isValid: true,
      record: result.user,
    });
  });
  //token: "JWT_TOKEN", record: CommonHelper.dummyCollectionRecord(collection),
  ///auth-refresh
  router.post("/auth-refresh", authController.refreshToken);

  return router;
};
