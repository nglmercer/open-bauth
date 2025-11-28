import { Hono } from "hono";
import type { AuthContext } from "../../src/index";
import type { AuthService } from "../../src/index";
import { AuthController } from "../controllers/auth.controller";

// Define local AppContext type for Hono variables
export type AppContext = {
  Variables: {
    auth: AuthContext;
  };
};

export function createPublicRoutes(deps: { authService: AuthService }) {
  const { authService } = deps;
  const router = new Hono<AppContext>();

  // Initialize AuthController
  const authController = new AuthController(authService);

  // Public welcome route
  router.get("/", (c) => {
    const auth = c.get("auth");
    const message = auth?.isAuthenticated
      ? `Welcome back, ${auth.user?.first_name}!`
      : "Welcome, guest! Please log in.";
    return c.json({ message });
  });

  // Use AuthController for authentication routes
  router.post("/register", authController.register);
  router.post("/login", authController.login);
  router.post("/refresh", authController.refreshToken);
  // Admin registration (specific to public routes)
  router.post("/register/admin", async (c) => {
    const body = await c.req.json();
    const result = await authService.register(body);
    const user_id = result.user?.id;
    if (user_id) {
      await authService.assignRole(user_id, "admin");
      await authService.assignRole(user_id, "moderator");
    }
    if (!result.success) {
      // Asegurar que el formato de respuesta coincida con el esperado por las pruebas
      return c.json(
        {
          success: false,
          error: {
            message: result.error?.message || "Admin registration failed",
            type: result.error?.type || "UNKNOWN_ERROR",
            timestamp: new Date().toISOString(),
          },
        },
        400,
      );
    }
    return c.json(
      {
        success: true,
        message: "Admin registered successfully",
        data: {
          user: result.user,
          token: result.token,
        },
      },
      200,
    ); // Cambiar a 200 para consistencia
  });

  // Register with role (specific to public routes)
  router.post("/register-with-role", async (c) => {
    const body = await c.req.json();
    const { role_name, permission_names, ...registrationData } = body as any;

    const registrationResult = await authService.register(registrationData);
    if (!registrationResult.success) {
      // Asegurar que el formato de respuesta coincida con el esperado por las pruebas
      return c.json(
        {
          success: false,
          error: {
            message: registrationResult.error?.message || "Registration failed",
            type: registrationResult.error?.type || "UNKNOWN_ERROR",
            timestamp: new Date().toISOString(),
          },
        },
        400,
      );
    }

    const user_id = registrationResult.user?.id;
    if (user_id && role_name) {
      const roleAssignmentResult = await authService.assignRole(
        user_id,
        role_name,
      );
      if (!roleAssignmentResult.success) {
        return c.json(
          {
            success: false,
            error:roleAssignmentResult.error || {
              message: "User registered, but role assignment failed.",
              type:  "ROLE_ASSIGNMENT_ERROR",
              timestamp: new Date().toISOString(),
            },
          },
          400,
        );
      }
    }

    return c.json(
      {
        success: true,
        message: "User registered successfully",
        data: {
          user: registrationResult.user,
          token: registrationResult.token,
        },
      },
      200, // Cambiar a 200 como esperan los tests
    );
  });

  return router;
}
