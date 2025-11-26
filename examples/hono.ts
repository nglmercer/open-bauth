//hono.ts

import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { prettyJSON } from "hono/pretty-json";
import { serveStatic } from "hono/bun";
import { Database } from "bun:sqlite";

// Core Application Imports
import { DatabaseInitializer } from "../src/index";
import { JWTService } from "../src/index";
import { AuthService } from "../src/index";
import { PermissionService } from "../src/index";
import { registerOAuthSchemaExtensions } from "../src/database/schema/oauth-schema-extensions";
import { AppContext, AppDependencies, Services } from "./app";
import { merged } from "./integrations/newSchemas";
//,pointsSchema, processesSchema, notificationsSchema
import { createMiddlewareFactory } from "./middleware/factory";
import {
  setupGenericControllers,
  tableConfigs,
} from "./routers/base.controller";
// Router Imports
import { createPublicRoutes } from "./routers/public.routes";
import { createProtectedRoutes } from "./routers/protected.routes";
import { createModeratorRoutes } from "./routers/moderator.routes";
import { createAdminRoutes } from "./routers/admin.routes";
import { createProductRoutes } from "./routers/product.routes";
import { createOAuthRoutes } from "./routers/oauth/oauth.routes";
import { globalErrorHandler } from "./middleware/error.handler";
import { createSuperuserAuthMethodsRouter } from "./routers/auth.routes";

// --- 1. Service Initialization ---
// Use test database path if in test environment
const dbPath =
  process.env.NODE_ENV === "test"
    ? process.env.DATABASE_URL || "./tests/db/auth.db"
    : "auth.db";
const db = new Database(dbPath);
// Import DatabaseInitializer from src for consistency
const dbInitializer = new DatabaseInitializer({
  database: db,
  externalSchemas: merged.getAll(),
});

// Register OAuth schema extensions
registerOAuthSchemaExtensions();

await dbInitializer.initialize();
await dbInitializer.seedDefaults();

const jwtService = new JWTService(
  process.env.JWT_SECRET || "a-very-secret-key-for-hono",
  process.env.JWT_EXPIRATION || "7d",
);
const authService = new AuthService(dbInitializer, jwtService);
const permissionService = new PermissionService(dbInitializer);

// Create SecurityService with dynamic import to avoid type conflicts
const { SecurityService } = await import("../src/services/security");
const securityService = new SecurityService();
// Create OAuthService with dynamic import to avoid type conflicts
const { OAuthService } = await import("../src/services/oauth");
const oauthService = new OAuthService(
  dbInitializer as any, // Cast to any to bypass type checking
  securityService,
  jwtService,
);

// Create the services container
const services: Services = {
  jwtService,
  authService,
  permissionService,
  securityService,
  oauthService,
};
console.log("✅ Services initialized.");

// --- 2. Dependency Container Setup ---
// Create the middleware factory using the initialized services
const middlewares = createMiddlewareFactory(services);

// --- 3. Hono Application Setup ---
const app = new Hono<AppContext>();

// Error handler middleware (must be first)
app.onError(globalErrorHandler);

// Global middlewares
app.use("*", logger());
app.use("*", prettyJSON());
app.use(
  "*",
  cors({
    origin: "*", // Add your frontend URL
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  }),
);

// Use the factory to create the global optional auth middleware
app.use("*", middlewares.optionalAuth());

// Static file serving for images
app.use("/images/*", serveStatic({ root: "./public" }));

// --- 4. Routers ---
// Create routers by passing the single dependency container
const publicRoutes = createPublicRoutes({ authService: services.authService });
const superuserAuthMethodsRoutes = createSuperuserAuthMethodsRouter(services);
const protectedRoutes = createProtectedRoutes({
  requireAuth: middlewares.requireAuth(),
});
const moderatorRoutes = createModeratorRoutes({
  requireAuth: middlewares.requireAuth(),
  requireModeratorRole: middlewares.requireRole(["moderator"]),
  requireEditPermission: middlewares.requirePermission(["edit:content"]),
});
const adminRoutes = createAdminRoutes(
  { authService: services.authService, permissionService: permissionService },
  {
    requireAuth: middlewares.requireAuth(),
    requireAdminRole: middlewares.requireRole(["admin"]),
  },
);
const productRoutes = createProductRoutes({ dbInitializer });
const genericRouters = setupGenericControllers(dbInitializer);
const oauthRoutes = createOAuthRoutes(services);

// Mount routers firts publics later protected
app.route("/auth", publicRoutes);
app.route("/api/auth", publicRoutes);
app.route("/api", genericRouters);
//app.route('/api/collections/_superusers', superuserAuthMethodsRoutes);
app.route("/api", protectedRoutes);
app.route("/api/mod", moderatorRoutes);
app.route("/api/admin", adminRoutes);
app.route("/api", productRoutes);
app.route("/oauth", oauthRoutes);
//app.route('/api/collections/')
// --- 5. Export for Bun ---
export default app;
export { db, dbInitializer };
