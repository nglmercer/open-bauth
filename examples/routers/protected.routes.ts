import { Hono } from "hono";
import type { Context, Next } from "hono";
import type { AuthContext } from "../../src/index";

export type AppContext = {
  Variables: {
    auth: AuthContext;
  };
};

export function createProtectedRoutes(middlewares: {
  requireAuth: (c: Context, next: Next) => Promise<Response | void>;
}) {
  const { requireAuth } = middlewares;
  const router = new Hono<AppContext>();

  router.use("*", requireAuth);

  router.get("/profile", (c) => {
    const auth = c.get("auth");
    return c.json({
      message: "This is your private profile data.",
      user: auth.user,
      permissions: auth.permissions,
    });
  });

  return router;
}
