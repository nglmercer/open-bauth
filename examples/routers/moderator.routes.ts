import { Hono } from "hono";
import type { Context, Next } from "hono";
import type { AuthContext } from "../../src/index";

export type AppContext = {
  Variables: {
    auth: AuthContext;
  };
};

export function createModeratorRoutes(middlewares: {
  requireAuth: (c: Context, next: Next) => Promise<Response | void>;
  requireModeratorRole: (c: Context, next: Next) => Promise<Response | void>;
  requireEditPermission: (c: Context, next: Next) => Promise<Response | void>;
}) {
  const { requireAuth, requireModeratorRole, requireEditPermission } =
    middlewares;
  const router = new Hono<AppContext>();

  router.use("*", requireAuth, requireModeratorRole);

  router.get("/content", (c) => {
    return c.json({ message: "Here is the content you can moderate." });
  });

  router.post("/content/edit", requireEditPermission, (c) => {
    return c.json({ message: "Content edited successfully!" });
  });

  return router;
}
