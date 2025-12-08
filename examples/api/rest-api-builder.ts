import { Hono } from "hono";
import { DatabaseInitializer } from "../../src/database/database-initializer";
import { BaseController } from "../../src/database/base-controller";

/**
 * Utility to automatically build a REST API from registered schemas.
 * Mimics behavior similar to Generic implementation for rapid value.
 */
export class RestApiBuilder {
    private initializer: DatabaseInitializer;

    constructor(initializer: DatabaseInitializer) {
        this.initializer = initializer;
    }

    /**
     * Generates a router with CRUD endpoints for ALL tables using dynamic routing.
     * This allows accessing tables added at runtime without restarting the router.
     */
    public buildRouter(basePath: string = "/api/v1") {
        const app = new Hono().basePath(basePath);

        // Endpoint to discover available resources
        app.get("/_meta/tables", (c) => {
            const schemas = this.initializer.getSchemas();
            return c.json(schemas.map(s => s.tableName));
        });

        // Mount dynamic routes for any table
        this.mountDynamicRoutes(app);

        return app;
    }

    private mountDynamicRoutes(app: Hono) {
        // Helper to validate table existence
        const validateTable = (tableName: string) => {
            // We fetch fresh schemas every time to support dynamic additions
            const schemas = this.initializer.getSchemas();
            const exists = schemas.some(s => s.tableName === tableName);
            return exists;
        };

        // GET /:table - List with filters
        app.get("/:table", async (c) => {
            const tableName = c.req.param("table");
            if (!validateTable(tableName)) {
                return c.json({ error: `Table '${tableName}' not found or not registered` }, 404);
            }

            const controller = this.initializer.createController(tableName);
            const query = c.req.query();

            const searchOptions = this.parseQueryParameters(query);

            const result = await controller.search(searchOptions);
            if (!result.success) return c.json(result, 400);
            return c.json(result.data);
        });

        // GET /:table/:id - Get one
        app.get("/:table/:id", async (c) => {
            const tableName = c.req.param("table");
            if (!validateTable(tableName)) {
                return c.json({ error: `Table '${tableName}' not found` }, 404);
            }

            const controller = this.initializer.createController(tableName);
            const id = c.req.param("id");
            const result = await controller.findById(id);
            if (!result.success || !result.data) return c.json({ error: "Not found" }, 404);
            return c.json(result.data);
        });

        // POST /:table - Create
        app.post("/:table", async (c) => {
            const tableName = c.req.param("table");
            if (!validateTable(tableName)) {
                return c.json({ error: `Table '${tableName}' not found` }, 404);
            }

            const controller = this.initializer.createController(tableName);
            let body;
            try {
                body = await c.req.json();
            } catch (e) {
                return c.json({ error: "Invalid JSON" }, 400);
            }

            const result = await controller.create(body);
            if (!result.success) {
                return c.json({ error: result.error, issues: result.message }, 400);
            }
            return c.json(result.data, 201);
        });

        // PATCH /:table/:id - Update
        app.patch("/:table/:id", async (c) => {
            const tableName = c.req.param("table");
            if (!validateTable(tableName)) {
                return c.json({ error: `Table '${tableName}' not found` }, 404);
            }

            const controller = this.initializer.createController(tableName);
            const id = c.req.param("id");
            let body;
            try {
                body = await c.req.json();
            } catch (e) {
                return c.json({ error: "Invalid JSON" }, 400);
            }

            const result = await controller.update(id, body);
            if (!result.success) return c.json({ error: result.error }, 400);
            return c.json(result.data);
        });

        // DELETE /:table/:id - Delete
        app.delete("/:table/:id", async (c) => {
            const tableName = c.req.param("table");
            if (!validateTable(tableName)) {
                return c.json({ error: `Table '${tableName}' not found` }, 404);
            }

            const controller = this.initializer.createController(tableName);
            const id = c.req.param("id");
            const result = await controller.delete(id);
            if (!result.success) return c.json({ error: result.error }, 400);
            return c.json({ success: true });
        });
    }

    /**
     * Translator for URL parameters to Controller Search Options
     * Supports:
     * - select=col1,col2
     * - limit=10
     * - offset=0
     * - order=col.asc|desc
     * - col=eq.val, col=gt.val (Simple Supabase-like syntax)
     * - col=val (Direct equality)
     */
    private parseQueryParameters(query: Record<string, string>): any {
        const where: Record<string, any> = {};
        const options: any = { where };

        for (const [key, value] of Object.entries(query)) {
            // Reserved keys
            if (key === "select") {
                options.select = value.split(",");
                continue;
            }
            if (key === "limit") {
                options.limit = parseInt(value, 10);
                continue;
            }
            if (key === "offset") {
                options.offset = parseInt(value, 10);
                continue;
            }
            if (key === "order") {
                const parts = value.split(".");
                if (parts.length === 2) {
                    options.orderBy = parts[0];
                    options.orderDirection = parts[1].toUpperCase();
                } else {
                    options.orderBy = value;
                    options.orderDirection = "ASC";
                }
                continue;
            }

            // Filter handling
            // Format: eq.123, gt.10, like.%foo%
            if (value.includes(".")) {
                const [op, ...valParts] = value.split(".");
                const val = valParts.join("."); // Join back in case value had dots

                const operatorMap: Record<string, string> = {
                    eq: "=",
                    gt: ">",
                    gte: ">=",
                    lt: "<",
                    lte: "<=",
                    like: "LIKE",
                    neq: "!="
                };

                if (operatorMap[op]) {
                    where[key] = { operator: operatorMap[op], value: val };
                } else {
                    // Fallback or handle special cases like 'in'
                    where[key] = value;
                }
            } else {
                // Direct equality default
                where[key] = value;
            }
        }

        return options;
    }
}
