import { Context, Hono } from "hono";
import { DatabaseInitializer } from "../../src/index";
import {
  GenericController,
  type ControllerConfig,
  type ValidationRule,
} from "../controllers/generic-controller";

// Ejemplo 1: Controlador de Productos (corrigiendo el problema del join)
const productConfig: ControllerConfig = {
  tableName: "products",
  primaryKey: "id",
  validation: {
    create: [
      { field: "name", required: true, type: "string", min: 1, max: 255 },
      { field: "price", required: true, type: "number", min: 0 },
      { field: "stock_quantity", type: "number", min: 0 },
      { field: "category_id", type: "string" },
    ],
    update: [
      { field: "name", type: "string", min: 1, max: 255 },
      { field: "price", type: "number", min: 0 },
      { field: "stock_quantity", type: "number", min: 0 },
      { field: "category_id", type: "string" },
    ],
  },
  oneToOneRelations: [
    {
      name: "category",
      tableName: "categories",
      localKey: "category_id", // clave foránea en products
      foreignKey: "id", // clave primaria en categories
    },
  ],
  defaultFilters: {
    is_available: true, // Solo productos disponibles por defecto
  },
  defaultOrder: {
    field: "created_at",
    direction: "DESC",
  },
};

// Ejemplo 2: Controlador de Categorías
const categoryConfig: ControllerConfig = {
  tableName: "categories",
  primaryKey: "id",
  validation: {
    create: [
      { field: "name", required: true, type: "string", min: 1, max: 100 },
      { field: "icon", type: "string", max: 50 },
      { field: "description", type: "string", max: 500 },
    ],
    update: [
      { field: "name", type: "string", min: 1, max: 100 },
      { field: "icon", type: "string", max: 50 },
      { field: "description", type: "string", max: 500 },
    ],
  },
  oneToOneRelations: [
    {
      name: "products",
      tableName: "products",
      localKey: "id", // clave primaria en categories
      foreignKey: "category_id", // clave foránea en products
    },
  ],
  defaultFilters: {
    is_active: true,
  },
  defaultOrder: {
    field: "name",
    direction: "ASC",
  },
};

// Ejemplo 3: Controlador de Usuarios
const userConfig: ControllerConfig = {
  tableName: "users",
  primaryKey: "id",
  validation: {
    create: [
      {
        field: "email",
        required: true,
        type: "string",
        pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        message: "Email must be valid",
      },
      { field: "name", required: true, type: "string", min: 1, max: 255 },
      { field: "age", type: "number", min: 13, max: 120 },
      {
        field: "password",
        required: true,
        type: "string",
        min: 8,
        validator: (value) => /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(value),
        message:
          "Password must contain at least one lowercase, uppercase, and number",
      },
    ],
    update: [
      {
        field: "email",
        type: "string",
        pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        message: "Email must be valid",
      },
      { field: "name", type: "string", min: 1, max: 255 },
      { field: "age", type: "number", min: 13, max: 120 },
      {
        field: "password",
        type: "string",
        min: 8,
        validator: (value) => /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(value),
        message:
          "Password must contain at least one lowercase, uppercase, and number",
      },
    ],
  },
  defaultFilters: {
    is_active: true,
  },
  defaultOrder: {
    field: "created_at",
    direction: "DESC",
  },
  oneToOneRelations: [
    {
      name: "user_profiles", // Name of the relation (singular)
      tableName: "user_profiles",
      localKey: "id", // user_profiles.id = users.id (shared primary key)
      foreignKey: "id", // users.id
    },
  ],
};
const projectsConfig: ControllerConfig = {
  tableName: "projects",
  primaryKey: "id",
  validation: {
    create: [
      {
        field: "project_name",
        required: true,
        type: "string",
        min: 1,
        max: 255,
      },
      { field: "project_owner", type: "string", max: 255 },
      { field: "team", type: "array" },
      { field: "description", type: "string", max: 1000 },
      { field: "start_date", type: "string" },
      { field: "end_date", type: "string" },
      { field: "status", type: "string", max: 50 },
    ],
    update: [
      { field: "project_name", type: "string", min: 1, max: 255 },
      { field: "description", type: "string", max: 1000 },
      { field: "start_date", type: "string" },
      { field: "end_date", type: "string" },
      { field: "status", type: "string", max: 50 },
    ],
  },
  defaultOrder: {
    field: "created_at",
    direction: "DESC",
  },
};
// Ejemplo de setup completo con HonoJS
export function setupGenericControllers(dbInitializer: DatabaseInitializer) {
  const app = new Hono();

  // Crear instancias de controladores
  const productController = new GenericController(dbInitializer, productConfig);
  const categoryController = new GenericController(
    dbInitializer,
    categoryConfig,
  );
  const userController = new GenericController(dbInitializer, userConfig);
  const projectController = new GenericController(
    dbInitializer,
    projectsConfig,
  );
  // Rutas para productos
  /*   app.get('/products', productController.getAll.bind(productController));
  app.get('/products/:id', productController.getById.bind(productController));
  app.post('/products', productController.create.bind(productController));
  app.put('/products/:id', productController.update.bind(productController));
  app.delete('/products/:id', productController.delete.bind(productController));
  app.post('/products/search', productController.search.bind(productController));
  app.get('/products/count', productController.count.bind(productController));
  app.get('/products/random', productController.random.bind(productController));
  app.post('/products/find-first', productController.findFirst.bind(productController));

  // Rutas para categorías
  app.get('/categories', categoryController.getAll.bind(categoryController));
  app.get('/categories/:id', categoryController.getById.bind(categoryController));
  app.post('/categories', categoryController.create.bind(categoryController));
  app.put('/categories/:id', categoryController.update.bind(categoryController));
  app.delete('/categories/:id', categoryController.delete.bind(categoryController));
  app.post('/categories/search', categoryController.search.bind(categoryController));
 */
  // Rutas para usuarios
  app.get("/users", userController.getAll.bind(userController));
  app.get("/users/:id", userController.getById.bind(userController));
  app.post("/users", userController.create.bind(userController));
  app.put("/users/:id", userController.update.bind(userController));
  app.delete("/users/:id", userController.delete.bind(userController));
  app.post("/users/search", userController.search.bind(userController));

  // Rutas para proyectos
  app.get("/projects", projectController.getAll.bind(projectController));
  app.get("/projects/:id", projectController.getById.bind(projectController));
  app.post("/projects", projectController.create.bind(projectController));
  app.put("/projects/:id", projectController.update.bind(projectController));
  app.delete("/projects/:id", projectController.delete.bind(projectController));
  app.post(
    "/projects/search",
    projectController.search.bind(projectController),
  );
  return app;
}

// Ejemplo de uso específico
export class ProductControllerFixed {
  private genericController: GenericController;

  constructor(dbInitializer: DatabaseInitializer) {
    this.genericController = new GenericController(
      dbInitializer,
      productConfig,
    );
  }

  // Delegamos a los métodos genéricos
  async getProducts(c: Context) {
    return this.genericController.getAll(c);
  }

  async getProduct(c: Context) {
    return this.genericController.getById(c);
  }

  async createProduct(c: Context) {
    return this.genericController.create(c);
  }

  async updateProduct(c: Context) {
    return this.genericController.update(c);
  }

  async deleteProduct(c: Context) {
    return this.genericController.delete(c);
  }

  // Método personalizado específico para productos
  /*   async getProductsWithStock(c: Context) {
      try {
        const minStock = parseInt(c.req.query('min_stock') || '1');

        // Usar el método de búsqueda con filtros personalizados
        const searchBody = {
          filters: {
            stock_quantity: { operator: '>=', value: minStock },
            is_available: true
          },
          include_relations: true,
          limit: 50
        };

        // Simular el body de la request para el método search
        c.req.json = async () => searchBody;
        return await this.genericController.search(c);
      } catch (error) {
        return c.json({
          success: false,
          error: 'Failed to get products with stock'
        }, 500);
      }
    } */
}

// Factory function para crear controladores dinámicamente
export function createGenericController<T = any>(
  dbInitializer: DatabaseInitializer,
  tableName: string,
  config: Partial<ControllerConfig> = {},
): GenericController<Record<string, any>> {
  const fullConfig: ControllerConfig = {
    tableName,
    primaryKey: "id",
    defaultOrder: { field: "created_at", direction: "DESC" },
    ...config,
  };

  return new GenericController<Record<string, any>>(dbInitializer, fullConfig);
}

// Ejemplo de uso completo en una aplicación
export const tableConfigs = {
  products: productConfig,
  categories: categoryConfig,
  users: userConfig,
} as Record<string, ControllerConfig>;

// Ejemplos de llamadas a la API

/*
// GET /products?limit=10&category_id=123&include_relations=true
// Obtiene productos con relaciones de categoría

// POST /products
{
  "name": "iPhone 15",
  "price": 999.99,
  "description": "Latest iPhone",
  "category_id": "electronics-123",
  "stock_quantity": 50,
  "is_available": true
}

// PUT /products/product-456
{
  "price": 899.99,
  "stock_quantity": 45
}

// POST /products/search
{
  "filters": {
    "price": { "operator": "<=", "value": 500 },
    "category_id": ["electronics-123", "accessories-456"],
    "is_available": true
  },
  "include_relations": true,
  "limit": 20,
  "offset": 0,
  "orderBy": "price",
  "orderDirection": "ASC"
}

// GET /products/count?is_available=true&category_id=electronics-123

// GET /products/random?limit=5&is_available=true

// POST /products/find-first
{
  "filters": {
    "name": { "operator": "LIKE", "value": "%iPhone%" },
    "is_available": true
  }
}

// POST /products/query
{
  "sql": "SELECT * FROM products WHERE price BETWEEN ? AND ?",
  "params": [100, 500]
}

// GET /products/schema
// Devuelve el esquema de la tabla y la configuración del controlador
*/

export { GenericController };
