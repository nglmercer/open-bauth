// tests/database/schema/names/table-names.test.ts
// Tests for custom table names and service-specific schemas

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { DatabaseInitializer } from "../../../../src/database/database-initializer";
import {
  setDatabaseConfig,
  getDatabaseConfig,
  DEFAULT_TABLE_NAMES,
  type DatabaseConfig,
} from "../../../../src/database/config";
import {
  buildDatabaseSchemas,
  getTableSchema,
  getTableSchemaByKey,
} from "../../../../src/database/schema/schema-builder";
import { defaultLogger as logger } from "../../../../src/logger";
import { registerOAuthSchemaExtensions } from "../../../../src/database/schema/oauth-schema-extensions";

describe("Custom Table Names and Service-Specific Schemas", () => {
  let testDb: Database;
  let initializer: DatabaseInitializer;
  const TEST_DB_PATH = "./tests/db/test_table_names.db";

  beforeEach(async () => {
    // Clean up any existing test database
    try {
      const db = new Database(TEST_DB_PATH);
      db.close();
      await Bun.file(TEST_DB_PATH).delete();
    } catch (error) {
      // File doesn't exist, that's fine
    }

    testDb = new Database(TEST_DB_PATH, { create: true });
    initializer = new DatabaseInitializer({
      database: testDb,
      logger: logger,
      enableWAL: true,
      enableForeignKeys: true,
    });

    // Reset to default configuration before each test
    setDatabaseConfig({});
  });

  afterEach(async () => {
    if (testDb) {
      testDb.close();
    }
    try {
      await Bun.file(TEST_DB_PATH).delete();
    } catch (error) {
      // File doesn't exist, that's fine
    }
  });

  describe("Spanish Table Names", () => {
    it("should use Spanish table names for all tables", () => {
      const spanishTableNames = {
        users: "usuarios",
        roles: "roles",
        permissions: "permisos",
        userRoles: "usuario_roles",
        rolePermissions: "rol_permisos",
        sessions: "sesiones",
      };

      const config: DatabaseConfig = {
        tableNames: spanishTableNames,
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();

      expect(schemas).toHaveLength(6);

      // Verify all table names are Spanish
      const tableNames = schemas.map((s) => s.tableName);
      expect(tableNames).toContain("usuarios");
      expect(tableNames).toContain("roles");
      expect(tableNames).toContain("permisos");
      expect(tableNames).toContain("usuario_roles");
      expect(tableNames).toContain("rol_permisos");
      expect(tableNames).toContain("sesiones");

      // Verify no English names remain
      expect(tableNames).not.toContain("users");
      expect(tableNames).not.toContain("permissions");
      expect(tableNames).not.toContain("user_roles");
      expect(tableNames).not.toContain("role_permissions");
      expect(tableNames).not.toContain("sessions");
    });

    it("should initialize database with Spanish table names", async () => {
      const spanishTableNames = {
        users: "usuarios",
        roles: "roles",
        permissions: "permisos",
        userRoles: "usuario_roles",
        rolePermissions: "rol_permisos",
        sessions: "sesiones",
      };

      const config: DatabaseConfig = {
        tableNames: spanishTableNames,
      };

      setDatabaseConfig(config);
      await initializer.reset();

      // Verify Spanish tables exist
      const tableInfo = testDb
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .all() as any[];
      expect(tableInfo.some((t) => t.name === "usuarios")).toBe(true);
      expect(tableInfo.some((t) => t.name === "roles")).toBe(true);
      expect(tableInfo.some((t) => t.name === "permisos")).toBe(true);
      expect(tableInfo.some((t) => t.name === "usuario_roles")).toBe(true);
      expect(tableInfo.some((t) => t.name === "rol_permisos")).toBe(true);
      expect(tableInfo.some((t) => t.name === "sesiones")).toBe(true);

      // Verify English tables don't exist
      expect(tableInfo.some((t) => t.name === "users")).toBe(false);
      expect(tableInfo.some((t) => t.name === "permissions")).toBe(false);
    });

    it("should have correct foreign key references with Spanish table names", async () => {
      const spanishTableNames = {
        users: "usuarios",
        roles: "roles",
        permissions: "permisos",
        userRoles: "usuario_roles",
        rolePermissions: "rol_permisos",
        sessions: "sesiones",
      };

      const config: DatabaseConfig = {
        tableNames: spanishTableNames,
      };

      setDatabaseConfig(config);
      await initializer.reset();

      // Check foreign key constraints in usuario_roles table
      const usuarioRolesFks = testDb
        .prepare("PRAGMA foreign_key_list(usuario_roles)")
        .all() as any[];

      // Should reference usuarios table instead of users
      const usersFk = usuarioRolesFks.find((fk) => fk.table === "usuarios");
      expect(usersFk).toBeDefined();
      expect(usersFk.from).toBe("user_id");
      expect(usersFk.to).toBe("id");

      // Should reference roles table
      const rolesFk = usuarioRolesFks.find((fk) => fk.table === "roles");
      expect(rolesFk).toBeDefined();
      expect(rolesFk.from).toBe("role_id");
      expect(rolesFk.to).toBe("id");
    });

    it("should have correct index names with Spanish table names", async () => {
      const spanishTableNames = {
        users: "usuarios",
        roles: "roles",
        permissions: "permisos",
        userRoles: "usuario_roles",
        rolePermissions: "rol_permisos",
        sessions: "sesiones",
      };

      const config: DatabaseConfig = {
        tableNames: spanishTableNames,
      };

      setDatabaseConfig(config);
      await initializer.reset();

      // Check index names are updated
      const indexInfo = testDb
        .prepare("SELECT name FROM sqlite_master WHERE type='index'")
        .all() as any[];

      expect(indexInfo.some((idx) => idx.name === "idx_usuarios_email")).toBe(
        true,
      );
      expect(indexInfo.some((idx) => idx.name === "idx_roles_name")).toBe(true);
      expect(indexInfo.some((idx) => idx.name === "idx_permisos_name")).toBe(
        true,
      );
      expect(
        indexInfo.some((idx) => idx.name === "idx_usuario_roles_user_id"),
      ).toBe(true);
      expect(
        indexInfo.some((idx) => idx.name === "idx_rol_permisos_role_id"),
      ).toBe(true);
      expect(indexInfo.some((idx) => idx.name === "idx_sesiones_token")).toBe(
        true,
      );
    });
  });

  describe("Service-Specific Table Names", () => {
    it("should use prefixed table names for different services", () => {
      const prefixedTableNames = {
        users: "auth_users",
        roles: "auth_roles",
        permissions: "auth_permissions",
        userRoles: "auth_user_roles",
        rolePermissions: "auth_role_permissions",
        sessions: "auth_sessions",
      };

      const config: DatabaseConfig = {
        tableNames: prefixedTableNames,
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();

      // Verify all table names have auth_ prefix
      const tableNames = schemas.map((s) => s.tableName);
      tableNames.forEach((name) => {
        expect(name).toStartWith("auth_");
      });
    });

    it("should use blog-specific table names", () => {
      const blogTableNames = {
        users: "blog_users",
        roles: "blog_roles",
        permissions: "blog_permissions",
        userRoles: "blog_user_roles",
        rolePermissions: "blog_role_permissions",
        sessions: "blog_sessions",
      };

      const config: DatabaseConfig = {
        tableNames: blogTableNames,
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();

      // Verify all table names have blog_ prefix
      const tableNames = schemas.map((s) => s.tableName);
      tableNames.forEach((name) => {
        expect(name).toStartWith("blog_");
      });

      // Verify specific blog table names
      expect(tableNames).toContain("blog_users");
      expect(tableNames).toContain("blog_roles");
      expect(tableNames).toContain("blog_permissions");
    });

    it("should use e-commerce specific table names", () => {
      const ecommerceTableNames = {
        users: "customers",
        roles: "customer_groups",
        permissions: "permissions", // Keep some default names
        userRoles: "customer_group_memberships",
        rolePermissions: "group_permissions",
        sessions: "customer_sessions",
      };

      const config: DatabaseConfig = {
        tableNames: ecommerceTableNames,
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();

      // Verify e-commerce specific names
      const tableNames = schemas.map((s) => s.tableName);
      expect(tableNames).toContain("customers");
      expect(tableNames).toContain("customer_groups");
      expect(tableNames).toContain("permissions"); // Kept default
      expect(tableNames).toContain("customer_group_memberships");
      expect(tableNames).toContain("group_permissions");
      expect(tableNames).toContain("customer_sessions");
    });
  });

  describe("Mixed Table Names and Schema Extensions", () => {
    it("should combine Spanish table names with schema extensions", () => {
      const spanishTableNames = {
        users: "usuarios",
        roles: "roles",
        permissions: "permisos",
        userRoles: "usuario_roles",
        rolePermissions: "rol_permisos",
        sessions: "sesiones",
      };

      const config: DatabaseConfig = {
        tableNames: spanishTableNames,
        schemaExtensions: {
          users: {
            // Use original key name here, not the custom table name
            additionalColumns: [
              { name: "telefono", type: "TEXT" },
              { name: "direccion", type: "TEXT" },
            ],
          },
          roles: {
            additionalColumns: [{ name: "descripcion_larga", type: "TEXT" }],
          },
        },
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();

      // Find the usuarios schema (should exist with Spanish name)
      const usuariosSchema = schemas.find((s) => s.tableName === "usuarios");
      expect(usuariosSchema).toBeDefined();
      expect(usuariosSchema!.columns.map((c) => c.name)).toContain("telefono");
      expect(usuariosSchema!.columns.map((c) => c.name)).toContain("direccion");

      // Find the roles schema
      const rolesSchema = schemas.find((s) => s.tableName === "roles");
      expect(rolesSchema).toBeDefined();
      expect(rolesSchema!.columns.map((c) => c.name)).toContain(
        "descripcion_larga",
      );
    });

    it("should handle complex service configuration with custom names and extensions", () => {
      const config: DatabaseConfig = {
        tableNames: {
          users: "app_users",
          roles: "app_roles",
          permissions: "app_permissions",
          userRoles: "app_user_roles",
          rolePermissions: "app_role_permissions",
          sessions: "app_sessions",
        },
        schemaExtensions: {
          users: {
            // Use original key name for extensions
            additionalColumns: [
              { name: "profile_picture", type: "TEXT" },
              { name: "preferences", type: "TEXT" }, // JSON
            ],
            removedColumns: ["last_login_at"],
          },
          sessions: {
            additionalColumns: [
              { name: "device_fingerprint", type: "TEXT" },
              { name: "geo_location", type: "TEXT" },
            ],
          },
        },
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();

      // Verify app_users schema
      const appUsersSchema = schemas.find((s) => s.tableName === "app_users");
      expect(appUsersSchema).toBeDefined();
      expect(appUsersSchema!.columns.map((c) => c.name)).toContain(
        "profile_picture",
      );
      expect(appUsersSchema!.columns.map((c) => c.name)).toContain(
        "preferences",
      );
      expect(appUsersSchema!.columns.map((c) => c.name)).not.toContain(
        "last_login_at",
      );

      // Verify app_sessions schema
      const appSessionsSchema = schemas.find(
        (s) => s.tableName === "app_sessions",
      );
      expect(appSessionsSchema).toBeDefined();
      expect(appSessionsSchema!.columns.map((c) => c.name)).toContain(
        "device_fingerprint",
      );
      expect(appSessionsSchema!.columns.map((c) => c.name)).toContain(
        "geo_location",
      );
    });
  });

  describe("Database Operations with Custom Table Names", () => {
    it("should perform CRUD operations on tables with Spanish names", async () => {
      const spanishTableNames = {
        users: "usuarios",
        roles: "roles",
        permissions: "permisos",
        userRoles: "usuario_roles",
        rolePermissions: "rol_permisos",
        sessions: "sesiones",
      };

      const config: DatabaseConfig = {
        tableNames: spanishTableNames,
      };

      setDatabaseConfig(config);
      await initializer.reset();

      // Insert into usuarios table
      const insertUser = testDb.prepare(`
        INSERT INTO usuarios (email, password_hash, first_name, last_name)
        VALUES (?, ?, ?, ?)
      `);

      const userResult = insertUser.run(
        "test@ejemplo.com",
        "hashed_password",
        "Juan",
        "Pérez",
      );
      expect(userResult.lastInsertRowid).toBeDefined();

      // Insert into roles table
      const insertRole = testDb.prepare(`
        INSERT INTO roles (name, description)
        VALUES (?, ?)
      `);

      const roleResult = insertRole.run(
        "administrador",
        "Rol de administrador",
      );
      expect(roleResult.lastInsertRowid).toBeDefined();

      // Query the data
      const user = testDb
        .prepare("SELECT * FROM usuarios WHERE email = ?")
        .get("test@ejemplo.com") as any;
      expect(user).toBeDefined();
      expect(user.first_name).toBe("Juan");
      expect(user.last_name).toBe("Pérez");

      const role = testDb
        .prepare("SELECT * FROM roles WHERE name = ?")
        .get("administrador") as any;
      expect(role).toBeDefined();
      expect(role.description).toBe("Rol de administrador");
    });

    it("should handle foreign key relationships with custom table names", async () => {
      const prefixedTableNames = {
        users: "auth_users",
        roles: "auth_roles",
        permissions: "auth_permissions",
        userRoles: "auth_user_roles",
        rolePermissions: "auth_role_permissions",
        sessions: "auth_sessions",
      };

      const config: DatabaseConfig = {
        tableNames: prefixedTableNames,
      };

      setDatabaseConfig(config);
      await initializer.reset();

      // Insert user
      const insertUser = testDb.prepare(`
        INSERT INTO auth_users (email, password_hash, first_name, last_name)
        VALUES (?, ?, ?, ?)
      `);
      const userResult = insertUser.run(
        "user@auth.com",
        "hash",
        "Auth",
        "User",
      );

      // Get the inserted user ID
      const insertedUser = testDb
        .prepare("SELECT id FROM auth_users WHERE email = ?")
        .get("user@auth.com") as any;
      const userId = insertedUser.id;

      // Insert role
      const insertRole = testDb.prepare(`
        INSERT INTO auth_roles (name, description)
        VALUES (?, ?)
      `);
      const roleResult = insertRole.run("member", "Regular member");

      // Get the inserted role ID
      const insertedRole = testDb
        .prepare("SELECT id FROM auth_roles WHERE name = ?")
        .get("member") as any;
      const roleId = insertedRole.id;

      // Insert user-role relationship
      const insertUserRole = testDb.prepare(`
        INSERT INTO auth_user_roles (user_id, role_id)
        VALUES (?, ?)
      `);
      const userRoleResult = insertUserRole.run(userId, roleId);

      expect(userRoleResult.lastInsertRowid).toBeDefined();

      // Query with JOIN to verify relationships work
      const relationship = testDb
        .prepare(
          `
        SELECT u.email, r.name as role_name
        FROM auth_users u
        JOIN auth_user_roles ur ON u.id = ur.user_id
        JOIN auth_roles r ON ur.role_id = r.id
        WHERE u.id = ?
      `,
        )
        .get(userId) as any;

      expect(relationship).toBeDefined();
      expect(relationship.email).toBe("user@auth.com");
      expect(relationship.role_name).toBe("member");
    });
  });

  describe("Schema Retrieval Functions", () => {
    it("should get schema by custom table name using getTableSchema", () => {
      const config: DatabaseConfig = {
        tableNames: {
          users: "custom_users",
          roles: "custom_roles",
        },
      };

      setDatabaseConfig(config);

      const customUsersSchema = getTableSchema("custom_users");
      expect(customUsersSchema).toBeDefined();
      expect(customUsersSchema!.tableName).toBe("custom_users");

      const customRolesSchema = getTableSchema("custom_roles");
      expect(customRolesSchema).toBeDefined();
      expect(customRolesSchema!.tableName).toBe("custom_roles");

      // Should return null for non-existent table
      const nonExistentSchema = getTableSchema("non_existent");
      expect(nonExistentSchema).toBeNull();
    });

    it("should get schema by key using getTableSchemaByKey", () => {
      const config: DatabaseConfig = {
        tableNames: {
          users: "custom_users",
          roles: "custom_roles",
        },
      };

      setDatabaseConfig(config);

      const usersSchema = getTableSchemaByKey("users");
      expect(usersSchema).toBeDefined();
      expect(usersSchema!.tableName).toBe("custom_users");

      const rolesSchema = getTableSchemaByKey("roles");
      expect(rolesSchema).toBeDefined();
      expect(rolesSchema!.tableName).toBe("custom_roles");
    });

    it("should handle getTableSchemaByKey with non-existent keys", () => {
      // This would fail TypeScript, but let's test runtime behavior
      const schema = getTableSchemaByKey("non_existent" as any);
      expect(schema).toBeNull();
    });
  });

  describe("Edge Cases and Error Handling", () => {
    it("should handle partial table name configuration", () => {
      const config: DatabaseConfig = {
        tableNames: {
          users: "custom_users",
          roles: "custom_roles",
          // Leave others as default
        },
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();

      const tableNames = schemas.map((s) => s.tableName);
      expect(tableNames).toContain("custom_users");
      expect(tableNames).toContain("custom_roles");
      expect(tableNames).toContain("permissions"); // Default
      expect(tableNames).toContain("user_roles"); // Default
      expect(tableNames).toContain("role_permissions"); // Default
      expect(tableNames).toContain("sessions"); // Default
    });

    it("should handle empty table name configuration", () => {
      const config: DatabaseConfig = {
        tableNames: {},
      };

      setDatabaseConfig(config);

      // Register OAuth schemas first
      registerOAuthSchemaExtensions();

      const schemas = buildDatabaseSchemas();

      // Should use all default names (now includes OAuth tables)
      const tableNames = schemas.map((s) => s.tableName);

      // Check that basic table names are present (OAuth tables might not be included in basic build)
      const basicTableNames = [
        "users",
        "roles",
        "permissions",
        "user_roles",
        "role_permissions",
        "sessions",
      ];
      basicTableNames.forEach((tableName) => {
        expect(tableNames).toContain(tableName);
      });

      // Check that we have at least the basic tables
      expect(tableNames.length).toBeGreaterThanOrEqual(basicTableNames.length);
    });

    it("should handle null/undefined table name configuration", () => {
      const config: DatabaseConfig = {
        tableNames: undefined as any,
      };

      setDatabaseConfig(config);

      // Register OAuth schemas first
      registerOAuthSchemaExtensions();

      const schemas = buildDatabaseSchemas();

      // Should use all default names (now includes OAuth tables)
      const tableNames = schemas.map((s) => s.tableName);

      // Check that basic table names are present (OAuth tables might not be included in basic build)
      const basicTableNames = [
        "users",
        "roles",
        "permissions",
        "user_roles",
        "role_permissions",
        "sessions",
      ];
      basicTableNames.forEach((tableName) => {
        expect(tableNames).toContain(tableName);
      });

      // Check that we have at least the basic tables
      expect(tableNames.length).toBeGreaterThanOrEqual(basicTableNames.length);
    });

    it("should handle updating table names configuration", () => {
      // Start with Spanish names
      setDatabaseConfig({
        tableNames: {
          users: "usuarios",
          roles: "roles",
        },
      });

      let schemas = buildDatabaseSchemas();
      let tableNames = schemas.map((s) => s.tableName);
      expect(tableNames).toContain("usuarios");
      expect(tableNames).toContain("roles");

      // Update to prefixed names
      setDatabaseConfig({
        tableNames: {
          users: "auth_users",
          roles: "auth_roles",
        },
      });

      schemas = buildDatabaseSchemas();
      tableNames = schemas.map((s) => s.tableName);
      expect(tableNames).toContain("auth_users");
      expect(tableNames).toContain("auth_roles");
      expect(tableNames).not.toContain("usuarios");
    });
  });

  describe("Multi-Service Scenarios", () => {
    it("should support different table name configurations for different services", async () => {
      // Test authentication service configuration
      const authConfig: DatabaseConfig = {
        tableNames: {
          users: "auth_users",
          roles: "auth_roles",
          permissions: "auth_permissions",
          userRoles: "auth_user_roles",
          rolePermissions: "auth_role_permissions",
          sessions: "auth_sessions",
        },
      };

      setDatabaseConfig(authConfig);
      const authSchemas = buildDatabaseSchemas();
      const authTableNames = authSchemas.map((s) => s.tableName);

      // All tables should have auth_ prefix
      authTableNames.forEach((name) => {
        expect(name).toStartWith("auth_");
      });

      // Reset and test blog service configuration
      const blogConfig: DatabaseConfig = {
        tableNames: {
          users: "blog_users",
          roles: "blog_roles",
          permissions: "blog_permissions",
          userRoles: "blog_user_roles",
          rolePermissions: "blog_role_permissions",
          sessions: "blog_sessions",
        },
      };

      setDatabaseConfig(blogConfig);
      const blogSchemas = buildDatabaseSchemas();
      const blogTableNames = blogSchemas.map((s) => s.tableName);

      // All tables should have blog_ prefix
      blogTableNames.forEach((name) => {
        expect(name).toStartWith("blog_");
      });

      // Verify configurations are different
      expect(authTableNames).not.toEqual(blogTableNames);
    });

    it("should maintain schema consistency across service configurations", () => {
      const serviceConfigurations = [
        {
          name: "Auth Service",
          config: {
            tableNames: {
              users: "auth_users",
              roles: "auth_roles",
            },
          } as DatabaseConfig,
        },
        {
          name: "Blog Service",
          config: {
            tableNames: {
              users: "blog_users",
              roles: "blog_roles",
            },
          } as DatabaseConfig,
        },
        {
          name: "API Service",
          config: {
            tableNames: {
              users: "api_users",
              roles: "api_roles",
            },
          } as DatabaseConfig,
        },
      ];

      serviceConfigurations.forEach(({ name, config }) => {
        setDatabaseConfig(config);
        const schemas = buildDatabaseSchemas();

        // Verify schema structure is consistent across configurations
        const usersSchema = schemas.find((s) => s.tableName.includes("users"));
        const rolesSchema = schemas.find((s) => s.tableName.includes("roles"));

        expect(usersSchema).toBeDefined();
        expect(rolesSchema).toBeDefined();

        // Both should have same column structure regardless of table name
        expect(usersSchema!.columns.map((c) => c.name)).toEqual(
          expect.arrayContaining([
            "id",
            "email",
            "password_hash",
            "first_name",
            "last_name",
          ]),
        );

        expect(rolesSchema!.columns.map((c) => c.name)).toEqual(
          expect.arrayContaining(["id", "name", "description"]),
        );
      });
    });
  });
});
