// tests/database/schema/extensions/schema-extensions.test.ts
// Tests for database schema extensions functionality

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { DatabaseInitializer } from "../../../../src/database/database-initializer";
import {
  setDatabaseConfig,
  getDatabaseConfig,
  createSchemaExtension,
  COMMON_COLUMNS,
  SchemaExtensions,
  type DatabaseConfig,
} from "../../../../src/database/config";
import {
  buildDatabaseSchemas,
  getTableSchemaByKey,
} from "../../../../src/database/schema/schema-builder";
import { defaultLogger as logger } from "../../../../src/logger";

describe("Database Schema Extensions", () => {
  let testDb: Database;
  let initializer: DatabaseInitializer;
  const TEST_DB_PATH = "./tests/db/test_schema_extensions.db";

  beforeEach(async () => {
    // Clean up any existing test database
    try {
      const db = new Database(TEST_DB_PATH);
      db.close();
      // Remove the file
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

  describe("Basic Schema Extensions", () => {
    it("should build schemas without extensions using default configuration", () => {
      const schemas = buildDatabaseSchemas();

      expect(schemas).toHaveLength(6);

      const usersSchema = schemas.find((s) => s.tableName === "users");
      expect(usersSchema).toBeDefined();
      expect(usersSchema!.columns).toHaveLength(10); // Now includes username field
      expect(usersSchema!.columns.map((c) => c.name)).toContain("email");
      expect(usersSchema!.columns.map((c) => c.name)).toContain(
        "password_hash",
      );
      expect(usersSchema!.columns.map((c) => c.name)).toContain("username");
    });

    it("should add additional columns to users table", () => {
      const config: DatabaseConfig = {
        schemaExtensions: {
          users: createSchemaExtension([
            COMMON_COLUMNS.phoneNumber,
            COMMON_COLUMNS.avatarUrl,
            { name: "bio", type: "TEXT" },
          ]),
        },
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();
      const usersSchema = schemas.find((s) => s.tableName === "users");

      expect(usersSchema).toBeDefined();
      expect(usersSchema!.columns).toHaveLength(13); // 10 original + 3 additional
      expect(usersSchema!.columns.map((c) => c.name)).toContain("phone_number");
      expect(usersSchema!.columns.map((c) => c.name)).toContain("avatar_url");
      expect(usersSchema!.columns.map((c) => c.name)).toContain("bio");
    });

    it("should modify existing columns in roles table", () => {
      const config: DatabaseConfig = {
        schemaExtensions: {
          roles: createSchemaExtension(
            undefined, // no additional columns
            [
              // modified columns
              {
                name: "name",
                type: "TEXT",
                unique: true,
                notNull: true,
                defaultValue: "'user'", // Add default value
              },
            ],
          ),
        },
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();
      const rolesSchema = schemas.find((s) => s.tableName === "roles");

      expect(rolesSchema).toBeDefined();
      const nameColumn = rolesSchema!.columns.find((c) => c.name === "name");
      expect(nameColumn).toBeDefined();
      expect(nameColumn!.defaultValue).toBe("'user'");
    });

    it("should remove columns from permissions table", () => {
      const config: DatabaseConfig = {
        schemaExtensions: {
          permissions: createSchemaExtension(
            undefined, // no additional columns
            undefined, // no modified columns
            ["description"], // removed columns
          ),
        },
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();
      const permissionsSchema = schemas.find(
        (s) => s.tableName === "permissions",
      );

      expect(permissionsSchema).toBeDefined();
      expect(permissionsSchema!.columns).toHaveLength(5); // 6 original - 1 removed
      expect(permissionsSchema!.columns.map((c) => c.name)).not.toContain(
        "description",
      );
    });

    it("should combine add, modify, and remove operations", () => {
      const config: DatabaseConfig = {
        schemaExtensions: {
          users: createSchemaExtension(
            [
              // additional columns
              COMMON_COLUMNS.phoneNumber,
              COMMON_COLUMNS.metadata,
            ],
            [
              // modified columns
              {
                name: "email",
                type: "TEXT",
                unique: true,
                notNull: true,
                defaultValue: "'unknown@example.com'",
              },
            ],
            [
              // removed columns
              "last_login_at",
            ],
          ),
        },
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();
      const usersSchema = schemas.find((s) => s.tableName === "users");

      expect(usersSchema).toBeDefined();
      expect(usersSchema!.columns).toHaveLength(11); // 10 original - 1 removed + 2 added

      // Check additions
      expect(usersSchema!.columns.map((c) => c.name)).toContain("phone_number");
      expect(usersSchema!.columns.map((c) => c.name)).toContain("metadata");

      // Check modification
      const emailColumn = usersSchema!.columns.find((c) => c.name === "email");
      expect(emailColumn!.defaultValue).toBe("'unknown@example.com'");

      // Check removal
      expect(usersSchema!.columns.map((c) => c.name)).not.toContain(
        "last_login_at",
      );
    });
  });

  describe("Predefined Schema Extensions", () => {
    it("should add soft delete functionality using predefined extension", () => {
      const config: DatabaseConfig = {
        schemaExtensions: {
          users: SchemaExtensions.addSoftDelete(),
        },
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();
      const usersSchema = schemas.find((s) => s.tableName === "users");

      expect(usersSchema).toBeDefined();
      expect(usersSchema!.columns).toHaveLength(12); // 10 original + 2 soft delete columns
      expect(usersSchema!.columns.map((c) => c.name)).toContain("deleted_at");
      expect(usersSchema!.columns.map((c) => c.name)).toContain("is_deleted");
    });

    it("should add audit fields using predefined extension", () => {
      const config: DatabaseConfig = {
        schemaExtensions: {
          roles: SchemaExtensions.addAuditFields(),
        },
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();
      const rolesSchema = schemas.find((s) => s.tableName === "roles");

      expect(rolesSchema).toBeDefined();
      expect(rolesSchema!.columns).toHaveLength(8); // 6 original + 2 audit fields
      expect(rolesSchema!.columns.map((c) => c.name)).toContain("created_by");
      expect(rolesSchema!.columns.map((c) => c.name)).toContain("updated_by");
    });

    it("should add user profile fields using predefined extension", () => {
      const config: DatabaseConfig = {
        schemaExtensions: {
          users: SchemaExtensions.addUserProfileFields(),
        },
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();
      const usersSchema = schemas.find((s) => s.tableName === "users");

      expect(usersSchema).toBeDefined();
      expect(usersSchema!.columns).toHaveLength(14); // 10 original + 4 profile fields
      expect(usersSchema!.columns.map((c) => c.name)).toContain("phone_number");
      expect(usersSchema!.columns.map((c) => c.name)).toContain("avatar_url");
      expect(usersSchema!.columns.map((c) => c.name)).toContain("timezone");
      expect(usersSchema!.columns.map((c) => c.name)).toContain("language");
    });

    it("should replace is_active with status field using predefined extension", () => {
      const config: DatabaseConfig = {
        schemaExtensions: {
          roles: SchemaExtensions.useStatusField(),
        },
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();
      const rolesSchema = schemas.find((s) => s.tableName === "roles");

      expect(rolesSchema).toBeDefined();
      expect(rolesSchema!.columns).toHaveLength(6); // 6 original - 1 removed + 1 added
      expect(rolesSchema!.columns.map((c) => c.name)).not.toContain(
        "is_active",
      );
      expect(rolesSchema!.columns.map((c) => c.name)).toContain("status");

      const statusColumn = rolesSchema!.columns.find(
        (c) => c.name === "status",
      );
      expect(statusColumn!.defaultValue).toBe("active");
    });

    it("should add metadata field using predefined extension", () => {
      const config: DatabaseConfig = {
        schemaExtensions: {
          permissions: SchemaExtensions.addMetadata(),
        },
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();
      const permissionsSchema = schemas.find(
        (s) => s.tableName === "permissions",
      );

      expect(permissionsSchema).toBeDefined();
      expect(permissionsSchema!.columns).toHaveLength(7); // 6 original + 1 metadata
      expect(permissionsSchema!.columns.map((c) => c.name)).toContain(
        "metadata",
      );
    });
  });

  describe("Complex Schema Extensions", () => {
    it("should apply extensions to multiple tables simultaneously", () => {
      const config: DatabaseConfig = {
        schemaExtensions: {
          users: SchemaExtensions.addSoftDelete(),
          roles: SchemaExtensions.addAuditFields(),
          permissions: SchemaExtensions.addMetadata(),
          sessions: createSchemaExtension([
            { name: "device_info", type: "TEXT" },
            { name: "location", type: "TEXT" },
          ]),
        },
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();

      const usersSchema = schemas.find((s) => s.tableName === "users");
      const rolesSchema = schemas.find((s) => s.tableName === "roles");
      const permissionsSchema = schemas.find(
        (s) => s.tableName === "permissions",
      );
      const sessionsSchema = schemas.find((s) => s.tableName === "sessions");

      // Verify users has soft delete
      expect(usersSchema!.columns.map((c) => c.name)).toContain("deleted_at");
      expect(usersSchema!.columns.map((c) => c.name)).toContain("is_deleted");

      // Verify roles has audit fields
      expect(rolesSchema!.columns.map((c) => c.name)).toContain("created_by");
      expect(rolesSchema!.columns.map((c) => c.name)).toContain("updated_by");

      // Verify permissions has metadata
      expect(permissionsSchema!.columns.map((c) => c.name)).toContain(
        "metadata",
      );

      // Verify sessions has custom fields
      expect(sessionsSchema!.columns.map((c) => c.name)).toContain(
        "device_info",
      );
      expect(sessionsSchema!.columns.map((c) => c.name)).toContain("location");
    });

    it("should handle complex column modifications with constraints", () => {
      const config: DatabaseConfig = {
        schemaExtensions: {
          userRoles: createSchemaExtension(
            [
              // additional columns
              {
                name: "assigned_by",
                type: "TEXT",
                notNull: true,
                references: { table: "users", column: "id" },
              },
              {
                name: "expires_at",
                type: "DATETIME",
              },
            ],
            [
              // modified columns
              {
                name: "created_at",
                type: "DATETIME",
                defaultValue: "CURRENT_TIMESTAMP",
                notNull: true,
              },
            ],
          ),
        },
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();
      const userRolesSchema = schemas.find((s) => s.tableName === "user_roles");

      expect(userRolesSchema).toBeDefined();
      expect(userRolesSchema!.columns).toHaveLength(7); // 5 original + 2 added

      // Check additional columns
      const assignedByColumn = userRolesSchema!.columns.find(
        (c) => c.name === "assigned_by",
      );
      expect(assignedByColumn).toBeDefined();
      expect(assignedByColumn!.notNull).toBe(true);
      expect(assignedByColumn!.references).toEqual({
        table: "users",
        column: "id",
      });

      const expiresAtColumn = userRolesSchema!.columns.find(
        (c) => c.name === "expires_at",
      );
      expect(expiresAtColumn).toBeDefined();
      expect(expiresAtColumn!.type).toBe("DATETIME");
    });
  });

  describe("Database Integration with Extensions", () => {
    it("should initialize database with schema extensions", async () => {
      const config: DatabaseConfig = {
        schemaExtensions: {
          users: SchemaExtensions.addUserProfileFields(),
          roles: SchemaExtensions.addAuditFields(),
        },
      };

      setDatabaseConfig(config);
      await initializer.reset();

      // Verify tables exist with extended columns
      const tableInfo = testDb
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .all() as any[];
      expect(tableInfo.some((t) => t.name === "users")).toBe(true);
      expect(tableInfo.some((t) => t.name === "roles")).toBe(true);

      // Verify extended columns exist in users table
      const usersColumns = testDb
        .prepare("PRAGMA table_info(users)")
        .all() as any[];
      expect(usersColumns.some((c) => c.name === "phone_number")).toBe(true);
      expect(usersColumns.some((c) => c.name === "avatar_url")).toBe(true);

      // Verify extended columns exist in roles table
      const rolesColumns = testDb
        .prepare("PRAGMA table_info(roles)")
        .all() as any[];
      expect(rolesColumns.some((c) => c.name === "created_by")).toBe(true);
      expect(rolesColumns.some((c) => c.name === "updated_by")).toBe(true);
    });

    it("should perform CRUD operations on tables with extensions", async () => {
      const config: DatabaseConfig = {
        schemaExtensions: {
          users: SchemaExtensions.addUserProfileFields(),
        },
      };

      setDatabaseConfig(config);
      await initializer.reset();

      // Insert user with extended fields
      const insertStmt = testDb.prepare(`
        INSERT INTO users (email, password_hash, first_name, last_name, phone_number, avatar_url, timezone, language)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const result = insertStmt.run(
        "test@example.com",
        "hashed_password",
        "Test",
        "User",
        "+1234567890",
        "https://example.com/avatar.jpg",
        "America/New_York",
        "en",
      );

      expect(result.lastInsertRowid).toBeDefined();

      // Query user with extended fields
      const user = testDb
        .prepare("SELECT * FROM users WHERE email = ?")
        .get("test@example.com") as any;
      expect(user).toBeDefined();
      expect(user.email).toBe("test@example.com");
      expect(user.phone_number).toBe("+1234567890");
      expect(user.avatar_url).toBe("https://example.com/avatar.jpg");
      expect(user.timezone).toBe("America/New_York");
      expect(user.language).toBe("en");
    });

    it("should handle foreign key constraints with custom table names and extensions", async () => {
      const config: DatabaseConfig = {
        tableNames: {
          users: "app_users",
          roles: "app_roles",
          userRoles: "app_user_roles",
        },
        schemaExtensions: {
          userRoles: createSchemaExtension([
            {
              name: "assigned_by",
              type: "TEXT",
              references: { table: "app_users", column: "id" },
            },
          ]),
        },
      };

      setDatabaseConfig(config);
      await initializer.reset();

      // Verify tables with custom names exist
      const tableInfo = testDb
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .all() as any[];
      expect(tableInfo.some((t) => t.name === "app_users")).toBe(true);
      expect(tableInfo.some((t) => t.name === "app_roles")).toBe(true);
      expect(tableInfo.some((t) => t.name === "app_user_roles")).toBe(true);

      // Verify foreign key constraints are properly set up
      const fkInfo = testDb
        .prepare("PRAGMA foreign_key_list(app_user_roles)")
        .all() as any[];
      expect(fkInfo.length).toBeGreaterThan(0);

      // Check that references point to correct table names
      const userRoleFk = fkInfo.find((fk) => fk.table === "app_users");
      expect(userRoleFk).toBeDefined();
    });
  });

  describe("Edge Cases and Error Handling", () => {
    it("should handle empty schema extensions gracefully", () => {
      const config: DatabaseConfig = {
        schemaExtensions: {},
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();
      expect(schemas).toHaveLength(6);
    });

    it("should handle undefined schema extensions", () => {
      const config: DatabaseConfig = {};

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();
      expect(schemas).toHaveLength(6);
    });

    it("should handle attempts to modify non-existent columns", () => {
      const config: DatabaseConfig = {
        schemaExtensions: {
          users: createSchemaExtension(undefined, [
            { name: "non_existent_column", type: "TEXT" },
          ]),
        },
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();
      const usersSchema = schemas.find((s) => s.tableName === "users");

      // Should not add the non-existent column as a modification
      expect(usersSchema!.columns.map((c) => c.name)).not.toContain(
        "non_existent_column",
      );
    });

    it("should handle attempts to remove non-existent columns", () => {
      const config: DatabaseConfig = {
        schemaExtensions: {
          users: createSchemaExtension(undefined, undefined, [
            "non_existent_column",
          ]),
        },
      };

      setDatabaseConfig(config);
      const schemas = buildDatabaseSchemas();
      const usersSchema = schemas.find((s) => s.tableName === "users");

      // Should have all original columns intact
      expect(usersSchema!.columns).toHaveLength(10);
    });
  });

  describe("Configuration Management", () => {
    it("should reset configuration to defaults", () => {
      // Set custom configuration
      const customConfig: DatabaseConfig = {
        schemaExtensions: {
          users: SchemaExtensions.addSoftDelete(),
        },
      };
      setDatabaseConfig(customConfig);

      // Verify custom config is applied
      let schemas = buildDatabaseSchemas();
      let usersSchema = schemas.find((s) => s.tableName === "users");
      expect(usersSchema!.columns.map((c) => c.name)).toContain("deleted_at");

      // Reset to defaults
      setDatabaseConfig({}, true);

      // Verify defaults are restored
      schemas = buildDatabaseSchemas();
      usersSchema = schemas.find((s) => s.tableName === "users");
      expect(usersSchema!.columns.map((c) => c.name)).not.toContain(
        "deleted_at",
      );
    });

    it("should merge configurations correctly", () => {
      // Set initial configuration
      setDatabaseConfig({
        schemaExtensions: {
          users: SchemaExtensions.addSoftDelete(),
        },
      });

      // Add more configuration
      setDatabaseConfig({
        schemaExtensions: {
          roles: SchemaExtensions.addAuditFields(),
        },
      });

      const schemas = buildDatabaseSchemas();
      const usersSchema = schemas.find((s) => s.tableName === "users");
      const rolesSchema = schemas.find((s) => s.tableName === "roles");

      // Both extensions should be present
      expect(usersSchema!.columns.map((c) => c.name)).toContain("deleted_at");
      expect(rolesSchema!.columns.map((c) => c.name)).toContain("created_by");
    });
  });
});
