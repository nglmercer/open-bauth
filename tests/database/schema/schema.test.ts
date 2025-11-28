// tests/database/schema/schema.test.ts
// Tests for the new Schema class and type definitions

import { describe, it, expect, beforeEach } from "bun:test";
import {
  Schema,
  SchemaDefinition,
  SchemaOptions,
  SchemaIndex,
} from "../../../src/database/schema/schema";

describe("Schema Class", () => {
  describe("Basic Schema Creation", () => {
    it("should create a schema with simple field definitions", () => {
      const schema = new Schema({
        id: { type: String, primaryKey: true },
        name: { type: String, required: true },
        email: { type: String, unique: true },
        age: { type: Number },
        active: { type: Boolean, default: true },
      });

      const tableSchema = schema.toTableSchema("users");

      expect(tableSchema.tableName).toBe("users");
      expect(tableSchema.columns).toHaveLength(5);

      const idColumn = tableSchema.columns.find((c) => c.name === "id");
      expect(idColumn?.primaryKey).toBe(true);
      expect(idColumn?.type).toBe("TEXT");

      const nameColumn = tableSchema.columns.find((c) => c.name === "name");
      expect(nameColumn?.notNull).toBe(true);

      const emailColumn = tableSchema.columns.find((c) => c.name === "email");
      expect(emailColumn?.unique).toBe(true);

      const ageColumn = tableSchema.columns.find((c) => c.name === "age");
      expect(ageColumn?.type).toBe("INTEGER");

      const activeColumn = tableSchema.columns.find((c) => c.name === "active");
      expect(activeColumn?.defaultValue).toBe(true);
    });

    it("should handle constructor shortcuts", () => {
      const schema = new Schema({
        id: String, // Simple constructor
        name: { type: String, required: true },
        metadata: {}, // Object becomes TEXT with "{}" default
        tags: [String], // Array becomes TEXT with "[]" default
        created_at: Date, // Date constructor
      });

      const tableSchema = schema.toTableSchema("test");

      expect(tableSchema.columns).toHaveLength(5);

      const idColumn = tableSchema.columns.find((c) => c.name === "id");
      expect(idColumn?.type).toBe("TEXT");

      const metadataColumn = tableSchema.columns.find(
        (c) => c.name === "metadata",
      );
      expect(metadataColumn?.type).toBe("TEXT");
      expect(metadataColumn?.defaultValue).toBe("{}");

      const tagsColumn = tableSchema.columns.find((c) => c.name === "tags");
      expect(tagsColumn?.type).toBe("TEXT");
      expect(tagsColumn?.defaultValue).toBe("[]");

      const createdAtColumn = tableSchema.columns.find(
        (c) => c.name === "created_at",
      );
      expect(createdAtColumn?.type).toBe("DATETIME");
    });

    it("should handle indexes correctly", () => {
      const indexes: SchemaIndex[] = [
        { name: "idx_users_email", columns: ["email"], unique: true },
        { name: "idx_users_active", columns: ["active"] },
        { name: "idx_users_name_age", columns: ["name", "age"] },
      ];
      const options: SchemaOptions = { indexes };
      const schema = new Schema(
        {
          id: { type: String, primaryKey: true },
          email: { type: String },
          active: { type: Boolean },
          name: { type: String },
          age: { type: Number },
        },
        options,
      );

      const tableSchema = schema.toTableSchema("users");

      expect(tableSchema.indexes).toBeDefined();
      expect(tableSchema.indexes).toHaveLength(3);
      expect(tableSchema.indexes![0]).toEqual(indexes[0]);
      expect(tableSchema.indexes![1]).toEqual(indexes[1]);
      expect(tableSchema.indexes![2]).toEqual(indexes[2]);
    });
  });

  describe("Advanced Field Definitions", () => {
    it("should handle references using ref shortcut", () => {
      const schema = new Schema({
        id: { type: String, primaryKey: true },
        user_id: { type: String, ref: "users" },
        role_id: { type: String, ref: "roles" },
      });

      const tableSchema = schema.toTableSchema("assignments");

      const userIdColumn = tableSchema.columns.find(
        (c) => c.name === "user_id",
      );
      expect(userIdColumn?.references).toEqual({
        table: "users",
        column: "id",
      });

      const roleIdColumn = tableSchema.columns.find(
        (c) => c.name === "role_id",
      );
      expect(roleIdColumn?.references).toEqual({
        table: "roles",
        column: "id",
      });
    });

    it("should handle explicit references", () => {
      const schema = new Schema({
        id: { type: String, primaryKey: true },
        user_id: {
          type: String,
          references: { table: "users", column: "uuid" },
        },
      });

      const tableSchema = schema.toTableSchema("user_sessions");

      const userIdColumn = tableSchema.columns.find(
        (c) => c.name === "user_id",
      );
      expect(userIdColumn?.references).toEqual({
        table: "users",
        column: "uuid",
      });
    });

    it("should handle check constraints", () => {
      const schema = new Schema({
        id: { type: String, primaryKey: true },
        age: { type: Number, check: "age >= 0" },
        email: {
          type: String,
          check: "email LIKE '%@%.%'",
        },
        status: {
          type: String,
          default: "active",
          check: "status IN ('active', 'inactive', 'suspended')",
        },
      });

      const tableSchema = schema.toTableSchema("users");

      const ageColumn = tableSchema.columns.find((c) => c.name === "age");
      expect(ageColumn?.check).toBe("age >= 0");

      const emailColumn = tableSchema.columns.find((c) => c.name === "email");
      expect(emailColumn?.check).toBe("email LIKE '%@%.%'");

      const statusColumn = tableSchema.columns.find((c) => c.name === "status");
      expect(statusColumn?.check).toBe(
        "status IN ('active', 'inactive', 'suspended')",
      );
      expect(statusColumn?.defaultValue).toBe("active");
    });

    it("should handle Date.now default values", () => {
      const schema = new Schema({
        id: { type: String, primaryKey: true },
        created_at: { type: Date, default: Date.now },
        updated_at: { type: Date, default: Date.now },
      });

      const tableSchema = schema.toTableSchema("test");

      const createdAtColumn = tableSchema.columns.find(
        (c) => c.name === "created_at",
      );
      expect(createdAtColumn?.defaultValue).toBe("CURRENT_TIMESTAMP");

      const updatedAtColumn = tableSchema.columns.find(
        (c) => c.name === "updated_at",
      );
      expect(updatedAtColumn?.defaultValue).toBe("CURRENT_TIMESTAMP");
    });

    it("should handle function default values", () => {
      const schema = new Schema({
        id: { type: String, primaryKey: true },
        token: {
          type: String,
          default: () => "(lower(hex(randomblob(16))))",
        },
        random_number: {
          type: Number,
          default: () => Math.floor(Math.random() * 1000),
        },
      });

      const tableSchema = schema.toTableSchema("test");

      const tokenColumn = tableSchema.columns.find((c) => c.name === "token");
      expect(tokenColumn?.defaultValue).toBe("(lower(hex(randomblob(16))))");

      const randomNumberColumn = tableSchema.columns.find(
        (c) => c.name === "random_number",
      );
      expect(typeof randomNumberColumn?.defaultValue).toBe("number");
      expect(randomNumberColumn?.defaultValue).toBeGreaterThanOrEqual(0);
      expect(randomNumberColumn?.defaultValue).toBeLessThan(1000);
    });
  });

  describe("Type Mapping", () => {
    it("should map constructor types to SQL types correctly", () => {
      const schema = new Schema({
        id: { type: String, primaryKey: true },
        count: { type: Number },
        active: { type: Boolean },
        created_at: { type: Date },
        metadata: { type: Object },
        tags: { type: Array },
      });

      const tableSchema = schema.toTableSchema("test");

      expect(tableSchema.columns.find((c) => c.name === "id")?.type).toBe(
        "TEXT",
      );
      expect(tableSchema.columns.find((c) => c.name === "count")?.type).toBe(
        "INTEGER",
      );
      expect(tableSchema.columns.find((c) => c.name === "active")?.type).toBe(
        "BOOLEAN",
      );
      expect(
        tableSchema.columns.find((c) => c.name === "created_at")?.type,
      ).toBe("DATETIME");
      expect(tableSchema.columns.find((c) => c.name === "metadata")?.type).toBe(
        "TEXT",
      );
      expect(tableSchema.columns.find((c) => c.name === "tags")?.type).toBe(
        "TEXT",
      );
    });

    it("should handle string types directly", () => {
      const schema = new Schema({
        id: { type: "TEXT", primaryKey: true },
        priority: { type: "INTEGER" },
        enabled: { type: "BOOLEAN" },
        expires_at: { type: "DATETIME" },
      });

      const tableSchema = schema.toTableSchema("test");

      expect(tableSchema.columns.find((c) => c.name === "id")?.type).toBe(
        "TEXT",
      );
      expect(tableSchema.columns.find((c) => c.name === "priority")?.type).toBe(
        "INTEGER",
      );
      expect(tableSchema.columns.find((c) => c.name === "enabled")?.type).toBe(
        "BOOLEAN",
      );
      expect(
        tableSchema.columns.find((c) => c.name === "expires_at")?.type,
      ).toBe("DATETIME");
    });
  });

  describe("Complex Schema Structures", () => {
    it("should handle nested objects correctly", () => {
      const schema = new Schema({
        id: { type: String, primaryKey: true },
        profile: {
          bio: String,
          avatar: String,
          settings: {
            theme: String,
            notifications: Boolean,
          },
        },
        preferences: {
          language: String,
          timezone: String,
        },
      });

      const tableSchema = schema.toTableSchema("users");

      const profileColumn = tableSchema.columns.find(
        (c) => c.name === "profile",
      );
      expect(profileColumn?.type).toBe("TEXT");
      expect(profileColumn?.defaultValue).toBe("{}");

      const preferencesColumn = tableSchema.columns.find(
        (c) => c.name === "preferences",
      );
      expect(preferencesColumn?.type).toBe("TEXT");
      expect(preferencesColumn?.defaultValue).toBe("{}");
    });

    it("should handle arrays correctly", () => {
      const schema = new Schema({
        id: { type: String, primaryKey: true },
        tags: [String],
        numbers: [Number],
        complex: [{ name: String, value: Number }],
      });

      const tableSchema = schema.toTableSchema("test");

      const tagsColumn = tableSchema.columns.find((c) => c.name === "tags");
      expect(tagsColumn?.type).toBe("TEXT");
      expect(tagsColumn?.defaultValue).toBe("[]");

      const numbersColumn = tableSchema.columns.find(
        (c) => c.name === "numbers",
      );
      expect(numbersColumn?.type).toBe("TEXT");
      expect(numbersColumn?.defaultValue).toBe("[]");

      const complexColumn = tableSchema.columns.find(
        (c) => c.name === "complex",
      );
      expect(complexColumn?.type).toBe("TEXT");
      expect(complexColumn?.defaultValue).toBe("[]");
    });
  });

  describe("getColumns Method", () => {
    it("should return columns without creating a table schema", () => {
      const schema = new Schema({
        id: { type: String, primaryKey: true },
        name: { type: String, required: true },
        email: { type: String, unique: true },
      });

      const columns = schema.getColumns();

      expect(columns).toHaveLength(3);
      expect(columns[0].name).toBe("id");
      expect(columns[0].primaryKey).toBe(true);
      expect(columns[1].name).toBe("name");
      expect(columns[1].notNull).toBe(true);
      expect(columns[2].name).toBe("email");
      expect(columns[2].unique).toBe(true);
    });
  });

  describe("Edge Cases", () => {
    it("should handle empty schema", () => {
      const schema = new Schema({});
      const tableSchema = schema.toTableSchema("empty");

      expect(tableSchema.tableName).toBe("empty");
      expect(tableSchema.columns).toHaveLength(0);
      expect(tableSchema.indexes).toBeUndefined();
    });

    it("should handle schema with only options", () => {
      const options: SchemaOptions = {
        indexes: [{ name: "idx_test_name", columns: ["name"] }],
      };

      const schema = new Schema({}, options);
      const tableSchema = schema.toTableSchema("test");

      expect(tableSchema.columns).toHaveLength(0);
      expect(tableSchema.indexes).toBeDefined();
      expect(tableSchema.indexes).toHaveLength(1);
      expect(tableSchema.indexes![0].name).toBe("idx_test_name");
    });

    it("should handle undefined values gracefully", () => {
      const schema = new Schema({
        id: { type: String, primaryKey: true },
        optional_field: { type: String },
        with_default: { type: String, default: "default_value" },
        with_check: { type: String, check: "length(name) > 0" },
      });

      const tableSchema = schema.toTableSchema("test");

      const optionalColumn = tableSchema.columns.find(
        (c) => c.name === "optional_field",
      );
      expect(optionalColumn?.notNull).toBeUndefined();
      expect(optionalColumn?.unique).toBeUndefined();
      expect(optionalColumn?.primaryKey).toBeUndefined();
      expect(optionalColumn?.check).toBeUndefined();

      const withDefaultColumn = tableSchema.columns.find(
        (c) => c.name === "with_default",
      );
      expect(withDefaultColumn?.defaultValue).toBe("default_value");

      const withCheckColumn = tableSchema.columns.find(
        (c) => c.name === "with_check",
      );
      expect(withCheckColumn?.check).toBe("length(name) > 0");
    });
  });

  describe("Real-World Schema Examples", () => {
    it("should handle a complete user profile schema", () => {
      const userProfileSchema = new Schema(
        {
          id: {
            type: String,
            primaryKey: true,
            default: "(lower(hex(randomblob(16))))",
          },
          user_id: {
            type: String,
            ref: "users",
            notNull: true,
          },
          bio: { type: String },
          avatar_url: { type: String },
          phone: {
            type: String,
            check: "phone REGEXP '^[+]?[0-9]{10,15}$'",
          },
          date_of_birth: { type: Date },
          is_verified: {
            type: Boolean,
            default: false,
          },
          preferences: {
            theme: { type: String, default: "light" },
            language: { type: String, default: "en" },
            notifications: { type: Boolean, default: true },
          },
          created_at: { type: Date, default: Date.now },
          updated_at: { type: Date, default: Date.now },
        },
        {
          indexes: [
            {
              name: "idx_user_profiles_user_id",
              columns: ["user_id"],
              unique: true,
            },
            { name: "idx_user_profiles_verified", columns: ["is_verified"] },
            { name: "idx_user_profiles_dob", columns: ["date_of_birth"] },
          ],
        },
      );

      const tableSchema = userProfileSchema.toTableSchema("user_profiles");

      expect(tableSchema.columns).toHaveLength(10); // preferences becomes single TEXT field

      // Check primary key
      const idColumn = tableSchema.columns.find((c) => c.name === "id");
      expect(idColumn?.primaryKey).toBe(true);
      expect(idColumn?.defaultValue).toBe("(lower(hex(randomblob(16))))");

      // Check foreign key
      const userIdColumn = tableSchema.columns.find(
        (c) => c.name === "user_id",
      );
      expect(userIdColumn?.notNull).toBe(true);
      expect(userIdColumn?.references).toEqual({
        table: "users",
        column: "id",
      });

      // Check check constraint
      const phoneColumn = tableSchema.columns.find((c) => c.name === "phone");
      expect(phoneColumn?.check).toBe("phone REGEXP '^[+]?[0-9]{10,15}$'");

      // Check nested object
      const preferencesColumn = tableSchema.columns.find(
        (c) => c.name === "preferences",
      );
      expect(preferencesColumn?.type).toBe("TEXT");
      expect(preferencesColumn?.defaultValue).toBe("{}");

      // Check indexes
      expect(tableSchema.indexes).toHaveLength(3);
      expect(tableSchema.indexes![0].name).toBe("idx_user_profiles_user_id");
      expect(tableSchema.indexes![0].unique).toBe(true);
    });

    it("should handle OAuth client schema", () => {
      const oauthClientSchema = new Schema(
        {
          id: {
            type: String,
            primaryKey: true,
            default: "(lower(hex(randomblob(16))))",
          },
          client_id: {
            type: String,
            required: true,
            unique: true,
          },
          client_secret: { type: String },
          client_name: {
            type: String,
            required: true,
          },
          redirect_uris: {
            type: "TEXT",
            required: true,
          },
          grant_types: {
            type: "TEXT",
            required: true,
          },
          response_types: {
            type: "TEXT",
            required: true,
          },
          scope: {
            type: String,
            default: "",
          },
          logo_uri: { type: String },
          client_uri: { type: String },
          token_endpoint_auth_method: {
            type: String,
            default: "client_secret_basic",
          },
          is_public: {
            type: Boolean,
            default: false,
          },
          is_active: {
            type: Boolean,
            default: true,
          },
          created_at: {
            type: Date,
            default: Date.now,
          },
          updated_at: {
            type: Date,
            default: Date.now,
          },
        },
        {
          indexes: [
            {
              name: "idx_oauth_clients_client_id",
              columns: ["client_id"],
              unique: true,
            },
            {
              name: "idx_oauth_clients_active",
              columns: ["is_active"],
            },
          ],
        },
      );

      const tableSchema = oauthClientSchema.toTableSchema("oauth_clients");

      expect(tableSchema.columns).toHaveLength(15); // Updated to match actual column count

      // Check required fields
      const clientIdColumn = tableSchema.columns.find(
        (c) => c.name === "client_id",
      );
      expect(clientIdColumn?.notNull).toBe(true);
      expect(clientIdColumn?.unique).toBe(true);

      const clientNameColumn = tableSchema.columns.find(
        (c) => c.name === "client_name",
      );
      expect(clientNameColumn?.notNull).toBe(true);

      // Check defaults
      const scopeColumn = tableSchema.columns.find((c) => c.name === "scope");
      expect(scopeColumn?.defaultValue).toBe("");

      const isPublicColumn = tableSchema.columns.find(
        (c) => c.name === "is_public",
      );
      expect(isPublicColumn?.defaultValue).toBe(false);
    });
  });
});
