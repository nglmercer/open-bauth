/**
 * Comprehensive usage example for the custom table names and schema extensions system
 * This file demonstrates how to configure and use the new database configuration system
 */

import { Database } from "bun:sqlite";
import { DatabaseInitializer } from "../../src/database/database-initializer";
import {
  setDatabaseConfig,
  getDatabaseConfig,
  getAllTableNames,
  COMMON_COLUMNS,
  SchemaExtensions,
  createSchemaExtension,
} from "../../src/database/config";
import {
  initializeServices,
  getServices,
} from "../../src/services/service-factory";
import { spanishTableNames, completeCustomConfig } from "./example-config";

// ============================================================================
// EXAMPLE 1: Basic Usage with Default Configuration
// ============================================================================

async function basicUsageExample() {
  console.log("=== Basic Usage Example ===");

  // Create database connection
  const database = new Database(":memory:");

  // Initialize with default configuration
  const dbInitializer = new DatabaseInitializer({
    database: database,
    enableWAL: true,
    enableForeignKeys: true,
  });

  // Initialize database
  await dbInitializer.initialize();

  // Initialize services
  const serviceFactory = initializeServices(dbInitializer);
  const { authService, permissionService } = getServices();

  // Show current table names
  console.log("Default table names:", getAllTableNames());

  // Create a test user
  const registerResult = await authService.register({
    email: "user@example.com",
    password: "password123",
    first_name: "John",
    last_name: "Doe",
  });

  console.log("User created:", registerResult.success ? "Success" : "Failed");
}

// ============================================================================
// EXAMPLE 2: Custom Table Names
// ============================================================================

async function customTableNamesExample() {
  console.log("\n=== Custom Table Names Example ===");

  // Set custom table names BEFORE database initialization
  setDatabaseConfig({
    tableNames: {
      users: "app_users",
      roles: "app_roles",
      permissions: "app_permissions",
      userRoles: "app_user_roles",
      rolePermissions: "app_role_permissions",
      sessions: "app_sessions",
    },
  });

  // Create database connection
  const database = new Database(":memory:");

  // Initialize database with custom table names
  const dbInitializer = new DatabaseInitializer({ database: database });
  await dbInitializer.initialize();

  // Show current table names
  console.log("Custom table names:", getAllTableNames());

  // Initialize services - they will automatically use custom table names
  const serviceFactory = initializeServices(dbInitializer);
  const { authService } = getServices();

  // Create a test user (will be stored in 'app_users' table)
  const registerResult = await authService.register({
    email: "user2@example.com",
    password: "password123",
    first_name: "Jane",
    last_name: "Smith",
  });

  console.log(
    "User created in custom table:",
    registerResult.success ? "Success" : "Failed",
  );
}

// ============================================================================
// EXAMPLE 3: Schema Extensions
// ============================================================================

async function schemaExtensionsExample() {
  console.log("\n=== Schema Extensions Example ===");

  // Reset to default table names but add schema extensions
  setDatabaseConfig({
    schemaExtensions: {
      // Add profile fields to users table
      users: SchemaExtensions.addUserProfileFields(),

      // Add metadata to roles table
      roles: SchemaExtensions.addMetadata(),

      // Add soft delete to sessions table
      sessions: SchemaExtensions.addSoftDelete(),

      // Custom extension for permissions table
      permissions: {
        additionalColumns: [
          { name: "category", type: "TEXT", defaultValue: "general" },
          { name: "priority", type: "INTEGER", defaultValue: 0 },
        ],
      },
    },
  });

  // Create database connection
  const database = new Database(":memory:");

  // Initialize database with extended schemas
  const dbInitializer = new DatabaseInitializer({ database: database });
  await dbInitializer.initialize();

  // Show what was created
  console.log("Database initialized with extended schemas");

  // Get the actual schema to verify extensions
  const usersController = dbInitializer.createControllerByKey("users");
  const userSchema = await usersController.getSchema();

  if (userSchema.success && userSchema.data) {
    console.log(
      "Users table columns:",
      userSchema.data.columns.map((col) => col.name),
    );
  }

  // Initialize services
  const serviceFactory = initializeServices(dbInitializer);
  const { authService } = getServices();

  // Create a user with extended fields
  const registerResult = await authService.register({
    email: "user3@example.com",
    password: "password123",
    first_name: "Bob",
    last_name: "Wilson",
  });

  if (registerResult.success && registerResult.user) {
    // Update user with new extended fields
    await authService.updateUser(registerResult.user.id, {
      phone_number: "+1234567890",
      timezone: "America/New_York",
      language: "en",
    });

    console.log("User created with extended fields");
  }
}

// ============================================================================
// EXAMPLE 4: Complete Custom Configuration
// ============================================================================

async function completeCustomExample() {
  console.log("\n=== Complete Custom Configuration Example ===");

  // Apply complete custom configuration
  setDatabaseConfig(completeCustomConfig);

  // Show current configuration
  const config = getDatabaseConfig();
  console.log("Current table names:", config.tableNames);
  console.log(
    "Schema extensions configured:",
    Object.keys(config.schemaExtensions || {}),
  );

  // Create database connection
  const database = new Database(":memory:");

  // Initialize database with complete custom configuration
  const dbInitializer = new DatabaseInitializer({ database: database });
  await dbInitializer.initialize();

  // Initialize services
  const serviceFactory = initializeServices(dbInitializer);
  const { authService, permissionService } = getServices();

  // Create custom role with extended fields
  const roleResult = await permissionService.createRole({
    name: "custom_admin",
    description: "Custom administrator with extended fields",
  });

  if (roleResult.success && roleResult.role) {
    console.log("Custom role created:", roleResult.role.name);
  }

  // Create user with extended fields
  const registerResult = await authService.register({
    email: "admin@example.com",
    password: "admin123",
    first_name: "Admin",
    last_name: "User",
  });

  if (registerResult.success && registerResult.user) {
    // Assign custom role
    await authService.assignRole(registerResult.user.id, "custom_admin");
    console.log("Admin user created with custom role");
  }
}

// ============================================================================
// EXAMPLE 5: Dynamic Configuration Changes
// ============================================================================

async function dynamicConfigurationExample() {
  console.log("\n=== Dynamic Configuration Example ===");

  // Start with default configuration
  setDatabaseConfig({
    tableNames: { users: "temp_users", roles: "temp_roles" },
  });

  const database = new Database(":memory:");
  const dbInitializer = new DatabaseInitializer({ database: database });

  // Initialize with first configuration
  await dbInitializer.initialize();

  console.log("Initial table names:", getAllTableNames());

  // Update configuration (Note: This requires reinitialization)
  setDatabaseConfig({
    tableNames: {
      users: "final_users",
      roles: "final_roles",
      permissions: "final_permissions",
    },
    schemaExtensions: {
      users: { additionalColumns: [COMMON_COLUMNS.metadata] },
    },
  });

  // Create new database initializer with updated configuration
  const finalDb = new Database(":memory:");
  const finalInitializer = new DatabaseInitializer({ database: finalDb });
  await finalInitializer.initialize();

  console.log("Updated table names:", getAllTableNames());

  // Use service factory with new configuration
  const serviceFactory = initializeServices(finalInitializer);
  const { authService } = getServices();

  const registerResult = await authService.register({
    email: "final@example.com",
    password: "password123",
    first_name: "Final",
    last_name: "User",
  });

  console.log(
    "User created with final configuration:",
    registerResult.success ? "Success" : "Failed",
  );
}

// ============================================================================
// EXAMPLE 6: Advanced Schema Extensions
// ============================================================================

async function advancedSchemaExample() {
  console.log("\n=== Advanced Schema Extensions Example ===");

  // Create advanced custom schema extensions
  setDatabaseConfig({
    tableNames: {
      users: "advanced_users",
      roles: "advanced_roles",
      permissions: "advanced_permissions",
      userRoles: "advanced_user_roles",
      rolePermissions: "advanced_role_permissions",
      sessions: "advanced_sessions",
    },
    schemaExtensions: {
      users: {
        additionalColumns: [
          COMMON_COLUMNS.phoneNumber,
          COMMON_COLUMNS.avatarUrl,
          COMMON_COLUMNS.timezone,
          COMMON_COLUMNS.language,
          COMMON_COLUMNS.metadata,
          { name: "date_of_birth", type: "DATE" },
          { name: "gender", type: "TEXT" },
          { name: "bio", type: "TEXT" },
          { name: "website", type: "TEXT" },
          { name: "is_verified", type: "BOOLEAN", defaultValue: false },
        ],
        modifiedColumns: [
          {
            name: "email",
            type: "TEXT",
            unique: true,
            notNull: true,
            // Add email validation constraint
            check: "email LIKE '%@%.%'",
          },
        ],
      },
      roles: {
        additionalColumns: [
          { name: "level", type: "INTEGER", defaultValue: 1 },
          { name: "color", type: "TEXT", defaultValue: "#007bff" },
          { name: "icon", type: "TEXT" },
          COMMON_COLUMNS.metadata,
        ],
      },
      sessions: {
        additionalColumns: [
          { name: "device_type", type: "TEXT" },
          { name: "device_id", type: "TEXT" },
          { name: "location", type: "TEXT" },
          COMMON_COLUMNS.metadata,
        ],
      },
    },
  });

  const database = new Database(":memory:");
  const dbInitializer = new DatabaseInitializer({ database: database });
  await dbInitializer.initialize();

  // Verify advanced schema
  const usersController = dbInitializer.createControllerByKey("users");
  const schema = await usersController.getSchema();

  if (schema.success && schema.data) {
    console.log("Advanced users table columns:");
    schema.data.columns.forEach((col) => {
      const constraints: string[] = [];
      if (col.notNull) constraints.push("NOT NULL");
      if ("unique" in col && col.unique) constraints.push("UNIQUE");
      if (col.defaultValue) constraints.push(`DEFAULT ${col.defaultValue}`);
      if ("check" in col && col.check) constraints.push(`CHECK(${col.check})`);

      console.log(
        `  - ${col.name}: ${col.type}${constraints.length > 0 ? " (" + constraints.join(", ") + ")" : ""}`,
      );
    });
  }

  // Test with advanced user
  const serviceFactory = initializeServices(dbInitializer);
  const { authService } = getServices();

  const result = await authService.register({
    email: "advanced@example.com",
    password: "password123",
    first_name: "Advanced",
    last_name: "User",
  });

  if (result.success && result.user) {
    // Update with advanced fields
    await authService.updateUser(result.user.id, {
      phone_number: "+1987654321",
      timezone: "Europe/London",
      language: "en",
      metadata: JSON.stringify({
        preferences: { theme: "dark", notifications: true },
        social_links: { twitter: "@advanceduser" },
      }),
    });

    console.log("Advanced user created successfully");
  }
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================

async function runAllExamples() {
  try {
    await basicUsageExample();
    await customTableNamesExample();
    await schemaExtensionsExample();
    await completeCustomExample();
    await dynamicConfigurationExample();
    await advancedSchemaExample();

    console.log("\n=== All Examples Completed Successfully ===");
  } catch (error) {
    console.error("Error running examples:", error);
  }
}

// Export for use in other files
export {
  basicUsageExample,
  customTableNamesExample,
  schemaExtensionsExample,
  completeCustomExample,
  dynamicConfigurationExample,
  advancedSchemaExample,
  runAllExamples,
};

// Run examples if this file is executed directly
// Note: This may not work in all environments, adjust as needed
// if (import.meta.main) {
//   runAllExamples();
// }
