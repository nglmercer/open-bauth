// Test wrapper for Hono app that sets up the test environment
import { beforeAll } from "bun:test";

// Set up test environment before importing the app
process.env.NODE_ENV = "test";
process.env.TEST_DB_PATH = process.env.TEST_DB_PATH || "./tests/db/auth.db";

// Import the app after setting environment variables
export { default as app, db, dbInitializer } from "../../examples/hono";
