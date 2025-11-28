/**
 * Minimalist Test Suite for BaseController
 * Run with: bun test base-controller.test.ts
 */

import { test, expect, beforeEach, describe } from "bun:test";
import { Database } from "bun:sqlite";
import {
  BaseController,
  type TableSchema,
} from "../src/database/base-controller";

// Test interfaces
interface User {
  id: number;
  name: string;
  email: string;
  age?: number;
  created_at?: string;
  updated_at?: string;
  is_active: boolean;
}

// Test schema
const userSchema: TableSchema = {
  tableName: "users",
  columns: [
    { name: "id", type: "INTEGER", primaryKey: true, autoIncrement: true },
    { name: "name", type: "TEXT", notNull: true },
    { name: "email", type: "TEXT", notNull: true, unique: true },
    { name: "age", type: "INTEGER" },
    { name: "is_active", type: "BOOLEAN", defaultValue: true },
  ],
};

describe("BaseController", () => {
  let db: Database;
  let controller: BaseController<User>;

  beforeEach(async () => {
    // Fresh in-memory database for each test
    db = new Database(":memory:");

    // Initialize database
    const initResult = await BaseController.initializeDatabase(
      db,
      [userSchema],
      true
    );
    expect(initResult.success).toBe(true);

    // Create controller
    controller = new BaseController<User>("users", {
      database: db,
      isSQLite: true,
    });
  });

  test("should create a record", async () => {
    const result = await controller.create({
      name: "John Doe",
      email: "john@test.com",
      age: 25,
      is_active: true,
    });

    expect(result.success).toBe(true);
    expect(result.data).toMatchObject({
      name: "John Doe",
      email: "john@test.com",
      age: 25,
    });
    expect(result.data?.id).toBeGreaterThan(0);
  });

  test("should find record by ID", async () => {
    const createResult = await controller.create({
      name: "Jane Smith",
      email: "jane@test.com",
    });

    const findResult = await controller.findById(createResult.data!.id);

    expect(findResult.success).toBe(true);
    expect(findResult.data?.name).toBe("Jane Smith");
  });

  test("should update a record", async () => {
    const createResult = await controller.create({
      name: "Bob Wilson",
      email: "bob@test.com",
      age: 30,
    });

    const updateResult = await controller.update(createResult.data!.id, {
      age: 31,
      name: "Bob Updated",
    });

    expect(updateResult.success).toBe(true);
    expect(updateResult.data?.age).toBe(31);
    expect(updateResult.data?.name).toBe("Bob Updated");
  });

  test("should delete a record", async () => {
    const createResult = await controller.create({
      name: "Alice Brown",
      email: "alice@test.com",
    });

    const deleteResult = await controller.delete(createResult.data!.id);
    expect(deleteResult.success).toBe(true);

    const findResult = await controller.findById(createResult.data!.id);
    expect(findResult.success).toBe(false);
  });

  test("should search with filters", async () => {
    await controller.create({
      name: "User1",
      email: "user1@test.com",
      is_active: true,
    });
    await controller.create({
      name: "User2",
      email: "user2@test.com",
      is_active: false,
    });
    await controller.create({
      name: "User3",
      email: "user3@test.com",
      is_active: true,
    });

    const activeUsers = await controller.search({ is_active: true });

    expect(activeUsers.success).toBe(true);
    expect(activeUsers.data?.length).toBe(2);
    expect(activeUsers.total).toBe(2);
  });

  test("should count records", async () => {
    await controller.create({ name: "Count1", email: "count1@test.com" });
    await controller.create({ name: "Count2", email: "count2@test.com" });

    const countResult = await controller.count();

    expect(countResult.success).toBe(true);
    expect(countResult.data).toBe(2);
  });

  test("should handle findFirst", async () => {
    await controller.create({
      name: "First Test",
      email: "first@test.com",
      age: 25,
    });

    const result = await controller.findFirst({ age: 25 });

    expect(result.success).toBe(true);
    expect(result.data?.name).toBe("First Test");
  });

  test("should return null for findFirst with no matches", async () => {
    const result = await controller.findFirst({ age: 999 });

    expect(result.success).toBe(true);
    expect(result.data).toBe(null);
  });

  test("should handle pagination", async () => {
    // Create test data
    for (let i = 1; i <= 5; i++) {
      await controller.create({
        name: `User${i}`,
        email: `user${i}@test.com`,
        age: 20 + i,
      });
    }

    const page1 = await controller.findAll({
      limit: 2,
      offset: 0,
      orderBy: "id",
    });
    const page2 = await controller.findAll({
      limit: 2,
      offset: 2,
      orderBy: "id",
    });

    expect(page1.success).toBe(true);
    expect(page1.data?.length).toBe(2);
    expect(page1.total).toBe(5);

    expect(page2.success).toBe(true);
    expect(page2.data?.length).toBe(2);
    expect(page2.data?.[0].name).toBe("User3");
  });

  test("should handle boolean filters correctly", async () => {
    await controller.create({
      name: "Active",
      email: "active@test.com",
      is_active: true,
    });
    await controller.create({
      name: "Inactive",
      email: "inactive@test.com",
      is_active: false,
    });

    const activeResult = await controller.search({ is_active: true });
    const inactiveResult = await controller.search({ is_active: false });

    expect(activeResult.data?.length).toBe(1);
    expect(activeResult.data?.[0].name).toBe("Active");

    expect(inactiveResult.data?.length).toBe(1);
    expect(inactiveResult.data?.[0].name).toBe("Inactive");
  });

  test("should execute custom queries", async () => {
    await controller.create({
      name: "Query Test",
      email: "query@test.com",
      age: 30,
    });

    const result = await controller.query(
      "SELECT name, age FROM users WHERE age > ?",
      [25]
    );

    expect(result.success).toBe(true);
    expect((result.data as any[]).length).toBe(1);
    expect((result.data as any[])[0].name).toBe("Query Test");
  });

  test("should get schema information", async () => {
    const schemaResult = await controller.getSchema();
    console.log("schemaResult", schemaResult.data);
    expect(schemaResult.success).toBe(true);
    expect(schemaResult?.data?.tableName).toBe("users");
    expect(schemaResult?.data?.columns).toBeArray();
  });

  test("should handle validation errors gracefully", async () => {
    const result = await controller.create({});

    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  test("should handle non-existent record updates", async () => {
    const result = await controller.update(999, { name: "Not Found" });

    expect(result.success).toBe(false);
    expect(result.error).toContain("not found");
  });

  test("should handle non-existent record deletion", async () => {
    const result = await controller.delete(999);

    expect(result.success).toBe(false);
    expect(result.error).toBe("Record not found");
  });
  test("should handle random records with various scenarios", async () => {
    // Create test records
    const testRecords = [
      { name: "Random1", email: "random1@test.com", age: 25, is_active: true },
      { name: "Random2", email: "random2@test.com", age: 30, is_active: false },
      { name: "Random3", email: "random3@test.com", age: 35, is_active: true },
    ];

    for (const record of testRecords) {
      await controller.create(record);
    }

    const randomResult = await controller.random({});
    expect(randomResult.success).toBe(true);
    expect(randomResult.data?.length).toBe(1);
    expect(testRecords.map((r) => r.name)).toContain(
      (randomResult.data as any[])[0].name
    );

    const activeRandomResult = await controller.random({ is_active: true });
    expect(activeRandomResult.success).toBe(true);
    expect(
      typeof activeRandomResult.data?.[0].is_active === "boolean"
        ? activeRandomResult.data?.[0].is_active
        : Boolean(activeRandomResult.data?.[0].is_active)
    ).toBe(true);

    const multipleRandomResult = await controller.random({}, 2);
    expect(multipleRandomResult.success).toBe(true);
    expect(multipleRandomResult.data?.length).toBe(2);
    expect(new Set(multipleRandomResult.data?.map((r) => r.name)).size).toBe(2);
    const noMatchResult = await controller.random({ age: 999 });
    expect(noMatchResult.success).toBe(true);
    expect(noMatchResult.data?.length).toBe(0);
    const badFilterResult = await controller.random({
      age: { invalid: "value" } as any,
    });

    expect(badFilterResult.success).toBe(false);
    expect(badFilterResult.error).toBeDefined();
  });
  test("should get a random record using existing controller methods", async () => {
    await controller.create({ name: "User A", email: "a@test.com" });
    await controller.create({ name: "User B", email: "b@test.com" });
    await controller.create({ name: "User C", email: "c@test.com" });
    const countResponse = await controller.count();
    expect(countResponse.success).toBe(true);
    const totalUsers = countResponse.data!;
    expect(totalUsers).toBe(3);
    const randomOffset = Math.floor(Math.random() * totalUsers);

    const randomUserResponse = await controller.findAll({
      limit: 1,
      offset: randomOffset,
      orderBy: "id",
    });

    expect(randomUserResponse.success).toBe(true);
    expect(randomUserResponse.data).toBeArray();
    expect(randomUserResponse.data?.length).toBe(1);

    const randomUser = randomUserResponse.data![0];
    console.log(
      `Random user selected (offset ${randomOffset}):`,
      randomUser.name
    );

    const validNames = ["User A", "User B", "User C"];
    expect(validNames).toContain(randomUser.name);
  });
  async function getRandomUsers(
    controller: BaseController<User>,
    limit: number
  ): Promise<User[]> {
    const countResponse = await controller.count();
    if (
      !countResponse.success ||
      !countResponse.data ||
      countResponse.data === 0
    ) {
      return [];
    }

    const total = countResponse.data;
    const finalLimit = Math.min(limit, total);
    const offsets = new Set<number>();

    while (offsets.size < finalLimit) {
      const randomOffset = Math.floor(Math.random() * total);
      offsets.add(randomOffset);
    }

    const results: User[] = [];
    for (const offset of offsets) {
      const response = await controller.findAll({
        limit: 1,
        offset,
        orderBy: "id",
      });
      if (response.success && response.data?.length === 1) {
        results.push(response.data[0]);
      }
    }

    return results;
  }

  test("should get multiple random records using external logic", async () => {
    await controller.create({ name: "User A", email: "a@test.com" });
    await controller.create({ name: "User B", email: "b@test.com" });
    await controller.create({ name: "User C", email: "c@test.com" });

    const randomUsers = await getRandomUsers(controller, 2);

    expect(randomUsers.length).toBe(2);
    const ids = new Set(randomUsers.map((u) => u.id));
    expect(ids.size).toBe(2);
    console.log(
      "Selected random users:",
      randomUsers.map((u) => u.name)
    );
  });
});
