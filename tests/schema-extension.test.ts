/**
 * Integration tests for external schema registration with DatabaseInitializer
 * Run with: bun test tests/schema-extension.test.ts
 */

import { describe, test, expect } from "bun:test";
import { Database } from "bun:sqlite";
import {
  BaseController,
  type TableSchema,
} from "../src/database/base-controller";
import {
  DatabaseInitializer,
  SchemaRegistry,
} from "../src/database/database-initializer";

// Define example external schemas used across tests
const pointsSchema: TableSchema = {
  tableName: "points",
  columns: [
    {
      name: "id",
      type: "TEXT",
      primaryKey: true,
      defaultValue: "(lower(hex(randomblob(16))))",
    },
    {
      name: "user_id",
      type: "TEXT",
      notNull: true,
      references: { table: "users", column: "id" },
    },
    { name: "points", type: "INTEGER", notNull: true, defaultValue: 0 },
    { name: "reason", type: "TEXT" },
    { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" },
  ],
  indexes: [
    { name: "idx_points_user_id", columns: ["user_id"] },
    { name: "idx_points_created_at", columns: ["created_at"] },
  ],
};

const notificationsSchema: TableSchema = {
  tableName: "notifications",
  columns: [
    {
      name: "id",
      type: "TEXT",
      primaryKey: true,
      defaultValue: "(lower(hex(randomblob(16))))",
    },
    {
      name: "user_id",
      type: "TEXT",
      notNull: true,
      references: { table: "users", column: "id" },
    },
    { name: "title", type: "TEXT", notNull: true },
    { name: "body", type: "TEXT" },
    { name: "read", type: "BOOLEAN", defaultValue: false },
    { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" },
  ],
  indexes: [
    { name: "idx_notifications_user_id", columns: ["user_id"] },
    { name: "idx_notifications_read", columns: ["read"] },
  ],
};

const processesSchema: TableSchema = {
  tableName: "processes",
  columns: [
    {
      name: "id",
      type: "TEXT",
      primaryKey: true,
      defaultValue: "(lower(hex(randomblob(16))))",
    },
    { name: "name", type: "TEXT", notNull: true, unique: true },
    { name: "status", type: "TEXT", notNull: true },
    { name: "payload", type: "TEXT" },
    { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" },
    { name: "updated_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" },
  ],
  indexes: [{ name: "idx_processes_status", columns: ["status"] }],
};

async function createTestUser(initializer: DatabaseInitializer) {
  const users = initializer.createController("users");
  const res = await users.create({
    email: `user_${Date.now()}@example.com`,
    password_hash: "hashed",
    first_name: "T",
    last_name: "U",
  });
  expect(res.success).toBe(true);
  return res.data as any;
}

describe("Database schema extension integration", () => {
  test("initializes with externalSchemas in constructor and performs CRUD on external table", async () => {
    const db = new Database(":memory:");
    const initializer = new DatabaseInitializer({
      database: db,
      externalSchemas: [pointsSchema],
    });

    const init = await initializer.initialize();
    expect(init.success).toBe(true);
    expect(init.tablesCreated).toContain("points");

    // Create a user (FK target) and then a points record
    const user = await createTestUser(initializer);

    const points = initializer.createController("points");
    const created = await points.create({
      user_id: user.id,
      points: 50,
      reason: "signup_bonus",
    });
    expect(created.success).toBe(true);

    // Query by user_id
    const list = await points.search({ user_id: user.id });
    expect(list.success).toBe(true);
    expect(list.data?.length).toBe(1);
    expect(list.data?.[0]).toMatchObject({ user_id: user.id, points: 50 });
  });

  test("registerSchemas() after construction adds external schema and allows operations", async () => {
    const db = new Database(":memory:");
    const initializer = new DatabaseInitializer({ database: db });

    // Register notifications externally and then initialize
    initializer.registerSchemas(notificationsSchema);
    const init = await initializer.initialize();
    expect(init.success).toBe(true);
    expect(init.tablesCreated).toContain("notifications");

    const user = await createTestUser(initializer);

    const notifications = initializer.createController("notifications");
    const created = await notifications.create({
      user_id: user.id,
      title: "Hello",
      body: "World",
    });
    expect(created.success).toBe(true);

    const unread = await notifications.search({
      user_id: user.id,
      read: false,
    });
    expect(unread.success).toBe(true);
    expect(unread.data?.length).toBe(1);

    // Mark as read
    const updated = await notifications.update((created.data as any).id, {
      read: true,
    });
    expect(updated.success).toBe(true);

    const readNow = await notifications.search({
      user_id: user.id,
      read: true,
    });
    expect(readNow.success).toBe(true);
    expect(readNow.data?.length).toBe(1);
  });

  test("SchemaRegistry merge + externalSchemas works with multiple external tables", async () => {
    const db = new Database(":memory:");

    const r1 = new SchemaRegistry([pointsSchema]);
    const r2 = new SchemaRegistry([processesSchema]);
    const merged = SchemaRegistry.merge(r1, r2);

    const initializer = new DatabaseInitializer({
      database: db,
      externalSchemas: merged.getAll(),
    });
    const init = await initializer.initialize();
    expect(init.success).toBe(true);
    expect(init.tablesCreated).toEqual(
      expect.arrayContaining(["points", "processes"]),
    );

    // Create records in both external tables
    const user = await createTestUser(initializer);

    const points = initializer.createController("points");
    const p = await points.create({
      user_id: user.id,
      points: 10,
      reason: "test",
    });
    expect(p.success).toBe(true);

    const processes = initializer.createController("processes");
    const proc = await processes.create({
      name: `proc_${Date.now()}`,
      status: "queued",
    });
    expect(proc.success).toBe(true);

    const countPoints = await points.count();
    expect(countPoints.success).toBe(true);
    expect(countPoints.data).toBe(1);

    const countProcesses = await processes.count();
    expect(countProcesses.success).toBe(true);
    expect(countProcesses.data).toBe(1);
  });
});

test("notifications.read filters accept Uint8Array/Buffer/boolean equivalents", async () => {
  const db = new Database(":memory:");
  const initializer = new DatabaseInitializer({ database: db });

  // Register notifications schema and initialize
  initializer.registerSchemas(notificationsSchema);
  const init = await initializer.initialize();
  expect(init.success).toBe(true);

  // Create a user and two notifications: one unread (default false) and one read using Uint8Array([1])
  const user = await createTestUser(initializer);
  const notifications = initializer.createController("notifications");

  const n1 = await notifications.create({
    user_id: user.id,
    title: "A",
    body: "Unread default",
  });
  expect(n1.success).toBe(true);

  const n2 = await notifications.create({
    user_id: user.id,
    title: "B",
    body: "Read via Uint8Array",
    read: new Uint8Array([1]),
  });
  expect(n2.success).toBe(true);

  // Search using Uint8Array([0]) should find the unread record
  const searchUnreadBytes = await notifications.search({
    user_id: user.id,
    read: new Uint8Array([0]),
  });
  expect(searchUnreadBytes.success).toBe(true);
  expect(searchUnreadBytes.data?.length).toBeGreaterThanOrEqual(1);

  // Search using Uint8Array([1]) should find the read record
  const searchReadBytes = await notifications.search({
    user_id: user.id,
    read: new Uint8Array([1]),
  });
  expect(searchReadBytes.success).toBe(true);
  expect(searchReadBytes.data?.length).toBeGreaterThanOrEqual(1);

  // Search using Buffer.from([1]) should also work
  const searchReadBuffer = await notifications.search({
    user_id: user.id,
    read: Buffer.from([1]),
  });
  expect(searchReadBuffer.success).toBe(true);
  expect(searchReadBuffer.data?.length).toBeGreaterThanOrEqual(1);

  // Also verify boolean search works when stored as Uint8Array/Buffer
  const searchReadBool = await notifications.search({
    user_id: user.id,
    read: true,
  });
  expect(searchReadBool.success).toBe(true);
  expect(searchReadBool.data?.length).toBeGreaterThanOrEqual(1);

  const searchUnreadBool = await notifications.search({
    user_id: user.id,
    read: false,
  });
  expect(searchUnreadBool.success).toBe(true);
  expect(searchUnreadBool.data?.length).toBeGreaterThanOrEqual(1);

  // Update the unread record to read using Buffer.from([1]) and verify
  const updatedUnread = await notifications.update((n1.data as any).id, {
    read: Buffer.from([1]),
  });
  expect(updatedUnread.success).toBe(true);

  const readNowBytes = await notifications.search({
    user_id: user.id,
    read: new Uint8Array([1]),
  });
  expect(readNowBytes.success).toBe(true);
  // After update, both records should be read
  expect(readNowBytes.data?.length).toBe(2);

  // And boolean search should return both as well
  const readNowBool = await notifications.search({
    user_id: user.id,
    read: true,
  });
  expect(readNowBool.success).toBe(true);
  expect(readNowBool.data?.length).toBe(2);
});

test("can search by IN with mixed boolean representations (boolean, Uint8Array, Buffer)", async () => {
  const db = new Database(":memory:");
  const initializer = new DatabaseInitializer({ database: db });

  initializer.registerSchemas(notificationsSchema);
  const init = await initializer.initialize();
  expect(init.success).toBe(true);

  const user = await createTestUser(initializer);
  const notifications = initializer.createController("notifications");

  const r1 = await notifications.create({
    user_id: user.id,
    title: "C",
    body: "Unread default",
  });
  expect(r1.success).toBe(true);

  const r2 = await notifications.create({
    user_id: user.id,
    title: "D",
    body: "Read via boolean",
    read: true,
  });
  expect(r2.success).toBe(true);

  // Search using IN with [Uint8Array([0]), Buffer([1])] should return both records
  const mixedSearch = await notifications.search({
    user_id: user.id,
    read: [new Uint8Array([0]), Buffer.from([1])],
  } as any);
  expect(mixedSearch.success).toBe(true);
  expect(mixedSearch.data?.length).toBe(2);
});

test("boolean searches are precise and avoid false positives", async () => {
  const db = new Database(":memory:");
  const initializer = new DatabaseInitializer({ database: db });

  initializer.registerSchemas(notificationsSchema);
  const init = await initializer.initialize();
  expect(init.success).toBe(true);

  const user = await createTestUser(initializer);
  const notifications = initializer.createController("notifications");

  // Create notifications with different boolean representations
  const falseDefault = await notifications.create({
    user_id: user.id,
    title: "False Default",
    body: "Should be false by default",
  });
  expect(falseDefault.success).toBe(true);

  const falseExplicit = await notifications.create({
    user_id: user.id,
    title: "False Explicit",
    body: "Explicitly false",
    read: false,
  });
  expect(falseExplicit.success).toBe(true);

  const falseUint8 = await notifications.create({
    user_id: user.id,
    title: "False Uint8Array",
    body: "False via Uint8Array",
    read: new Uint8Array([0]),
  });
  expect(falseUint8.success).toBe(true);

  const falseBuffer = await notifications.create({
    user_id: user.id,
    title: "False Buffer",
    body: "False via Buffer",
    read: Buffer.from([0]),
  });
  expect(falseBuffer.success).toBe(true);

  const trueBoolean = await notifications.create({
    user_id: user.id,
    title: "True Boolean",
    body: "True via boolean",
    read: true,
  });
  expect(trueBoolean.success).toBe(true);

  const trueUint8 = await notifications.create({
    user_id: user.id,
    title: "True Uint8Array",
    body: "True via Uint8Array",
    read: new Uint8Array([1]),
  });
  expect(trueUint8.success).toBe(true);

  const trueBuffer = await notifications.create({
    user_id: user.id,
    title: "True Buffer",
    body: "True via Buffer",
    read: Buffer.from([1]),
  });
  expect(trueBuffer.success).toBe(true);

  // CRITICAL TEST: Search for TRUE should return ONLY true records (4 records)
  const searchTrueBoolean = await notifications.search({
    user_id: user.id,
    read: true,
  });
  expect(searchTrueBoolean.success).toBe(true);
  expect(searchTrueBoolean.data?.length).toBe(3); // Only the 3 true records

  const searchTrueUint8 = await notifications.search({
    user_id: user.id,
    read: new Uint8Array([1]),
  });
  expect(searchTrueUint8.success).toBe(true);
  expect(searchTrueUint8.data?.length).toBe(3); // Should match boolean search

  const searchTrueBuffer = await notifications.search({
    user_id: user.id,
    read: Buffer.from([1]),
  });
  expect(searchTrueBuffer.success).toBe(true);
  expect(searchTrueBuffer.data?.length).toBe(3); // Should match boolean search

  // CRITICAL TEST: Search for FALSE should return ONLY false records (4 records)
  const searchFalseBoolean = await notifications.search({
    user_id: user.id,
    read: false,
  });
  expect(searchFalseBoolean.success).toBe(true);
  expect(searchFalseBoolean.data?.length).toBe(4); // All 4 false records

  const searchFalseUint8 = await notifications.search({
    user_id: user.id,
    read: new Uint8Array([0]),
  });
  expect(searchFalseUint8.success).toBe(true);
  expect(searchFalseUint8.data?.length).toBe(4); // Should match boolean search

  const searchFalseBuffer = await notifications.search({
    user_id: user.id,
    read: Buffer.from([0]),
  });
  expect(searchFalseBuffer.success).toBe(true);
  expect(searchFalseBuffer.data?.length).toBe(4); // Should match boolean search

  // Verify no overlap: true + false should equal total
  const totalRecords = await notifications.count({ user_id: user.id });
  expect(totalRecords.success).toBe(true);
  expect(totalRecords.data).toBe(7);
  expect(
    (searchTrueBoolean.data?.length ?? 0) +
      (searchFalseBoolean.data?.length ?? 0),
  ).toBe(totalRecords.data ?? 0);

  // Verify specific titles to ensure we're getting the right records
  const trueRecordTitles = searchTrueBoolean.data
    ?.map((r: any) => r.title)
    .sort();
  expect(trueRecordTitles).toEqual([
    "True Boolean",
    "True Buffer",
    "True Uint8Array",
  ]);

  const falseRecordTitles = searchFalseBoolean.data
    ?.map((r: any) => r.title)
    .sort();
  expect(falseRecordTitles).toEqual([
    "False Buffer",
    "False Default",
    "False Explicit",
    "False Uint8Array",
  ]);
});

test("edge cases and invalid boolean representations are handled correctly", async () => {
  const db = new Database(":memory:");
  const initializer = new DatabaseInitializer({ database: db });

  initializer.registerSchemas(notificationsSchema);
  const init = await initializer.initialize();
  expect(init.success).toBe(true);

  const user = await createTestUser(initializer);
  const notifications = initializer.createController("notifications");

  // Test: Multi-byte arrays should NOT be treated as boolean
  const multiByteFalse = await notifications.create({
    user_id: user.id,
    title: "Multi Byte False",
    body: "Multi-byte should not be boolean",
    read: new Uint8Array([0, 0]), // This should be treated as BLOB, not boolean
  });
  expect(multiByteFalse.success).toBe(true);

  const multiByteTrue = await notifications.create({
    user_id: user.id,
    title: "Multi Byte True",
    body: "Multi-byte should not be boolean",
    read: new Uint8Array([1, 1]), // This should be treated as BLOB, not boolean
  });
  expect(multiByteTrue.success).toBe(true);

  const regularFalse = await notifications.create({
    user_id: user.id,
    title: "Regular False",
    body: "Regular false",
    read: false,
  });
  expect(regularFalse.success).toBe(true);

  const regularTrue = await notifications.create({
    user_id: user.id,
    title: "Regular True",
    body: "Regular true",
    read: true,
  });
  expect(regularTrue.success).toBe(true);

  // Search for boolean false should NOT match multi-byte arrays
  const searchFalse = await notifications.search({
    user_id: user.id,
    read: false,
  });
  expect(searchFalse.success).toBe(true);
  expect(searchFalse.data?.length).toBe(1); // Only the regular false
  expect(searchFalse.data?.[0].title).toBe("Regular False");

  // Search for boolean true should NOT match multi-byte arrays
  const searchTrue = await notifications.search({
    user_id: user.id,
    read: true,
  });
  expect(searchTrue.success).toBe(true);
  expect(searchTrue.data?.length).toBe(1); // Only the regular true
  expect(searchTrue.data?.[0].title).toBe("Regular True");

  // Search with single-byte Uint8Array should NOT match multi-byte
  const searchUint8False = await notifications.search({
    user_id: user.id,
    read: new Uint8Array([0]),
  });
  expect(searchUint8False.success).toBe(true);
  expect(searchUint8False.data?.length).toBe(1); // Only the regular false
  expect(searchUint8False.data?.[0].title).toBe("Regular False");

  // Verify multi-byte records exist but are not matched by boolean searches
  const allRecords = await notifications.findAll({
    where: { user_id: user.id },
  });
  expect(allRecords.success).toBe(true);
  expect(allRecords.data?.length).toBe(4); // All 4 records exist

  // Test searching with multi-byte arrays should use exact binary comparison
  const searchMultiByteFalse = await notifications.search({
    user_id: user.id,
    read: new Uint8Array([0, 0]),
  });
  expect(searchMultiByteFalse.success).toBe(true);
  expect(searchMultiByteFalse.data?.length).toBe(1);
  expect(searchMultiByteFalse.data?.[0].title).toBe("Multi Byte False");

  const searchMultiByteTrue = await notifications.search({
    user_id: user.id,
    read: new Uint8Array([1, 1]),
  });
  expect(searchMultiByteTrue.success).toBe(true);
  expect(searchMultiByteTrue.data?.length).toBe(1);
  expect(searchMultiByteTrue.data?.[0].title).toBe("Multi Byte True");
});

test("IN queries with mixed boolean representations work precisely", async () => {
  const db = new Database(":memory:");
  const initializer = new DatabaseInitializer({ database: db });

  initializer.registerSchemas(notificationsSchema);
  const init = await initializer.initialize();
  expect(init.success).toBe(true);

  const user = await createTestUser(initializer);
  const notifications = initializer.createController("notifications");

  // Create records with different boolean representations
  await notifications.create({
    user_id: user.id,
    title: "A",
    body: "Default false",
  });
  await notifications.create({
    user_id: user.id,
    title: "B",
    body: "Explicit false",
    read: false,
  });
  await notifications.create({
    user_id: user.id,
    title: "C",
    body: "Uint8 false",
    read: new Uint8Array([0]),
  });
  await notifications.create({
    user_id: user.id,
    title: "D",
    body: "Buffer false",
    read: Buffer.from([0]),
  });
  await notifications.create({
    user_id: user.id,
    title: "E",
    body: "Boolean true",
    read: true,
  });
  await notifications.create({
    user_id: user.id,
    title: "F",
    body: "Uint8 true",
    read: new Uint8Array([1]),
  });
  await notifications.create({
    user_id: user.id,
    title: "G",
    body: "Buffer true",
    read: Buffer.from([1]),
  });
  await notifications.create({
    user_id: user.id,
    title: "H",
    body: "Multi-byte",
    read: new Uint8Array([0, 1]),
  });

  // Test IN with boolean values
  const searchBooleanIn = await notifications.search({
    user_id: user.id,
    read: [true, false],
  } as any);
  expect(searchBooleanIn.success).toBe(true);
  expect(searchBooleanIn.data?.length).toBe(7); // All except multi-byte

  // Test IN with mixed types - should handle each correctly
  const searchMixedIn = await notifications.search({
    user_id: user.id,
    read: [new Uint8Array([0]), Buffer.from([1]), false],
  } as any);
  expect(searchMixedIn.success).toBe(true);
  expect(searchMixedIn.data?.length).toBe(7); // All except multi-byte

  // Test IN with only true values in different representations
  const searchTrueIn = await notifications.search({
    user_id: user.id,
    read: [true, new Uint8Array([1]), Buffer.from([1])],
  } as any);
  expect(searchTrueIn.success).toBe(true);
  expect(searchTrueIn.data?.length).toBe(3); // Only true records

  const trueTitles = searchTrueIn.data?.map((r: any) => r.title).sort();
  expect(trueTitles).toEqual(["E", "F", "G"]);

  // Test IN with only false values in different representations
  const searchFalseIn = await notifications.search({
    user_id: user.id,
    read: [false, new Uint8Array([0]), Buffer.from([0])],
  } as any);
  expect(searchFalseIn.success).toBe(true);
  expect(searchFalseIn.data?.length).toBe(4); // Only false records

  const falseTitles = searchFalseIn.data?.map((r: any) => r.title).sort();
  expect(falseTitles).toEqual(["A", "B", "C", "D"]);

  // Test IN with multi-byte should only match exact multi-byte
  const searchMultiByteIn = await notifications.search({
    user_id: user.id,
    read: [new Uint8Array([0, 1]), new Uint8Array([1, 0])],
  } as any);
  expect(searchMultiByteIn.success).toBe(true);
  expect(searchMultiByteIn.data?.length).toBe(1); // Only the multi-byte record
  expect(searchMultiByteIn.data?.[0].title).toBe("H");
});
