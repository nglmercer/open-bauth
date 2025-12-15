import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { SQLiteSchemaExtractor } from "../../../src/database/schema/schema-extractor";
import { SchemaComparator } from "../../../src/database/schema/schema-comparison";
import { SQLiteMigrationGenerator } from "../../../src/database/schema/migration-generator";
import { DatabaseInitializer } from "../../../src/database/database-initializer";
import { Schema } from "../../../src/database/schema/schema";
import type { TableSchema } from "../../../src/database/base-controller";
import { SchemaRegistry } from "../../../src/database/database-initializer";
import { getOAuthSchemas } from "../../../src/database/schema/oauth-schema-extensions";
import { BaseController } from "../../../src/database/base-controller";
const newschemas = new Schema({
    id: { type: String, primaryKey: true },
    name: { type: String, required: true }
}).toTableSchema("users");
const timeschemas = new Schema({
    id: { type: String, primaryKey: true },
    created_at: { type: Date, required: true },
    updated_at: { type: Date, required: true }
}).toTableSchema("users");
const registry = new SchemaRegistry();
registry.register(newschemas);
registry.register(timeschemas);

describe("Schema Migration System", () => {
    let db: Database;
    let extractor: SQLiteSchemaExtractor;
    let dbInitializer: DatabaseInitializer;
    beforeEach(() => {
        db = new Database(":memory:");
        extractor = new SQLiteSchemaExtractor(db);
        dbInitializer = new DatabaseInitializer({
            database: db,
            externalSchemas: registry.getAll(),
        });
        dbInitializer.initialize();
    });

    afterEach(async () => {
        await extractor.close();
        db.close();
    });

  it("should generate SQL to create missing tables", async () => {
    // Current: Empty
    const currentSchemas: TableSchema[] = [];
    
    // Target: One table
    const targetSchema = new Schema({
        id: { type: String, primaryKey: true },
        name: { type: String, required: true }
    }).toTableSchema("users");

    const diff = SchemaComparator.compareSchemas(currentSchemas, [targetSchema]);
    expect(diff.tableDiffs).toHaveLength(1);
    expect(diff.tableDiffs[0].changeType).toBe("CREATE");

    const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
    expect(sql).toHaveLength(1);
    expect(sql[0]).toContain('CREATE TABLE IF NOT EXISTS "users"');
    
    // Apply
    db.run(sql[0]);
    
    const tables = await extractor.getAllTableNames();
    expect(tables).toContain("users");
  });

  it("should generate SQL to add missing columns", async () => {
    // Initial State
    db.run(`DROP TABLE IF EXISTS users`);
    db.run(`CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT NOT NULL);`);
    
    // Current state extraction
    const currentSchemas = await extractor.extractAsTableSchemas();
    
    // Target Schema (added 'email')
    const targetSchema = new Schema({
        id: { type: String, primaryKey: true },
        name: { type: String, required: true },
        email: { type: String } // New column
    }).toTableSchema("users");

    const diff = SchemaComparator.compareSchemas(currentSchemas, [targetSchema]);
    const tableDiff = diff.tableDiffs.find(t => t.tableName === "users");
    
    expect(tableDiff).toBeDefined();
    expect(tableDiff!.changeType).toBe("ALTER");
    expect(tableDiff!.columnDiffs).toHaveLength(1);
    expect(tableDiff!.columnDiffs[0].changeType).toBe("CREATE");
    expect(tableDiff!.columnDiffs[0].columnName).toBe("email");

    const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
    expect(sql.some(s => s.includes('ADD COLUMN "email" TEXT'))).toBe(true);
    
    // Apply (loop mostly for safety if multiple statements)
    for (const stmt of sql) db.run(stmt);
    
    const newSchema = await extractor.extractTableSchema("users");
    expect(newSchema!.tableSchema.columns.find(c => c.name === "email")).toBeDefined();
  });

  it("should generate SQL to drop extra columns", async () => {
    // Initial State
    db.run(`DROP TABLE IF EXISTS users`);
    db.run(`CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT NOT NULL, extra TEXT);`);

    
    // extraction
    const currentSchemas = await extractor.extractAsTableSchemas();
    
    // Target Schema (removed 'extra')
    const targetSchema = new Schema({
        id: { type: String, primaryKey: true },
        name: { type: String, required: true }
    }).toTableSchema("users");

    const diff = SchemaComparator.compareSchemas(currentSchemas, [targetSchema]);
    const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
    
    expect(sql.some(s => s.includes('DROP COLUMN "extra"'))).toBe(true);

    // Apply
    for (const stmt of sql) db.run(stmt);

    const newSchema = await extractor.extractTableSchema("users");
    expect(newSchema!.tableSchema.columns.find(c => c.name === "extra")).toBeUndefined();
  });

  it("should generate SQL to create new indexes", async () => {
      // Initial
      db.run(`DROP TABLE IF EXISTS users`);
      db.run(`CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT);`);
      const currentSchemas = await extractor.extractAsTableSchemas();

      // Target (add index on email)
      const targetSchema = new Schema(
          { id: { type: String, primaryKey: true }, email: String },
          { indexes: [{ name: "idx_email", columns: ["email"] }] }
      ).toTableSchema("users");

      const diff = SchemaComparator.compareSchemas(currentSchemas, [targetSchema]);
      const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
      
      expect(sql.some(s => s.includes('CREATE INDEX IF NOT EXISTS "idx_email"'))).toBe(true);
      
      for (const stmt of sql) db.run(stmt);
      
      const newSchema = await extractor.extractTableSchema("users");
      expect(newSchema!.tableSchema.indexes?.find(i => i.name === "idx_email")).toBeDefined();
  });

  describe("Edge Cases", () => {
    it("should fail when adding a NOT NULL column without default value to populated table", async () => {
        // Setup populated table
        db.run(`CREATE TABLE products (id TEXT PRIMARY KEY, name TEXT);`);
        db.run(`INSERT INTO products (id, name) VALUES ('1', 'Product A');`);

        const currentSchemas = await extractor.extractAsTableSchemas();
        
        // Target: Add required price column
        const targetSchema = new Schema({
            id: { type: String, primaryKey: true },
            name: { type: String },
            price: { type: Number, required: true } // NOT NULL, no default
        }).toTableSchema("products");

        const diff = SchemaComparator.compareSchemas(currentSchemas, [targetSchema]);
        const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);

        // SQLite allows adding NOT NULL column ONLY if it has a default value (except for newer versions which might allow it if table is empty, but here it is populated)
        // However, standard SQLite behavior forbids adding NOT NULL column to populated table without DEFAULT.
        
        expect(sql.length).toBeGreaterThan(0);
        
        // Try to execute - should fail
        expect(() => {
            for (const stmt of sql) db.run(stmt);
        }).toThrow(/NOT NULL constraint failed|Cannot add a NOT NULL column with default value NULL/i);
    });

    it("should handle default values correctly for boolean and numbers", async () => {
        db.run(`CREATE TABLE settings (id TEXT PRIMARY KEY);`);
        const currentSchemas = await extractor.extractAsTableSchemas();

        const targetSchema = new Schema({
            id: { type: String, primaryKey: true },
            is_active: { type: Boolean, default: true },
            max_retries: { type: Number, default: 5 }
        }).toTableSchema("settings");

        const diff = SchemaComparator.compareSchemas(currentSchemas, [targetSchema]);
        const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
        
        const activeSql = sql.find(s => s.includes("is_active"));
        const retriesSql = sql.find(s => s.includes("max_retries"));
        
        // Check generated SQL content
        expect(activeSql).toContain("DEFAULT 1"); // Boolean true -> 1
        expect(retriesSql).toContain("DEFAULT 5");
        
        // Execute
        for (const stmt of sql) db.run(stmt);
        
        // Check new row has defaults
        db.run(`INSERT INTO settings (id) VALUES ('config1');`);
        const row = db.query(`SELECT * FROM settings WHERE id = 'config1'`).get() as any;
        
        expect(row.is_active).toBe(1);
        expect(row.max_retries).toBe(5);
    });

    it("should detect complex type changes as warnings (simulated)", async () => {
        // Although we can't easily capture console.warn in Bun test without mocking,
        // we can verify the SQL generator returns the commented warnings or nothing safe for execution.
        
        db.run(`CREATE TABLE metadata (id TEXT PRIMARY KEY, value INTEGER);`);
        const currentSchemas = await extractor.extractAsTableSchemas();
        
        // Change 'value' from INTEGER to TEXT
        const targetSchema = new Schema({
            id: { type: String, primaryKey: true },
            value: { type: String } // Type change
        }).toTableSchema("metadata");
        
        const diff = SchemaComparator.compareSchemas(currentSchemas, [targetSchema]);
        const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
        
        // We shouldn't receive any functional SQL for this column change in the current implementation
        // because we decided to just log warnings for complex alters.
        // Assuming we didn't add any OTHER columns, the SQL list might be empty or contain other ops.
        // But for *this* column, no ALTER TABLE ... statements should mistakenly try to change type directly.
        
        // Our generator implementation logs warnings and does NOT return SQL for complex column alters.
        // So we expect no SQL related to 'value' column modification (SQLite doesn't support it directly).
        expect(sql.every(s => !s.includes('ALTER TABLE "metadata" ALTER COLUMN'))).toBe(true);
    });

    it("should validate Zod schemas match the db structure via Schema class", () => {
         const schemaDef = new Schema({
             id: { type: String, primaryKey: true },
             age: { type: Number, required: true }
         });
         
         const zodSchema = schemaDef.toZod();
         
         // Valid date
         expect(zodSchema.create.parse({ id: "1", age: 20 })).toEqual({ id: "1", age: 20 });
         
         // Invalid data (missing age)
         expect(zodSchema.create.safeParse({ id: "1" }).success).toBe(false);
         
         // Ensures standard field types are mapped correctly
         const tableSchema = schemaDef.toTableSchema("test");
         expect(tableSchema.columns.find(c => c.name === "age")!.type).toBe("INTEGER");
    });
  });

  describe("OAuth Schemas Integration", () => {
      it("should generate migrations for all OAuth schemas from empty db", async () => {
          const oauthSchemas = getOAuthSchemas();
          const currentSchemas = await extractor.extractAsTableSchemas(); 
          
          const diff = SchemaComparator.compareSchemas(currentSchemas, oauthSchemas);
          const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
          
          expect(sql.length).toBeGreaterThan(0);
          expect(sql.some(s => s.includes('CREATE TABLE IF NOT EXISTS "oauth_clients"'))).toBe(true);
          expect(sql.some(s => s.includes('CREATE TABLE IF NOT EXISTS "refresh_tokens"'))).toBe(true);
          
          // Execute
          for(const stmt of sql) db.run(stmt);
          
          const newTables = await extractor.getAllTableNames();
          expect(newTables).toContain("oauth_clients");
          expect(newTables).toContain("refresh_tokens");
      });

      it("should handle mixed state (some tables exist, some don't)", async () => {
         const oauthSchemas = getOAuthSchemas();
         
         // Manually create one table 'oauth_clients' with minimal columns
         // We do this inside the test, db is reset in beforeEach
         // We must be careful that beforeEach setup does not conflict, but it only sets up 'users' table usually.
         
         // Simulating an obscure state where oauth_clients exists but is incomplete
         db.run(`CREATE TABLE oauth_clients (id TEXT PRIMARY KEY, client_id TEXT);`);
         
         const currentSchemas = await extractor.extractAsTableSchemas();
         const diff = SchemaComparator.compareSchemas(currentSchemas, oauthSchemas);
         const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
         
         // Should NOT create oauth_clients again
         expect(sql.some(s => s.includes('CREATE TABLE IF NOT EXISTS "oauth_clients"'))).toBe(false);
         
         // Should create other tables (at least one example)
         expect(sql.some(s => s.includes('CREATE TABLE IF NOT EXISTS "refresh_tokens"'))).toBe(true);
         
         // Should ALTER oauth_clients to add missing columns (e.g. client_secret)
         // We check for one specific column addition
         expect(sql.some(s => s.includes('ALTER TABLE "oauth_clients" ADD COLUMN "client_secret"'))).toBe(true);
         
         for(const stmt of sql) db.run(stmt);
         
         const schema = await extractor.extractTableSchema("oauth_clients");
         expect(schema!.tableSchema.columns.find(c => c.name === "client_secret")).toBeDefined();
      });

      it("should extract schemas matching the defined structures (idempotency)", async () => {
          const oauthSchemas = getOAuthSchemas();
          
          // 1. Initialize DB with these schemas
          const initialDiff = SchemaComparator.compareSchemas([], oauthSchemas);
          const sql = SQLiteMigrationGenerator.generateMigrationSQL(initialDiff);
          for(const stmt of sql) db.run(stmt);
          
          // 2. Extract back
          const allExtractedSchemas = await extractor.extractAsTableSchemas();
          const targetTableNames = new Set(oauthSchemas.map(t => t.tableName));
          const extractedSchemas = allExtractedSchemas.filter(t => targetTableNames.has(t.tableName));
          
          // 3. Compare Extracted vs Target
          const diff = SchemaComparator.compareSchemas(extractedSchemas, oauthSchemas);
           
          if (diff.tableDiffs.length > 0) {
              console.log("Schema Idempotency Differences:", JSON.stringify(diff.tableDiffs, null, 2));
          }
          
          expect(diff.tableDiffs).toHaveLength(0);
      });
  });

  describe("Large Schema Migration (Rename Simulation)", () => {
    it("should handle migration from distinct naming conventions (Spanish to English)", async () => {
         // 1. Define Spanish Schemas (Current State)
         const spanishSchemas = [
             new Schema({
                 id: { type: String, primaryKey: true },
                 titulo: { type: String, required: true },
                 descripcion: { type: String }
             }).toTableSchema("series"),
             
             new Schema({
                 id: { type: String, primaryKey: true },
                 serie_id: { type: String, required: true },
                 numero: { type: Number, required: true },
                 anio: { type: Number }
             }).toTableSchema("temporadas"),
             
             new Schema({
                 id: { type: String, primaryKey: true },
                 temporada_id: { type: String, required: true },
                 titulo: { type: String, required: true },
                 duracion: { type: Number }
             }).toTableSchema("capitulos")
         ];

         // 2. Define English Schemas (Target State)
         const englishSchemas = [
             new Schema({
                 id: { type: String, primaryKey: true },
                 title: { type: String, required: true },
                 description: { type: String },
                 rating: { type: Number } // New field
             }).toTableSchema("shows"), // series -> shows
             
             new Schema({
                 id: { type: String, primaryKey: true },
                 show_id: { type: String, required: true },
                 number: { type: Number, required: true },
                 year: { type: Number }
             }).toTableSchema("seasons"), // temporadas -> seasons
             
             new Schema({
                 id: { type: String, primaryKey: true },
                 season_id: { type: String, required: true },
                 title: { type: String, required: true },
                 duration_minutes: { type: Number }
             }).toTableSchema("episodes") // capitulos -> episodes
         ];
         
         // 3. Setup Initial State (Spanish)
         const setupDiff = SchemaComparator.compareSchemas([], spanishSchemas);
         const setupSql = SQLiteMigrationGenerator.generateMigrationSQL(setupDiff);
         for (const stmt of setupSql) db.run(stmt);
         
         // Verify setup
         const currentTables = await extractor.getAllTableNames();
         expect(currentTables).toContain("series");
         expect(currentTables).toContain("temporadas");
         expect(currentTables).toContain("capitulos");
         
         // 4. Perform Migration (to English)
         const currentExtractedSchemas = await extractor.extractAsTableSchemas();
         
         const migrationDiff = SchemaComparator.compareSchemas(currentExtractedSchemas, englishSchemas);
         const migrationSql = SQLiteMigrationGenerator.generateMigrationSQL(migrationDiff);
         
         // 5. Verify SQL
         expect(migrationSql.some(s => s.includes('DROP TABLE IF EXISTS "series"'))).toBe(true);
         expect(migrationSql.some(s => s.includes('DROP TABLE IF EXISTS "temporadas"'))).toBe(true);
         expect(migrationSql.some(s => s.includes('DROP TABLE IF EXISTS "capitulos"'))).toBe(true);
         
         expect(migrationSql.some(s => s.includes('CREATE TABLE IF NOT EXISTS "shows"'))).toBe(true);
         expect(migrationSql.some(s => s.includes('CREATE TABLE IF NOT EXISTS "seasons"'))).toBe(true);
         expect(migrationSql.some(s => s.includes('CREATE TABLE IF NOT EXISTS "episodes"'))).toBe(true);
         
         // 6. Execute Migration
         for (const stmt of migrationSql) db.run(stmt);
         
         // 7. Verify Final State
         const newTables = await extractor.getAllTableNames();
         
         expect(newTables).not.toContain("series");
         expect(newTables).not.toContain("temporadas");
         expect(newTables).not.toContain("capitulos");
         
         expect(newTables).toContain("shows");
         expect(newTables).toContain("seasons");
         expect(newTables).toContain("episodes");
    });
  });
});
