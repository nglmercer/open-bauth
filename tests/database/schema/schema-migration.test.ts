import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { SQLiteSchemaExtractor } from "../../../src/database/schema/schema-extractor";
import { SchemaComparator } from "../../../src/database/schema/schema-comparison";
import { SQLiteMigrationGenerator } from "../../../src/database/schema/migration-generator";
import { DatabaseInitializer } from "../../../src/database/database-initializer";
import { MigrationManager } from "../../../src/database/schema/migration-manager";
import { Schema } from "../../../src/database/schema/schema";
import type { TableSchema } from "../../../src/database/base-controller";
import { SchemaRegistry } from "../../../src/database/database-initializer";
import { getOAuthSchemas } from "../../../src/database/schema/oauth-schema-extensions";
import { BaseController } from "../../../src/database/base-controller";
import type { ViewSchema, TriggerSchema } from "../../../src/database/base-controller";
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
// 1. Define Spanish Schemas (Current State)
// 1. Define Spanish Schemas (Current State)
const spanishSchemas = [
    new Schema({
        id: { type: String, primaryKey: true },
        titulo: { type: String, required: true },
        descripcion: { type: String },
        es_activo: { type: String },     // "true", "false", "1", "0"
        fecha_estreno: { type: String }, // "2024-01-01"
        visible_bit: { type: Number }    // 0 or 1
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
        rating: { type: Number },
        active: { type: Boolean },      // Typed Boolean
        release_date: { type: Date },   // Typed Date
        is_visible: { type: Boolean }   // Typed Boolean from bit
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

    it("should handle complex type changes by rebuilding table", async () => {
        db.run(`CREATE TABLE metadata (id TEXT PRIMARY KEY, value INTEGER);`);
        db.run(`INSERT INTO metadata (id, value) VALUES ('1', 123);`);
        const currentSchemas = await extractor.extractAsTableSchemas();
        
        // Change 'value' from INTEGER to TEXT
        const targetSchema = new Schema({
            id: { type: String, primaryKey: true },
            value: { type: String } // Type change
        }).toTableSchema("metadata");
        
        const diff = SchemaComparator.compareSchemas(currentSchemas, [targetSchema]);
        const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
        
        // Should generate a rebuild script (Create new, Insert, Drop old, Rename)
        expect(sql.some(s => s.includes('CREATE TABLE IF NOT EXISTS "_new_metadata"'))).toBe(true);
        expect(sql.some(s => s.includes('INSERT INTO "_new_metadata"'))).toBe(true);
        expect(sql.some(s => s.includes('DROP TABLE "metadata"'))).toBe(true);
        expect(sql.some(s => s.includes('ALTER TABLE "_new_metadata" RENAME TO "metadata"'))).toBe(true);
        
        // Execute
        for (const stmt of sql) db.run(stmt);
        
        // Analyze result
        const row = db.query("SELECT * FROM metadata WHERE id = '1'").get() as any;
        expect(String(row.value)).toBe("123"); // Data preserved and type handled (SQLite dynamic typing makes this easy, but structure changed)
        
        const newSchema = await extractor.extractTableSchema("metadata");
        expect(newSchema!.tableSchema.columns.find(c => c.name === "value")!.type).toBe("TEXT");
    });

    it("should handle adding column with UNIQUE constraint", async () => {
        db.run(`DROP TABLE IF EXISTS users`);
        db.run(`CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT);`);
        const currentSchemas = await extractor.extractAsTableSchemas();
        
        // Add email with UNIQUE
        const targetSchema = new Schema({
            id: { type: String, primaryKey: true },
            name: { type: String },
            email: { type: String, unique: true }
        }).toTableSchema("users");
        
        const diff = SchemaComparator.compareSchemas(currentSchemas, [targetSchema]);
        const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
        
        // Should contain ADD COLUMN (without UNIQUE) and CREATE UNIQUE INDEX
        const addColumn = sql.find(s => s.includes('ADD COLUMN "email"'));
        expect(addColumn).toBeDefined();
        expect(addColumn).not.toContain("UNIQUE"); // Should NOT be in the ADD COLUMN statement
        
        expect(sql.some(s => s.includes('CREATE UNIQUE INDEX IF NOT EXISTS "idx_users_email_unique"'))).toBe(true);
        
        // Execute
        for (const stmt of sql) db.run(stmt);
        
        const newSchema = await extractor.extractTableSchema("users");
        // Verify index exists
        expect(newSchema!.tableSchema.indexes?.some(i => i.columns.includes("email") && i.unique)).toBe(true);
    });

    it("should correctly generate SQL for composite primary keys", async () => {
        db.run(`DROP TABLE IF EXISTS team_members`);
        const currentSchemas: TableSchema[] = [];

        // Target: Table with Composite PK (team_id, user_id)
        const targetSchema = new Schema({
            team_id: { type: String, primaryKey: true },
            user_id: { type: String, primaryKey: true },
            role: { type: String }
        }).toTableSchema("team_members");

        const diff = SchemaComparator.compareSchemas(currentSchemas, [targetSchema]);
        const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);

        expect(sql).toHaveLength(1);
        const createStmt = sql[0];
        
        // Assertions
        expect(createStmt).toContain('CREATE TABLE IF NOT EXISTS "team_members"');
        expect(createStmt).toContain('PRIMARY KEY ("team_id", "user_id")');
        // Ensure individual columns don't have PRIMARY KEY appended
        expect(createStmt).not.toMatch(/"team_id" [^,]+ PRIMARY KEY/);
        expect(createStmt).not.toMatch(/"user_id" [^,]+ PRIMARY KEY/);

        // Apply and Verify
        db.run(createStmt);
        
        // SQLite doesn't easily expose composite PK metadata via simple PRAGMA table_info check for "pk" > 0 
        // (multiple cols will have pk > 0), so we check insertion behavior.
        
        // 1. Insert unique combination
        expect(() => {
            db.run(`INSERT INTO team_members (team_id, user_id, role) VALUES ('t1', 'u1', 'admin')`);
        }).not.toThrow();

        // 2. Insert same combination (Should fail)
        expect(() => {
            db.run(`INSERT INTO team_members (team_id, user_id, role) VALUES ('t1', 'u1', 'member')`);
        }).toThrow(/UNIQUE constraint failed/);

        // 3. Insert different combination (Should succeed)
        expect(() => {
            db.run(`INSERT INTO team_members (team_id, user_id, role) VALUES ('t1', 'u2', 'member')`);
        }).not.toThrow();
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
         expect(sql.some(s => s.includes('ADD COLUMN "client_secret"') || (s.includes('CREATE TABLE') && s.includes('client_secret')))).toBe(true);
         
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

  describe("Data Migration with BaseController", () => {
    it("should allow manual data migration between tables using BaseController", async () => {
        // 1. Setup Source Tables (Spanish)
        const setupDiff = SchemaComparator.compareSchemas([], spanishSchemas);
        const setupSql = SQLiteMigrationGenerator.generateMigrationSQL(setupDiff);
        for (const stmt of setupSql) db.run(stmt);
        
        // 2. Populate Source with BaseController
        dbInitializer.registerSchemas(spanishSchemas);
        
        const seriesController = dbInitializer.createController<{
            id: string, 
            titulo: string, 
            descripcion: string,
            es_activo: string,
            fecha_estreno: string,
            visible_bit: number
        }>("series");
        
        // Scenario A: "true" string, Date string, 1 bit
        await seriesController.create({ 
            id: "1", 
            titulo: "La Casa de Papel", 
            descripcion: "Un atraco perfecto",
            es_activo: "true",
            fecha_estreno: "2017-05-02",
            visible_bit: 1
        });
        
        // Scenario B: "0" string (false), Date string, 0 bit
        await seriesController.create({ 
            id: "2", 
            titulo: "Élite", 
            descripcion: "Drama adolescente",
            es_activo: "0",
            fecha_estreno: "2018-10-05",
            visible_bit: 0
        });

        // Scenario C: "false" string, Date string, 1 bit
        await seriesController.create({
            id: "3",
            titulo: "Vis a Vis",
            descripcion: "Carcel",
            es_activo: "false", 
            fecha_estreno: "2015-04-20",
            visible_bit: 1
        });
        
        // Verify insertion
        const initialData = await seriesController.findAll();
        expect(initialData.data).toHaveLength(3);

        // 3. Define Target Tables (English) and Register
        // (englishSchemas is already defined at top level)
        dbInitializer.registerSchemas(englishSchemas);
        
        // Transition: Keep source, add target
        const transitionSchemas = [...spanishSchemas, ...englishSchemas];
        const currentSchemas = await extractor.extractAsTableSchemas();
        const transitionDiff = SchemaComparator.compareSchemas(currentSchemas, transitionSchemas); 
        const transitionSql = SQLiteMigrationGenerator.generateMigrationSQL(transitionDiff);
        for (const stmt of transitionSql) db.run(stmt);
        
        // 4. Migrate Data from 'series' to 'shows' using BaseController
        const showsController = dbInitializer.createController<{
            id: string, 
            title: string, 
            description: string, 
            rating: number,
            active: boolean,
            release_date: Date,
            is_visible: boolean
        }>("shows");
        
        const seriesRecords = await seriesController.findAll();
        expect(seriesRecords.success).toBe(true);
        
        for (const record of seriesRecords.data!) {
            // Helper to parsing "messy" booleans
            const rawBool = String(record.es_activo).toLowerCase();
            const isActive = ["true", "1", "si", "yes"].includes(rawBool);
            
            await showsController.create({
                id: record.id,
                title: record.titulo,
                description: record.descripcion, 
                rating: 5,
                // Conversions
                active: isActive,
                release_date: new Date(record.fecha_estreno),
                is_visible: Boolean(record.visible_bit)
            });
        }
        
        // 5. Verify Final State in New Table
        const showsRecords = await showsController.findAll();
        expect(showsRecords.data).toHaveLength(3);
        
        // Check Record 1 (True, True)
        const paperHouse = showsRecords.data!.find(u => u.id === "1");
        expect(paperHouse!.title).toBe("La Casa de Papel");
        expect(paperHouse!.active).toBe<number>(1);  // from "true"
        expect(paperHouse!.is_visible).toBe<number>(1); // from 1
        expect(paperHouse!.release_date).toBeDefined();
        // SQLite stores Dates as strings typically, but BaseController might parse them back effectively or treat them as ISO strings
        // We check if it matches the input date string roughly
        expect(new Date(paperHouse!.release_date as any).toISOString().slice(0, 10)).toBe("2017-05-02");

        // Check Record 2 (False, False)
        const elite = showsRecords.data!.find(u => u.id === "2");
        expect(elite!.title).toBe("Élite");
        expect(elite!.active).toBe<number>(0); // from "0"
        expect(elite!.is_visible).toBe<number>(0); // from 0
        
        // Check Record 3 (False, True)
        const vis = showsRecords.data!.find(u => u.id === "3");
        expect(vis!.active).toBe<number>(0); // from "false"
        
        expect(vis!.is_visible).toBe<number>(1); // from 1
        // 6. Cleanup / Finalize Migration (Drop Old Tables)
        const finalDiff = SchemaComparator.compareSchemas(await extractor.extractAsTableSchemas(), englishSchemas);
        const finalSql = SQLiteMigrationGenerator.generateMigrationSQL(finalDiff);
        
        expect(finalSql.some(s => s.includes('DROP TABLE IF EXISTS "series"'))).toBe(true);
        
        for (const stmt of finalSql) db.run(stmt);
        
        const finalTables = await extractor.getAllTableNames();
        expect(finalTables).not.toContain("series");
        expect(finalTables).toContain("shows");
    });
  });

  describe("Robustness and Error Handling", () => {
      it("should fail when rebuilding a table referenced by foreign keys (Standard Execution)", async () => {
        // 1. Setup with FKs enforced
        db.run("PRAGMA foreign_keys = ON;");
        
        // Clean slate
        db.run("DROP TABLE IF EXISTS posts");
        db.run("DROP TABLE IF EXISTS users");

        // Parent table
        db.run("CREATE TABLE users (id TEXT PRIMARY KEY, name INTEGER);"); 
        db.run("INSERT INTO users (id, name) VALUES ('u1', 123);");
        
        // Child table
        db.run("CREATE TABLE posts (id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id));");
        db.run("INSERT INTO posts (id, user_id) VALUES ('p1', 'u1');");

        const currentSchemas = await extractor.extractAsTableSchemas();
        const postsSchema = currentSchemas.find(t => t.tableName === "posts");
        if (!postsSchema) throw new Error("Posts schema not found in extraction!");

        // 2. Target: Change users.name type (Trigger Rebuild)
        // We must include posts in target to avoid dropping it
        const targetSchema = new Schema({
            id: { type: String, primaryKey: true },
            name: { type: String } 
        }).toTableSchema("users");

        const diff = SchemaComparator.compareSchemas(currentSchemas, [targetSchema, postsSchema]);
        const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);

        // 3. Expect standard execution to fail
        expect(() => {
            db.transaction(() => {
                for (const stmt of sql) db.run(stmt);
            })();
        }).toThrow(/FOREIGN KEY constraint failed/);
      });

      it("should successfully rebuild table with foreign keys using MigrationManager", async () => {
        // 1. Setup with FKs enforced
        db.run("PRAGMA foreign_keys = ON;");
        
        db.run("DROP TABLE IF EXISTS posts");
        db.run("DROP TABLE IF EXISTS users");

        db.run("CREATE TABLE users (id TEXT PRIMARY KEY, name INTEGER);"); 
        db.run("INSERT INTO users (id, name) VALUES ('u1', 123);");
        db.run("CREATE TABLE posts (id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id));");
        db.run("INSERT INTO posts (id, user_id) VALUES ('p1', 'u1');");

        const currentSchemas = await extractor.extractAsTableSchemas();
        const postsSchema = currentSchemas.find(t => t.tableName === "posts");
        if (!postsSchema) throw new Error("Posts schema not found in extraction!");

        // 2. Target: Change users.name type (Trigger Rebuild)
        const targetSchema = new Schema({
            id: { type: String, primaryKey: true },
            name: { type: String } 
        }).toTableSchema("users");

        const diff = SchemaComparator.compareSchemas(currentSchemas, [targetSchema, postsSchema]);
        const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);

        // 3. Execute using Manager
        expect(() => {
            MigrationManager.runMigrations(db, sql);
        }).not.toThrow();

        // 4. Verify integrity
        const row = db.query("SELECT * FROM users WHERE id = 'u1'").get() as any;
        expect(String(row.name)).toBe("123");
        
        // Verify FK still enforces (try invalid insert)
        expect(() => {
            db.run("INSERT INTO posts (id, user_id) VALUES ('p2', 'invalid');");
        }).toThrow(/FOREIGN KEY constraint failed/);
      });

      it("should demonstrate data loss when renaming columns (Warning Test)", async () => {
        // 1. Setup
        db.run("DROP TABLE IF EXISTS users");
        db.run("CREATE TABLE users (id TEXT PRIMARY KEY, fullname TEXT);");
        db.run("INSERT INTO users (id, fullname) VALUES ('1', 'John Doe');");

        const currentSchemas = await extractor.extractAsTableSchemas();

        // 2. Target: Rename 'fullname' to 'name'
        const targetSchema = new Schema({
            id: { type: String, primaryKey: true },
            name: { type: String }
        }).toTableSchema("users");

        const diff = SchemaComparator.compareSchemas(currentSchemas, [targetSchema]);
        const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);

        // 3. Migrate
        MigrationManager.runMigrations(db, sql);

        // 4. Verify 'name' is empty (Data Loss)
        const row = db.query("SELECT * FROM users").get() as any;
        expect(row.name).toBeNull(); 
        expect(row.fullname).toBeUndefined();
      });
  });

  describe("Trigger Preservation during Rebuilds", () => {
    it("should preserve triggers when rebuilding a table", async () => {
        // 1. Setup Table and Trigger
        db.run(`CREATE TABLE events (id TEXT PRIMARY KEY, type TEXT);`);
        db.run(`CREATE TABLE logs (message TEXT);`);
        const triggerSQL = `CREATE TRIGGER log_event AFTER INSERT ON events BEGIN INSERT INTO logs (message) VALUES ('new event'); END;`;
        db.run(triggerSQL);

        // Verify trigger exists
        let triggers = db.query("SELECT name FROM sqlite_master WHERE type = 'trigger'").all();
        expect(triggers.some((t: any) => t.name === "log_event")).toBe(true);
        
        // Use extractor to get current state (requires extractTriggers which we verified exists)
        const currentSchemas = await extractor.extractAsTableSchemas();
        const currentTriggers = await extractor.extractTriggers();
        
        // 2. Define Target Schema that forces a REBUILD (e.g. changing column type)
        const targetTableSchema = new Schema({
            id: { type: String, primaryKey: true },
            type: { type: Number } // Changed from TEXT to NUMBER
        }).toTableSchema("events");
        
        const targetLogSchema = new Schema({ message: String }).toTableSchema("logs");

        // Target Triggers: We want to KEEP the existing trigger
        const targetTriggers = [...currentTriggers]; 

        // 3. Compare without modifying trigger
        const diff = SchemaComparator.compareSchemas(
            currentSchemas, 
            [targetTableSchema, targetLogSchema], 
            {}, 
            [], [], // views 
            currentTriggers, // current triggers
            targetTriggers   // target triggers
        );

        // Expect no trigger diffs because they are identical
        expect(diff.triggerDiffs).toHaveLength(0);
        
        // Expect table diff to be ALTER (Rebuild)
        const eventDiff = diff.tableDiffs.find(t => t.tableName === "events");
        expect(eventDiff?.changeType).toBe("ALTER");

        // 4. Generate SQL passing the targetTriggers to restore them if needed
        const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff, targetTriggers);
        
        // 5. Execute
        MigrationManager.runMigrations(db, sql);

        // 6. Verify Trigger Still Exists
        triggers = db.query("SELECT name FROM sqlite_master WHERE type = 'trigger'").all();
        expect(triggers.some((t: any) => t.name === "log_event")).toBe(true);
        
        // Verify Data Integrity
        db.run(`INSERT INTO events (id, type) VALUES ('e1', 1)`);
        const log = db.query("SELECT * FROM logs").get() as any;
        expect(log.message).toBe("new event");
    });
  });

  describe("Advanced Features: Renames, Views, Triggers", () => {
      it("should generate SQL for Table Rename when provided with mapping", async () => {
          // 0. Cleanup
          db.run("DROP TABLE IF EXISTS old_users;");
          db.run("DROP TABLE IF EXISTS new_users;");

          // 1. Setup
          db.run("CREATE TABLE old_users (id TEXT PRIMARY KEY, name TEXT);");
          const currentSchemas = await extractor.extractAsTableSchemas();
          
          // 2. Target with NEW name
          const targetSchema = new Schema({
              id: { type: String, primaryKey: true },
              name: { type: String }
          }).toTableSchema("new_users");
          
          // 3. Compare with Rename Hint
          const diff = SchemaComparator.compareSchemas(
              currentSchemas, 
              [targetSchema],
              { renames: { tables: { "old_users": "new_users" } } }
          );
          
          const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
          
          // 4. Verify
          expect(diff.tableDiffs.find(t => t.tableName === "old_users")?.changeType).toBe("RENAME");
          
          const renameSql = sql.find(s => s.includes('ALTER TABLE "old_users" RENAME TO "new_users"'));
          expect(renameSql).toBeDefined();
          
          // Execution
          for (const stmt of sql) db.run(stmt);
          const tables = await extractor.getAllTableNames();
          expect(tables).toContain("new_users");
          expect(tables).not.toContain("old_users");
      });

      it("should generate SQL for Column Rename when provided with mapping", async () => {
          // 0. Cleanup
          db.run("DROP TABLE IF EXISTS users;");

          // 1. Setup
          db.run("CREATE TABLE users (id TEXT PRIMARY KEY, fullname TEXT);");
          const currentSchemas = await extractor.extractAsTableSchemas();
          
          // 2. Target with NEW column name
          const targetSchema = new Schema({
              id: { type: String, primaryKey: true },
              name: { type: String }
          }).toTableSchema("users");
          
          // 3. Compare with Rename Hint
          const diff = SchemaComparator.compareSchemas(
              currentSchemas, 
              [targetSchema],
              { 
                  renames: { 
                      columns: { 
                          "users": { "fullname": "name" } 
                      } 
                  } 
              }
          );
          
          const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
          
          // 4. Verify
          const renameStmt = sql.find(s => s.includes("RENAME COLUMN"));
          expect(renameStmt).toBeDefined();
          expect(renameStmt).toContain('RENAME COLUMN "fullname" TO "name"');
          
          // Execution
          for (const stmt of sql) db.run(stmt);
          const schema = await extractor.extractTableSchema("users");
          expect(schema!.tableSchema.columns.find(c => c.name === "name")).toBeDefined();
          expect(schema!.tableSchema.columns.find(c => c.name === "fullname")).toBeUndefined();
      });

      it("should handle Views creation and updates", async () => {
          // 0. Cleanup
          db.run("DROP VIEW IF EXISTS active_users;");
          db.run("DROP TABLE IF EXISTS users;");

          // 1. Target View
          const targetView: ViewSchema = {
              name: "active_users",
              sql: "CREATE VIEW active_users AS SELECT * FROM users WHERE active = 1"
          };
          
          db.run("CREATE TABLE users (id TEXT, active INTEGER);"); // Dependency
          
          // 2. Initial Diff (Create)
          const diffCreate = SchemaComparator.compareSchemas([], [], {}, [], [targetView]);
          const sqlCreate = SQLiteMigrationGenerator.generateMigrationSQL(diffCreate);
          
          expect(sqlCreate).toContain(targetView.sql);
          for (const stmt of sqlCreate) db.run(stmt);
          
          // 3. Verify Creation
          const currentViews = await extractor.extractViews();
          expect(currentViews).toHaveLength(1);
          expect(currentViews[0].name).toBe("active_users");
          
          // 4. Update View
          const updatedView: ViewSchema = {
              name: "active_users",
              sql: "CREATE VIEW active_users AS SELECT id FROM users WHERE active = 1" // Changed * to id
          };
          
          const diffUpdate = SchemaComparator.compareSchemas([], [], {}, currentViews, [updatedView]);
          const sqlUpdate = SQLiteMigrationGenerator.generateMigrationSQL(diffUpdate);
          
          expect(sqlUpdate.some(s => s.includes("DROP VIEW"))).toBe(true);
          expect(sqlUpdate.some(s => s.includes("SELECT id"))).toBe(true);
          
          for (const stmt of sqlUpdate) db.run(stmt);
          
          const finalViews = await extractor.extractViews();
          expect(finalViews[0].sql).toContain("SELECT id");
      });

      it("should sort views by dependency during creation", async () => {
          // 0. Cleanup
          db.run("DROP VIEW IF EXISTS view_child;");
          db.run("DROP VIEW IF EXISTS view_parent;");
          db.run("DROP TABLE IF EXISTS base_table;");

          db.run("CREATE TABLE base_table (id INTEGER);");

          // 1. Define Views
          // Parent depends on base_table. Child depends on Parent.
          const viewParent: ViewSchema = {
              name: "view_parent",
              sql: "CREATE VIEW view_parent AS SELECT id FROM base_table"
          };
          
          const viewChild: ViewSchema = {
              name: "view_child",
              sql: "CREATE VIEW view_child AS SELECT * FROM view_parent"
          };

          // 2. Submit in WRONG order (Child first)
          // The generator should fix this.
          const diff = SchemaComparator.compareSchemas([], [], {}, [], [viewChild, viewParent]); 
          
          const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
          
          // 3. Verify SQL Order
          const parentIndex = sql.findIndex(s => s.includes("CREATE VIEW view_parent"));
          const childIndex = sql.findIndex(s => s.includes("CREATE VIEW view_child"));
          
          expect(parentIndex).toBeGreaterThan(-1);
          expect(childIndex).toBeGreaterThan(-1);
          expect(parentIndex).toBeLessThan(childIndex); // Parent MUST be before Child
          
          // 4. Execution check
          for (const stmt of sql) db.run(stmt);
      });

      it("should handle Triggers", async () => {
          // 0. Cleanup
          db.run("DROP TRIGGER IF EXISTS log_user_insert;");
          db.run("DROP TABLE IF EXISTS logs;");
          db.run("DROP TABLE IF EXISTS users;");

          db.run("CREATE TABLE logs (id INTEGER PRIMARY KEY, msg TEXT);");
          db.run("CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT);"); // Trigger target
          
          const targetTrigger: TriggerSchema = {
              name: "log_user_insert",
              tableName: "users",
              sql: `CREATE TRIGGER log_user_insert AFTER INSERT ON users BEGIN INSERT INTO logs (msg) VALUES ('new user'); END`
          };
          
          // Create
          const diff = SchemaComparator.compareSchemas([], [], {}, [], [], [], [targetTrigger]);
          const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
          
          expect(sql[0]).toBe(targetTrigger.sql);
          for (const stmt of sql) db.run(stmt);
          
          // Verify
          const currentTriggers = await extractor.extractTriggers();
          expect(currentTriggers).toHaveLength(1);
          expect(currentTriggers[0].name).toBe("log_user_insert");
          
          // Drop
          const diffDrop = SchemaComparator.compareSchemas([], [], {}, [], [], currentTriggers, []);
          const sqlDrop = SQLiteMigrationGenerator.generateMigrationSQL(diffDrop);
          
          expect(sqlDrop[0]).toContain("DROP TRIGGER");
          for (const stmt of sqlDrop) db.run(stmt);
          
          expect(await extractor.extractTriggers()).toHaveLength(0);
      });
  });

  it("should preserve sqlite_sequence when rebuilding table with AUTOINCREMENT", async () => {
    // 1. Create table with AUTOINCREMENT
    db.run(`DROP TABLE IF EXISTS seq_test`);
    db.run(`CREATE TABLE seq_test (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);`);
    db.run(`INSERT INTO seq_test (name) VALUES ('A');`); // id=1
    db.run(`INSERT INTO seq_test (name) VALUES ('B');`); // id=2
    db.run(`DELETE FROM seq_test WHERE id = 2;`); // Delete last
    
    // Sequence should be 2 in SQLite (auto increment keeps the high water mark)
    const seqBefore = db.query("SELECT seq FROM sqlite_sequence WHERE name = 'seq_test'").get() as any;
    expect(seqBefore.seq).toBe(2);

    const currentSchemas = await extractor.extractAsTableSchemas();

    // 2. Rebuild table (change column type to force rebuild)
    const targetSchema = new Schema({
        id: { type: Number, primaryKey: true, autoIncrement: true }, // maintain autoIncrement
        name: { type: Number } // Change Type TEXT -> NUMBER
    }).toTableSchema("seq_test");

    const diff = SchemaComparator.compareSchemas(currentSchemas, [targetSchema]);
    const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
    
    // Check if SQL contains sqlite_sequence logic
    expect(sql.some(s => s.includes("sqlite_sequence"))).toBe(true);
    expect(sql.some(s => s.includes("INSERT INTO"))).toBe(true);
    
    // 3. Apply
    for (const stmt of sql) {
        console.log("EXEC:", stmt);
        db.run(stmt);
    }
    
    // 4. Check Sequence
    const seqAfter = db.query("SELECT seq FROM sqlite_sequence WHERE name = 'seq_test'").get() as any;
    expect(seqAfter).toBeDefined();
    expect(seqAfter.seq).toBe(2);
    
    // 5. Insert new -> should be 3
    db.run(`INSERT INTO seq_test (name) VALUES (3);`);
    const newRow = db.query("SELECT * FROM seq_test WHERE name = 3").get() as any;
    expect(newRow.id).toBe(3);
  });
});
