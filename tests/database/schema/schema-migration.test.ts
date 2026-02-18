import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { SQLiteSchemaExtractor } from "../../../src/database/schema/schema-extractor";
import { SchemaComparator } from "../../../src/database/schema/schema-comparison";
import { SQLiteMigrationGenerator } from "../../../src/database/schema/migration-generator";
import { DatabaseInitializer } from "../../../src/database/database-initializer";
import { Schema } from "../../../src/database/schema/schema";
import type { TableSchema } from "../../../src/database/base-controller";
import { SchemaRegistry } from "../../../src/database/database-initializer";
import { getOAuthSchemas } from "../../../src/schemas";
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
        // Do NOT initialize with any schemas - tests will create what they need
        // This ensures a clean empty database for migration testing
        dbInitializer = new DatabaseInitializer({
            database: db,
            externalSchemas: [],  // Empty - don't use global schemas
        });
        // Don't call initialize() - let each test manage its own schema state
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
});
