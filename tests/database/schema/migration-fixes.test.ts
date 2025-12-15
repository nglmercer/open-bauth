
import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { SQLiteSchemaExtractor } from "../../../src/database/schema/schema-extractor";
import { SchemaComparator } from "../../../src/database/schema/schema-comparison";
import { SQLiteMigrationGenerator } from "../../../src/database/schema/migration-generator";
import { Schema } from "../../../src/database/schema/schema";
import { MigrationManager } from "../../../src/database/schema/migration-manager";

describe("Migration Generator Bug Fixes", () => {
    let db: Database;
    let extractor: SQLiteSchemaExtractor;

    beforeEach(() => {
        db = new Database(":memory:");
        extractor = new SQLiteSchemaExtractor(db);
    });

    afterEach(async () => {
        await extractor.close();
        db.close();
    });

    // Fix 1: SQL Injection in sqlite_sequence
    it("should safely handle table names with single quotes during rebuild WITH autoincrement", async () => {
        const tableName = "user's_auto_fix";
        // Create initial table
        db.run(`CREATE TABLE "${tableName}" (id INTEGER PRIMARY KEY AUTOINCREMENT, val INTEGER);`);
        db.run(`INSERT INTO "${tableName}" (val) VALUES (100);`);

        const currentSchemas = await extractor.extractAsTableSchemas();
        
        // Target: change val to TEXT, keep autoincrement (Force Rebuild)
        const targetSchema = new Schema({ 
             val: { type: String }
        }).toTableSchema(tableName);
        
        targetSchema.columns.unshift({
            name: "id",
            type: "INTEGER",
            primaryKey: true,
            autoIncrement: true
        });

        const diff = SchemaComparator.compareSchemas(currentSchemas, [targetSchema]);
        const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);

        // Check SQL content for escaping
        const rebuildSql = sql.find(s => s.includes("DELETE FROM sqlite_sequence"));
        expect(rebuildSql).toBeDefined();
        if (rebuildSql) {
             expect(rebuildSql).toContain("user''s_auto_fix");
        }

        // Execution should SUCCEED
        expect(() => {
             MigrationManager.runMigrations(db, sql);
        }).not.toThrow();

        const row = db.query(`SELECT * FROM "${tableName}"`).get() as any;
        expect(String(row.val)).toBe("100");
    });

    // Fix 2: Default Value Heuristics
    it("should correctly handle string defaults starting with parenthesis (treat as string)", async () => {
         const targetSchema = new Schema({
             id: { type: String, primaryKey: true },
             status: { type: String, default: "(pending)" } 
         }).toTableSchema("tasks_fix");

         const diff = SchemaComparator.compareSchemas([], [targetSchema]);
         const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
         
         const createStmt = sql[0];
         // It should be DEFAULT '(pending)'
         expect(createStmt).toContain("DEFAULT '(pending)'");
         
         expect(() => {
             db.run(createStmt);
         }).not.toThrow();
         
         db.run(`INSERT INTO tasks_fix (id) VALUES ('1');`);
         const row = db.query(`SELECT * FROM tasks_fix WHERE id = '1'`).get() as any;
         expect(row.status).toBe("(pending)");
    });

    it("should still allow raw SQL expressions if they look like functions (nested parens)", async () => {
         const targetSchema = new Schema({
             id: { type: String, primaryKey: true },
             random_val: { type: String, default: "(hex(randomblob(4)))" } 
         }).toTableSchema("expr_fix");

         const diff = SchemaComparator.compareSchemas([], [targetSchema]);
         const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
         
         const createStmt = sql[0];
         // Should be DEFAULT (hex(randomblob(4))) -> UNQUOTED
         expect(createStmt).toContain("DEFAULT (hex(randomblob(4)))");
         
         expect(() => {
             db.run(createStmt);
         }).not.toThrow();
         
         db.run(`INSERT INTO expr_fix (id) VALUES ('1');`);
         const row = db.query(`SELECT * FROM expr_fix WHERE id = '1'`).get() as any;
         expect(row.random_val).not.toBe("(hex(randomblob(4)))"); // Should be the RESULT
         expect(row.random_val.length).toBeGreaterThan(0);
    });

     it("should allow known keywords wrapped in parens", async () => {
         const targetSchema = new Schema({
             id: { type: String, primaryKey: true },
             created: { type: String, default: "(CURRENT_TIMESTAMP)" } 
         }).toTableSchema("kw_fix");

         const diff = SchemaComparator.compareSchemas([], [targetSchema]);
         const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
         
         const createStmt = sql[0];
         expect(createStmt).toContain("DEFAULT (CURRENT_TIMESTAMP)");
         
         expect(() => {
             db.run(createStmt);
         }).not.toThrow();
    });
});
