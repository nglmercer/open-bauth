
import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { SQLiteSchemaExtractor } from "../../../src/database/schema/schema-extractor";
import { SchemaComparator } from "../../../src/database/schema/schema-comparison";
import { SQLiteMigrationGenerator } from "../../../src/database/schema/migration-generator";
import { Schema } from "../../../src/database/schema/schema";

describe("Migration Generator Issues", () => {
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

    it("should update column definition when renaming AND changing type", async () => {
        // Setup: Table with 'age' as INTEGER
        db.run("CREATE TABLE users (id TEXT PRIMARY KEY, age INTEGER)");
        db.run("INSERT INTO users (id, age) VALUES ('1', 25)");

        const currentSchemas = await extractor.extractAsTableSchemas();

        // Target: Rename 'age' to 'age_text' AND change to TEXT
        const targetSchema = new Schema({
            id: { type: String, primaryKey: true },
            age_text: { type: String } 
        }).toTableSchema("users");

        // Compare with explicit rename
        const diff = SchemaComparator.compareSchemas(
            currentSchemas, 
            [targetSchema], 
            { renames: { columns: { "users": { "age": "age_text" } } } }
        );

        const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
        
        // Execute
        for (const stmt of sql) db.run(stmt);

        // Verify Schema
        const newSchema = await extractor.extractTableSchema("users");
        const col = newSchema!.tableSchema.columns.find(c => c.name === "age_text");
        
        // ISSUE 1 Expectation: Type should be TEXT
        // Current likely behavior: It remains INTEGER if only RENAME COLUMN was used
        expect(col!.type).toBe("TEXT"); 
    });

    it("should preserve data for renamed columns during a table rebuild", async () => {
        // Setup: Table with 'col_rename' and 'col_change'
        db.run("CREATE TABLE data (id TEXT PRIMARY KEY, col_rename TEXT, col_change INTEGER)");
        db.run("INSERT INTO data (id, col_rename, col_change) VALUES ('1', 'keep me', 100)");

        const currentSchemas = await extractor.extractAsTableSchemas();

        // Target:
        // 1. Rename 'col_rename' -> 'col_renamed'
        // 2. Change 'col_change' type -> TEXT (Triggers Rebuild)
        const targetSchema = new Schema({
            id: { type: String, primaryKey: true },
            col_renamed: { type: String },
            col_change: { type: String }
        }).toTableSchema("data");

        const diff = SchemaComparator.compareSchemas(
            currentSchemas, 
            [targetSchema],
            { renames: { columns: { "data": { "col_rename": "col_renamed" } } } }
        );

        const sql = SQLiteMigrationGenerator.generateMigrationSQL(diff);
        
        // It SHOULD generate a rebuild because of col_change type change.
        // Check if rebuild SQL handles the rename mapping in INSERT
        
        for (const stmt of sql) db.run(stmt);

        const row = db.query("SELECT * FROM data WHERE id = '1'").get() as any;
        
        // ISSUE 2 Expectation: Data should be preserved
        expect(row.col_renamed).toBe("keep me");
        expect(String(row.col_change)).toBe("100");
    });
});
