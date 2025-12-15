import { SchemaDiff, TableDiff, ColumnDiff, IndexDiff } from "./schema-comparison";
import type { ColumnDefinition } from "../base-controller";
import { BaseController } from "../base-controller";

export class SQLiteMigrationGenerator {
  static generateMigrationSQL(diff: SchemaDiff): string[] {
    const statements: string[] = [];

    // 1. Tables to DROP
    for (const tableDiff of diff.tableDiffs) {
      if (tableDiff.changeType === "DROP") {
        statements.push(`DROP TABLE IF EXISTS "${tableDiff.tableName}";`);
      }
    }

    // 2. Tables to CREATE
    for (const tableDiff of diff.tableDiffs) {
      if (tableDiff.changeType === "CREATE" && tableDiff.newSchema) {
        // Use BaseController's logic if possible, or reimplement
        // BaseController.generateCreateTableSQL is private, so we might need to expose it or reimplement
        statements.push(this.generateCreateTableSQL(tableDiff.newSchema));
        
        // Add indexes for new table
        if (tableDiff.newSchema.indexes) {
            for (const idx of tableDiff.newSchema.indexes) {
                statements.push(this.generateCreateIndexSQL(tableDiff.tableName, idx));
            }
        }
      }
    }

    // 3. Tables to ALTER
    for (const tableDiff of diff.tableDiffs) {
      if (tableDiff.changeType === "ALTER") {
        statements.push(...this.generateAlterTableSQL(tableDiff));
      }
    }

    return statements;
  }

  private static generateAlterTableSQL(tableDiff: TableDiff): string[] {
    const statements: string[] = [];
    const tableName = tableDiff.tableName;

    // Indexes changes
    for (const indexDiff of tableDiff.indexDiffs) {
        if (indexDiff.changeType === "DROP" || indexDiff.changeType === "ALTER") {
            statements.push(`DROP INDEX IF EXISTS "${indexDiff.indexName}";`);
        }
        if (indexDiff.changeType === "CREATE" || indexDiff.changeType === "ALTER") {
            if (indexDiff.newIndex) {
                 statements.push(this.generateCreateIndexSQL(tableName, indexDiff.newIndex));
            }
        }
    }

    // Column changes
    // SQLite supports ADD COLUMN
    // SQLite supports DROP COLUMN (>= 3.35.0) which bun supports
    // Altering column types is NOT supported directly and requires table recreation usually.
    
    // We will separate changes into:
    // - Simple additions (ADD COLUMN)
    // - Simple removals (DROP COLUMN)
    // - Complex changes (Type change, constraint change) -> Need full recreation
    
    const complexChanges = tableDiff.columnDiffs.some(
        c => c.changeType === "ALTER" // Modification of existing column
    );

    if (complexChanges) {
        // If we have complex changes, we might need to recreate the table
        // For now, let's just log a warning or handle what we can.
        // Implementing full table recreation (Create new, copy data, drop old, rename) is risky to auto-generate without backup.
        console.warn(`WARNING: Complex changes detected for table ${tableName}. Manual migration might be required.`);
         
         for (const colDiff of tableDiff.columnDiffs) {
             if (colDiff.changeType === "ALTER") {
                  console.warn(`-- ALTER COLUMN ${colDiff.columnName} changed: ${colDiff.differences?.join(", ")}`);
                  // SQLite doesn't support ALTER COLUMN type/constraint
             }
         }
    }

    // Handle Drops
    for (const colDiff of tableDiff.columnDiffs) {
        if (colDiff.changeType === "DROP") {
            statements.push(`ALTER TABLE "${tableName}" DROP COLUMN "${colDiff.columnName}";`);
        }
    }

    // Handle Adds
    for (const colDiff of tableDiff.columnDiffs) {
        if (colDiff.changeType === "CREATE" && colDiff.newColumn) {
             const colDef = this.generateColumnDefinition(colDiff.newColumn);
             statements.push(`ALTER TABLE "${tableName}" ADD COLUMN ${colDef};`);
        }
    }

    return statements;
  }

  private static generateCreateTableSQL(schema: import("../base-controller").TableSchema): string {
    const columns = schema.columns.map(c => this.generateColumnDefinition(c)).join(", ");
    return `CREATE TABLE IF NOT EXISTS "${schema.tableName}" (${columns});`;
  }

  private static generateColumnDefinition(col: ColumnDefinition): string {
      let def = `"${col.name}" ${col.type}`;
      
      if (col.primaryKey) {
          def += " PRIMARY KEY";
          if (col.autoIncrement) def += " AUTOINCREMENT";
      }
      
      if (col.notNull && !col.primaryKey) def += " NOT NULL";
      if (col.unique && !col.primaryKey) def += " UNIQUE";
      
      if (col.defaultValue !== undefined) {
           def += ` DEFAULT ${this.formatDefaultValue(col.defaultValue)}`;
      }
      
      if (col.references) {
          def += ` REFERENCES "${col.references.table}"("${col.references.column}")`;
          if (col.onDelete) def += ` ON DELETE ${col.onDelete}`;
      }
      
      if (col.check) {
          def += ` CHECK (${col.check})`;
      }
      
      return def;
  }

  private static generateCreateIndexSQL(tableName: string, index: { name: string, columns: string[], unique?: boolean }): string {
      const unique = index.unique ? "UNIQUE " : "";
      const cols = index.columns.map(c => `"${c}"`).join(", ");
      return `CREATE ${unique}INDEX IF NOT EXISTS "${index.name}" ON "${tableName}" (${cols});`;
  }

  private static formatDefaultValue(value: any): string {
      if (value === null) return "NULL";
      if (typeof value === "boolean") return value ? "1" : "0";
      if (typeof value === "number") return String(value);
      if (typeof value === "string") {
           // Basic check for SQL functions
           if (['CURRENT_TIMESTAMP', 'CURRENT_DATE', 'CURRENT_TIME'].includes(value.toUpperCase())) {
               return value;
           }
           return `'${value.replace(/'/g, "''")}'`;
      }
      return `'${JSON.stringify(value)}'`;
  }
}
