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

    // 4. Tables to RENAME
    for (const tableDiff of diff.tableDiffs) {
      // NOTE: If changeType is RENAME, we do this FIRST before altering validation
      // But usually altering involves the new name, so rename first is good.
      if (tableDiff.changeType === "RENAME" && tableDiff.newName) {
          statements.push(`ALTER TABLE "${tableDiff.tableName}" RENAME TO "${tableDiff.newName}";`);
          // Update tableName for subsequent operations in this loop?
          // No, the tableDiff object still has old tableName likely, or whatever was passed.
          // Comparator returned diff.tableName = OLD name for RENAME ops?
          // In my comparator logic: "diff.tableName = oldName!". So we use tableDiff.tableName to identify it.
          // Subsequent ALTERs in this loop (if any) need to use NEW name.
          // Actually, if we have ALTERS inside a RENAME tableDiff, they target the NEW schema.
          // So we should perform ALTERS on the NEW table name.
          
          // Let's mutate/shadow tableName for the next step?
          // Or we handle it inside generateAlterTableSQL.
      }
    }

    // 5. Tables to ALTER (including those just renamed)
    for (const tableDiff of diff.tableDiffs) {
      if (tableDiff.changeType === "ALTER" || tableDiff.changeType === "RENAME") {
        const effectiveTableName = (tableDiff.changeType === "RENAME" && tableDiff.newName) 
            ? tableDiff.newName 
            : tableDiff.tableName;

        if (this.requiresTableRebuild(tableDiff)) {
          statements.push(...this.generateRebuildTableSQL(tableDiff, effectiveTableName));
        } else {
          statements.push(...this.generateAlterTableSQL(tableDiff, effectiveTableName));
        }
      }
    }

    // 6. Views
    for (const viewDiff of diff.viewDiffs) {
        if (viewDiff.changeType === "DROP" || viewDiff.changeType === "ALTER") {
            statements.push(`DROP VIEW IF EXISTS "${viewDiff.viewName}";`);
        }
        if (viewDiff.changeType === "CREATE" || viewDiff.changeType === "ALTER") {
            if (viewDiff.newView?.sql) {
                statements.push(viewDiff.newView.sql);
            }
        }
    }

    // 7. Triggers
    for (const triggerDiff of diff.triggerDiffs) {
        if (triggerDiff.changeType === "DROP" || triggerDiff.changeType === "ALTER") {
            statements.push(`DROP TRIGGER IF EXISTS "${triggerDiff.triggerName}";`);
        }
        if (triggerDiff.changeType === "CREATE" || triggerDiff.changeType === "ALTER") {
             if (triggerDiff.newTrigger?.sql) {
                statements.push(triggerDiff.newTrigger.sql);
            }
        }
    }

    return statements;
  }

  private static requiresTableRebuild(tableDiff: TableDiff): boolean {
    // 1. Check for Column Modifications (ALTER) - Type change, constraint change
    if (tableDiff.columnDiffs.some(c => c.changeType === "ALTER")) {
      return true;
    }

    // 2. Check for Adding NOT NULL without Default
    // SQLite ADD COLUMN limitations
    for (const colDiff of tableDiff.columnDiffs) {
      if (colDiff.changeType === "CREATE" && colDiff.newColumn) {
        if (
          colDiff.newColumn.notNull &&
          colDiff.newColumn.defaultValue === undefined &&
          !colDiff.newColumn.primaryKey
        ) {
          // Cannot add NOT NULL column without default to populated table in SQLite
          return true;
        }
      }
    }

    return false;
  }

  private static generateRebuildTableSQL(tableDiff: TableDiff, overrideTableName?: string): string[] {
    const statements: string[] = [];
    const tableName = overrideTableName || tableDiff.tableName; // Target table name (if renamed, this is the new name)
    const oldTableName = tableDiff.tableName; // Always the identifier we started with (old name)
    
    // If it was renamed, the table ALREADY has the new name in the DB because we ran RENAME first.
    // So both should essentially be the same for the purpose of 'rebuilding the current table'
    // UNLESS we haven't run rename yet. But step 4 runs before step 5.
    // So 'tableName' matches the current state of DB (new name).
    
    // Safety check: if we renamed, overrideTableName provided.
    const currentDBTableName = (tableDiff.changeType === "RENAME" && tableDiff.newName) ? tableDiff.newName : tableDiff.tableName;
    
    const tempTableName = `_new_${tableName}`;
    
    if (!tableDiff.newSchema || !tableDiff.oldSchema) {
        console.warn(`Cannot rebuild table ${tableName} without full schema definition.`);
        return [];
    }

    // 1. Create new table with temporary name
    const createSQL = this.generateCreateTableSQL({
        ...tableDiff.newSchema,
        tableName: tempTableName
    });
    statements.push(createSQL);

    // 2. Copy data
    // Identify common columns
    const oldColumns = new Set(tableDiff.oldSchema.columns.map(c => c.name));
    
    const commonColumns = tableDiff.newSchema.columns
        .filter(c => oldColumns.has(c.name))
        .map(c => `"${c.name}"`);

    if (commonColumns.length > 0) {
        const cols = commonColumns.join(", ");
        statements.push(`INSERT INTO "${tempTableName}" (${cols}) SELECT ${cols} FROM "${tableName}";`);
    }

    // 3. Drop old table
    statements.push(`DROP TABLE "${tableName}";`);

    // 4. Rename new table
    statements.push(`ALTER TABLE "${tempTableName}" RENAME TO "${tableName}";`);

    // 5. Recreate Indexes
    if (tableDiff.newSchema.indexes) {
        for (const idx of tableDiff.newSchema.indexes) {
             statements.push(this.generateCreateIndexSQL(tableName, idx));
        }
    }

    return statements;
  }

  private static generateAlterTableSQL(tableDiff: TableDiff, overrideTableName?: string): string[] {
    const statements: string[] = [];
    const tableName = overrideTableName || tableDiff.tableName;

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

    // Handle Drops
    for (const colDiff of tableDiff.columnDiffs) {
        if (colDiff.changeType === "DROP") {
            statements.push(`ALTER TABLE "${tableName}" DROP COLUMN "${colDiff.columnName}";`);
        }
    }



    // Handle Rename Columns
    for (const colDiff of tableDiff.columnDiffs) {
        if (colDiff.changeType === "RENAME" && colDiff.oldColumn && colDiff.newColumn) {
            statements.push(`ALTER TABLE "${tableName}" RENAME COLUMN "${colDiff.oldColumn.name}" TO "${colDiff.newColumn.name}";`);
            
            // If there are other changes (type/constraints) to this column, they might need a rebuild or separate handling.
            // But 'diff' usually captures changes relative to the NEW column name.
            // SQLite Rename Column is metadata only usually.
        }
    }

    // Handle Adds
    for (const colDiff of tableDiff.columnDiffs) {
        if (colDiff.changeType === "CREATE" && colDiff.newColumn) {
             // Handle UNIQUE constraint limitation in ADD COLUMN
             const isUnique = colDiff.newColumn.unique;
             const colDef = this.generateColumnDefinition(colDiff.newColumn, true); // true = forAddColumn
             
             statements.push(`ALTER TABLE "${tableName}" ADD COLUMN ${colDef};`);
             
             if (isUnique) {
                 statements.push(this.generateCreateIndexSQL(tableName, {
                     name: `idx_${tableName}_${colDiff.columnName}_unique`,
                     columns: [colDiff.columnName],
                     unique: true
                 }));
             }
        }
    }

    return statements;
  }

  private static generateCreateTableSQL(schema: import("../base-controller").TableSchema): string {
    const columns = schema.columns.map(c => this.generateColumnDefinition(c)).join(", ");
    return `CREATE TABLE IF NOT EXISTS "${schema.tableName}" (${columns});`;
  }

  private static generateColumnDefinition(col: ColumnDefinition, forAddColumn: boolean = false): string {
      let def = `"${col.name}" ${col.type}`;
      
      if (col.primaryKey) {
          def += " PRIMARY KEY";
          if (col.autoIncrement) def += " AUTOINCREMENT";
      }
      
      if (col.notNull && !col.primaryKey) def += " NOT NULL";
      
      // SQLite ADD COLUMN does not support UNIQUE constraint directly
      if (col.unique && !col.primaryKey && !forAddColumn) def += " UNIQUE";
      
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
