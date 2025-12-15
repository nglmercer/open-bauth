import { SchemaDiff, TableDiff, ColumnDiff, IndexDiff } from "./schema-comparison";
import type { ColumnDefinition, TriggerSchema } from "../base-controller";
import { BaseController } from "../base-controller";

export class SQLiteMigrationGenerator {
  static generateMigrationSQL(diff: SchemaDiff, targetTriggers: TriggerSchema[] = []): string[] {
    const statements: string[] = [];
    const rebuiltTables = new Set<string>();

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
      if (tableDiff.changeType === "RENAME" && tableDiff.newName) {
          statements.push(`ALTER TABLE "${tableDiff.tableName}" RENAME TO "${tableDiff.newName}";`);
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
          rebuiltTables.add(effectiveTableName);
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

    // 7. Triggers (Explicit Changes)
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

    // 8. Restore Lost Triggers (due to Table Rebuilds)
    // If a table was rebuilt, its triggers are lost even if they didn't change (no diff).
    // We must restore them from targetTriggers.
    if (targetTriggers.length > 0) {
        for (const trigger of targetTriggers) {
            // Check if this trigger belongs to a rebuilt table
            if (rebuiltTables.has(trigger.tableName)) {
                // Check if this trigger was already handled in the diff (e.g. it was modified or explicitly dropped)
                const isHandledInDiff = diff.triggerDiffs.some(td => td.triggerName === trigger.name);
                
                if (!isHandledInDiff) {
                    // It was NOT in the diff, meaning it should be preserved.
                    // But rebuild destroyed it. So we must recreate it.
                    statements.push(trigger.sql);
                }
            }
        }
    }

    return statements;
  }

  private static requiresTableRebuild(tableDiff: TableDiff): boolean {
    // 1. Check for Column Modifications (ALTER) - Type change, constraint change
    // Also Check for RENAME where other properties changed (e.g. Type change + Rename)
    if (tableDiff.columnDiffs.some(c => 
        c.changeType === "ALTER" || 
        (c.changeType === "RENAME" && c.differences && c.differences.length > 0)
    )) {
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
    // 2. Copy data
    const insertColumns: string[] = [];
    const selectColumns: string[] = [];

    // Map new columns to old columns to preserve data
    for (const newCol of tableDiff.newSchema.columns) {
        // Check if this column corresponds to an old column (either same name or renamed)
        const colDiff = tableDiff.columnDiffs.find(cd => cd.newColumn?.name === newCol.name);
        
        let oldColName: string | undefined;

        if (colDiff && colDiff.changeType === "RENAME" && colDiff.oldColumn) {
             oldColName = colDiff.oldColumn.name;
        } else {
             // If not explicitly renamed in diff, check if it existed in old schema with same name
             const existsInOld = tableDiff.oldSchema.columns.some(c => c.name === newCol.name);
             if (existsInOld) {
                 oldColName = newCol.name;
             }
        }

        if (oldColName) {
            insertColumns.push(`"${newCol.name}"`);
            selectColumns.push(`"${oldColName}"`);
        }
    }

    if (insertColumns.length > 0) {
        statements.push(`INSERT INTO "${tempTableName}" (${insertColumns.join(", ")}) SELECT ${selectColumns.join(", ")} FROM "${tableName}";`);
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
    const pkColumns = schema.columns.filter(c => c.primaryKey);
    const useTableConstraint = pkColumns.length > 1;

    const columns = schema.columns.map(c => 
        this.generateColumnDefinition(c, false, useTableConstraint)
    ).join(", ");

    let constraints = "";
    if (useTableConstraint) {
        const pkNames = pkColumns.map(c => `"${c.name}"`).join(", ");
        constraints = `, PRIMARY KEY (${pkNames})`;
    }

    return `CREATE TABLE IF NOT EXISTS "${schema.tableName}" (${columns}${constraints});`;
  }

  private static generateColumnDefinition(col: ColumnDefinition, forAddColumn: boolean = false, suppressPrimaryKey: boolean = false): string {
      let def = `"${col.name}" ${col.type}`;
      
      if (col.primaryKey && !suppressPrimaryKey) {
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
