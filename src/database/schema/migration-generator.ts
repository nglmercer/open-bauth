import { SchemaDiff, TableDiff, ColumnDiff, IndexDiff, ViewDiff } from "./schema-comparison";
import type { ColumnDefinition, TriggerSchema } from "../base-controller";
export class SQLiteMigrationGenerator {
  static generateMigrationSQL(diff: SchemaDiff, targetTriggers: TriggerSchema[] = [], targetViews: import("../base-controller").ViewSchema[] = []): string[] {
    const statements: string[] = [];
    const rebuiltTables = new Set<string>();
    const modifiedTables = new Set<string>();

    // Identify ALL modified tables (to detect stale views)
    for (const tableDiff of diff.tableDiffs) {
        modifiedTables.add(tableDiff.tableName);
        if (tableDiff.newName) modifiedTables.add(tableDiff.newName);
    }

    // Identify Stale View Logic (Existing code 23-44) ...
    // Identify Stale Views: Views not in diff, but depend on modified tables
    const staleViews: ViewDiff[] = [];
    const handledViewNames = new Set(diff.viewDiffs.map(v => v.viewName));

    for (const view of targetViews) {
        if (!handledViewNames.has(view.name)) {
            // Check dependency
            const referencesModifiedTable = Array.from(modifiedTables).some(tableName => {
                const regex = new RegExp(`\\b${tableName}\\b|"${tableName}"`, 'i');
                return regex.test(view.sql);
            });

            if (referencesModifiedTable) {
                staleViews.push({
                    viewName: view.name,
                    changeType: "ALTER", // Treat as ALTER to force Drop + Create
                    oldView: view, // Assuming it existed
                    newView: view
                });
            }
        }
    }

    // Identify Stale Triggers: Triggers not in diff, but depend on modified tables
    // This catches cases where a trigger references a table that was renamed/altered, even if the trigger's own table wasn't rebuilt.
    const staleTriggers: any[] = []; // TriggerDiff
    const handledTriggerNames = new Set(diff.triggerDiffs.map(t => t.triggerName));

    for (const trigger of targetTriggers) {
        if (!handledTriggerNames.has(trigger.name)) {
             const referencesModifiedTable = Array.from(modifiedTables).some(tableName => {
                const regex = new RegExp(`\\b${tableName}\\b|"${tableName}"`, 'i');
                return regex.test(trigger.sql);
            });
            
            if (referencesModifiedTable) {
                staleTriggers.push({
                   triggerName: trigger.name,
                   changeType: "ALTER",
                   oldTrigger: trigger,
                   newTrigger: trigger
                });
            }
        }
    }

    // Merge explicitly changed views with stale views
    const allViewDiffs = [...diff.viewDiffs, ...staleViews];
    const allTriggerDiffs = [...diff.triggerDiffs, ...staleTriggers];

    // 0. Views to DROP (Do this first to avoid dependency issues when dropping/altering tables)
    for (const viewDiff of allViewDiffs) {
        if (viewDiff.changeType === "DROP" || viewDiff.changeType === "ALTER") {
            statements.push(`DROP VIEW IF EXISTS "${viewDiff.viewName}";`);
        }
    }

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

    // 6. Views to CREATE (After tables are ready)
    // Sort views by dependency to avoid creation errors
    const viewsToCreate = allViewDiffs.filter(v => v.changeType === "CREATE" || v.changeType === "ALTER");
    const sortedViews = this.sortViewsByDependency(viewsToCreate);

    for (const viewDiff of sortedViews) {
        if (viewDiff.newView?.sql) {
            statements.push(viewDiff.newView.sql);
        }
    }

    // 7. Triggers (Explicit Changes + Stale)
    for (const triggerDiff of allTriggerDiffs) {
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
                // Check if this trigger was already handled in the diff (e.g. it was modified or explicitly dropped or STALE RECREATED)
                // Note: allTriggerDiffs contains stale triggers, so they are "handled" in step 7.
                const isHandledInDiff = allTriggerDiffs.some(td => td.triggerName === trigger.name);
                
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
        
        // Limitation A: PRIMARY KEY
        // Cannot add a PRIMARY KEY column
        if (colDiff.newColumn.primaryKey) return true;

        // Limitation B: NOT NULL / Default
        if (
          colDiff.newColumn.notNull &&
          colDiff.newColumn.defaultValue === undefined
        ) {
          // Cannot add NOT NULL column without default to populated table in SQLite
          return true;
        }
        
        // Limitation C: Non-Constant Defaults
        // SQLite ADD COLUMN allows only constant defaults.
        // We conservatively assume any parenthesized expression might be non-constant (e.g. (random())).
        // Optimizing this would require SQL parsing to distinguish (1) from (random()).
        // Safe approach: Rebuild if it looks like an expression (other than known constants).
        const defVal = colDiff.newColumn.defaultValue;
        if (typeof defVal === 'string') {
             // If it starts with '(', it's possibly an expression we want to be careful with.
             // Note: formatDefaultValue allows '('... ')' to pass through as raw SQL.
             if (defVal.startsWith('(') && defVal.endsWith(')')) {
                 return true; 
             }
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
    // const currentDBTableName = (tableDiff.changeType === "RENAME" && tableDiff.newName) ? tableDiff.newName : tableDiff.tableName;
    
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

    // 3. Preserve sqlite_sequence (if applicable)
    // Only if the new schema uses AUTOINCREMENT.
    // If it does, sqlite_sequence is guaranteed to exist (created by the CREATE TABLE of _new_table).
    // DELETE first to ensure we don't have duplicates or rely on REPLACE if name isn't unique constraint.
    const hasAutoIncrement = tableDiff.newSchema.columns.some(c => c.autoIncrement);
    
    if (hasAutoIncrement) {
      const escapedTempName = tempTableName.replace(/'/g, "''");
      const escapedTableName = tableName.replace(/'/g, "''");
      
      statements.push(`DELETE FROM sqlite_sequence WHERE name = '${escapedTempName}';`);
      statements.push(`
        INSERT INTO sqlite_sequence (name, seq)
        SELECT '${escapedTempName}', seq FROM sqlite_sequence WHERE name = '${escapedTableName}';
      `.trim());
    }


    // 4. Drop old table
    statements.push(`DROP TABLE "${tableName}";`);

    // 5. Rename new table
    statements.push(`ALTER TABLE "${tempTableName}" RENAME TO "${tableName}";`);

    // 6. Recreate Indexes
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
           const upper = value.toUpperCase();
           // SQL Constants / Functions that should be unquoted
           // common SQLite time functions
           if (['CURRENT_TIMESTAMP', 'CURRENT_DATE', 'CURRENT_TIME'].includes(upper)) {
               return value;
           }
           // Wrapped expressions (e.g. (CURRENT_TIMESTAMP)) often returned by SQLite introspection
           // Smart Heuristic for Wrapped Expressions (e.g. (CURRENT_TIMESTAMP) or (random()))
           if (value.startsWith('(') && value.endsWith(')')) {
               const inner = value.slice(1, -1).trim();
               // 1. If it contains nested parentheses, it's likely a function call e.g. (scan(...))
               if (inner.includes('(')) return value;
               
               // 2. If it is a known keyword (often wrapped in parens by SQLite)
               const upper = inner.toUpperCase();
               if (['CURRENT_TIMESTAMP', 'CURRENT_DATE', 'CURRENT_TIME', 'TRUE', 'FALSE', 'NULL'].includes(upper)) {
                   return value;
               }

               // 3. Otherwise, it's likely just a string wrapped in parens e.g. "(pending)" -> treat as string.
               // Fall through to quoting logic.
           }
           
           return `'${value.replace(/'/g, "''")}'`;
      }
      return `'${JSON.stringify(value)}'`;
  }

  private static sortViewsByDependency(diffs: ViewDiff[]): ViewDiff[] {
    const sorted: ViewDiff[] = [];
    const visited = new Set<string>();
    const temp = new Set<string>();

    const visit = (diff: ViewDiff) => {
        if (temp.has(diff.viewName)) return; // Cycle detected
        if (visited.has(diff.viewName)) return;

        temp.add(diff.viewName);

        for (const otherDiff of diffs) {
            if (diff === otherDiff) continue;
            
            // Check if this View depends on otherDiff (by name reference in SQL)
            if (diff.newView) {
                const regex = new RegExp(`\\b${otherDiff.viewName}\\b|"${otherDiff.viewName}"`, 'i');
                if (regex.test(diff.newView.sql)) {
                    visit(otherDiff);
                }
            }
        }

        temp.delete(diff.viewName);
        visited.add(diff.viewName);
        sorted.push(diff);
    };

    for (const diff of diffs) {
        visit(diff);
    }

    return sorted;
  }
}
