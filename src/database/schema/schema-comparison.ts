import type { TableSchema, ColumnDefinition } from "../base-controller";

export type ChangeType = "CREATE" | "DROP" | "ALTER" | "NONE";

export interface ColumnDiff {
  columnName: string;
  changeType: ChangeType;
  oldColumn?: ColumnDefinition;
  newColumn?: ColumnDefinition;
  differences?: string[]; // List of property names that changed
}

export interface IndexDiff {
  indexName: string;
  changeType: ChangeType;
  oldIndex?: { name: string; columns: string[]; unique?: boolean };
  newIndex?: { name: string; columns: string[]; unique?: boolean };
}

export interface TableDiff {
  tableName: string;
  changeType: ChangeType;
  oldSchema?: TableSchema;
  newSchema?: TableSchema;
  columnDiffs: ColumnDiff[];
  indexDiffs: IndexDiff[];
}

export interface SchemaDiff {
  tableDiffs: TableDiff[];
}

export class SchemaComparator {
  static compareSchemas(
    currentSchemas: TableSchema[],
    targetSchemas: TableSchema[]
  ): SchemaDiff {
    const tableDiffs: TableDiff[] = [];

    // Check for tables in target (CREATE or ALTER)
    for (const targetTable of targetSchemas) {
      const currentTable = currentSchemas.find(
        (t) => t.tableName === targetTable.tableName
      );

      if (!currentTable) {
        tableDiffs.push({
          tableName: targetTable.tableName,
          changeType: "CREATE",
          newSchema: targetTable,
          columnDiffs: [],
          indexDiffs: [],
        });
      } else {
        const diff = this.compareTable(currentTable, targetTable);
        if (
          diff.changeType !== "NONE" ||
          diff.columnDiffs.length > 0 ||
          diff.indexDiffs.length > 0
        ) {
          tableDiffs.push(diff);
        }
      }
    }

    // Check for tables only in current (DROP)
    for (const currentTable of currentSchemas) {
      const targetTable = targetSchemas.find(
        (t) => t.tableName === currentTable.tableName
      );

      if (!targetTable) {
        tableDiffs.push({
          tableName: currentTable.tableName,
          changeType: "DROP",
          oldSchema: currentTable,
          columnDiffs: [],
          indexDiffs: [],
        });
      }
    }

    return { tableDiffs };
  }

  static compareTable(
    current: TableSchema,
    target: TableSchema
  ): TableDiff {
    const columnDiffs: ColumnDiff[] = [];
    const indexDiffs: IndexDiff[] = [];

    // Compare Columns
    const currentCols = new Map(current.columns.map((c) => [c.name, c]));
    const targetCols = new Map(target.columns.map((c) => [c.name, c]));

    // Check target columns (Create or Alter)
    for (const targetCol of target.columns) {
      const currentCol = currentCols.get(targetCol.name);

      if (!currentCol) {
        columnDiffs.push({
          columnName: targetCol.name,
          changeType: "CREATE",
          newColumn: targetCol,
        });
      } else {
        const differences = this.compareColumnDefinitions(currentCol, targetCol);
        if (differences.length > 0) {
          columnDiffs.push({
            columnName: targetCol.name,
            changeType: "ALTER",
            oldColumn: currentCol,
            newColumn: targetCol,
            differences,
          });
        }
      }
    }

    // Check current columns (Drop)
    for (const currentCol of current.columns) {
      if (!targetCols.has(currentCol.name)) {
        columnDiffs.push({
          columnName: currentCol.name,
          changeType: "DROP",
          oldColumn: currentCol,
        });
      }
    }

    // Compare Indexes
    const currentIndexes = new Map((current.indexes || []).map((i) => [i.name, i]));
    const targetIndexes = new Map((target.indexes || []).map((i) => [i.name, i]));

    // Check target indexes (Create or Alter -> actually Drop + Create for indexes)
    for (const targetIdx of (target.indexes || [])) {
      const currentIdx = currentIndexes.get(targetIdx.name);

      if (!currentIdx) {
        indexDiffs.push({
          indexName: targetIdx.name,
          changeType: "CREATE",
          newIndex: targetIdx,
        });
      } else {
        if (!this.compareIndexDefinitions(currentIdx, targetIdx)) {
            // Indexes are immutable, so we drop and recreate if different
            indexDiffs.push({
                indexName: targetIdx.name,
                changeType: "ALTER",
                oldIndex: currentIdx,
                newIndex: targetIdx
            });
        }
      }
    }

    // Check current indexes (Drop)
    for (const currentIdx of (current.indexes || [])) {
      if (!targetIndexes.has(currentIdx.name)) {
        // Ignore SQLite auto-indexes which are implicit
        if (currentIdx.name.startsWith("sqlite_autoindex_")) continue;
        
        indexDiffs.push({
          indexName: currentIdx.name,
          changeType: "DROP",
          oldIndex: currentIdx,
        });
      }
    }

    let changeType: ChangeType = "NONE";
    if (columnDiffs.length > 0 || indexDiffs.length > 0) {
      changeType = "ALTER";
    }

    return {
      tableName: target.tableName,
      changeType,
      oldSchema: current,
      newSchema: target,
      columnDiffs,
      indexDiffs,
    };
  }

  static compareColumnDefinitions(
    col1: ColumnDefinition,
    col2: ColumnDefinition
  ): string[] {
    const diffs: string[] = [];

    // Normalize types for comparison (e.g. VARCHAR vs TEXT)
    const type1 = this.normalizeType(col1.type);
    const type2 = this.normalizeType(col2.type);

    if (type1 !== type2) diffs.push("type");
    if (!!col1.primaryKey !== !!col2.primaryKey) diffs.push("primaryKey");
    if (!!col1.notNull !== !!col2.notNull) diffs.push("notNull");
    if (!!col1.unique !== !!col2.unique) diffs.push("unique");

    // Default Value Comparison needs care (string vs number vs object)
    if (!this.compareDefaultValues(col1.defaultValue, col2.defaultValue)) {
        diffs.push("defaultValue");
    }

    return diffs;
  }

  static normalizeType(type: string): string {
      const t = type.toUpperCase();
      if (t === 'VARCHAR') return 'TEXT';
      if (t === 'INT') return 'INTEGER';
      if (t === 'BOOL') return 'BOOLEAN';
      return t;
  }

  static compareDefaultValues(val1: any, val2: any): boolean {
    if (val1 === val2) return true;
    if (val1 === undefined && val2 === undefined) return true;
    
    // Normalize string representation
    const s1 = String(val1);
    const s2 = String(val2);
    
    if (s1 === s2) return true;
    
    // Handle Boolean vs Boolean-as-Integer/String (SQLite)
    if ((s1 === "true" && s2 === "1") || (s1 === "1" && s2 === "true")) return true;
    if ((s1 === "false" && s2 === "0") || (s1 === "0" && s2 === "false")) return true;

    // Handle string quoting in defaults if needed
    // e.g. "'val'" vs "val"
    const clean1 = s1.replace(/^'|'$/g, '');
    const clean2 = s2.replace(/^'|'$/g, '');
    if (clean1 === clean2) return true;

    return false;
  }

  static compareIndexDefinitions(
    idx1: { columns: string[]; unique?: boolean },
    idx2: { columns: string[]; unique?: boolean }
  ): boolean {
    if (!!idx1.unique !== !!idx2.unique) return false;
    if (idx1.columns.length !== idx2.columns.length) return false;
    
    // Order matters for indexes
    for (let i = 0; i < idx1.columns.length; i++) {
        if (idx1.columns[i] !== idx2.columns[i]) return false;
    }
    return true;
  }
}
