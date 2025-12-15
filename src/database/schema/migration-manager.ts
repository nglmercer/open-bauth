import { Database } from "bun:sqlite";

export class MigrationManager {
  /**
   * Executes a list of migration SQL statements safely.
   * Handles Foreign Key constraints by disabling them temporarily.
   * wraps execution in a transaction.
   */
  static runMigrations(db: Database, statements: string[]): void {
    if (statements.length === 0) return;

    // 1. Disable Foreign Keys to allow table rebuilds (DROP TABLE referenced by FK)
    // Note: This must be done outside the transaction in some SQLite modes, 
    // but in Bun/standard SQLite it's a pragma.
    db.run("PRAGMA foreign_keys = OFF;");

    try {
      // 2. Execute statements transactionally
      const executeTransact = db.transaction(() => {
        for (const sql of statements) {
          // Log for debugging (optional)
          // console.log(`Executing: ${sql}`);
          db.run(sql);
        }
      });
      
      executeTransact();

      // 3. Verify integrity (Optional: explicit check)
      // If the migration left the DB in a bad state (e.g. data for FK missing), this will reveal it.
      const violations = db.query("PRAGMA foreign_key_check;").all();
      if (violations.length > 0) {
        throw new Error(`Migration resulted in Foreign Key violations: ${JSON.stringify(violations)}`);
      }

    } finally {
      // 4. Re-enable Foreign Keys
      db.run("PRAGMA foreign_keys = ON;");
    }
  }
}
