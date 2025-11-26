## implementacion con schema para schema builder
```typescript
import { Schema } from "./schema";

export const userSchema = new Schema(
  // 1. Definición de campos (Primer argumento)
  {
    id: { type: String, required: true, default: "(lower(hex(randomblob(16))))", unique: true },
    email: { type: String, required: true, unique: true },
    username: String,
    password_hash: { type: String, required: true },
    is_active: { type: Boolean, default: true },
    meta: { // Esto se convertirá en TEXT (JSON)
      preferences: Object,
      theme: String
    },
    created_at: { type: Date, default: Date.now }
  },
  // 2. Opciones e Índices (Segundo argumento, opcional)
  {
    indexes: [
      { name: "idx_users_email", columns: ["email"], unique: true },
      { name: "idx_users_username", columns: ["username"], unique: true },
      // Índice compuesto
      { name: "idx_users_status_date", columns: ["is_active", "created_at"] }, 
    ]
  }
);
```