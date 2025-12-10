/**
 * Type compatibility tests - this file should compile without errors
 * if the type inference is working correctly.
 * 
 * Run with: bunx tsc --noEmit tests/type-compatibility-check.ts
 */

import { z } from "zod";
import {
    Schema,
    InferTypedSchemaRead,
    InferTypedSchemaCreate,
    InferTypedSchemaUpdate,
} from "../src/database/schema/schema";

// Define a schema with strong types
const userSchemaDefinition = {
    id: { type: String, primaryKey: true },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isActive: { type: Boolean, default: true },
    role: { type: String, default: 'user' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
} as const;

// Create schema - now Schema is generic and preserves the type
const userSchema = new Schema(userSchemaDefinition);

// Get Zod schemas - no longer needs explicit type parameter
const userZodSchemas = userSchema.toZodTyped();

// Infer types using z.infer (this always worked)
type UserReadType = z.infer<typeof userZodSchemas.read>;
type UserCreateType = z.infer<typeof userZodSchemas.create>;
type UserUpdateType = z.infer<typeof userZodSchemas.update>;

// Infer types using our helpers (this should now work too!)
type UserReadType2 = InferTypedSchemaRead<typeof userSchema>;
type UserCreateType2 = InferTypedSchemaCreate<typeof userSchema>;
type UserUpdateType2 = InferTypedSchemaUpdate<typeof userSchema>;

// TYPE COMPATIBILITY CHECKS
// These types should be TRUE if inference is working correctly
type TypeCompatibilityCheck = UserReadType2 extends UserReadType ? true : false;
type CreateTypeCompatibilityCheck = UserCreateType2 extends UserCreateType ? true : false;
type UpdateTypeCompatibilityCheck = UserUpdateType2 extends UserUpdateType ? true : false;

// Static assertions - these will fail at compile time if types don't match
const _readCheck: TypeCompatibilityCheck = true;
const _createCheck: CreateTypeCompatibilityCheck = true;
const _updateCheck: UpdateTypeCompatibilityCheck = true;

// Test that we can use the types correctly
const testReadUser: UserReadType2 = {
    id: "user-123",
    username: "johndoe",
    email: "john@example.com",
    password: "hashed-password",
    isActive: true,
    role: "admin",
    createdAt: new Date(),
    updatedAt: new Date()
};

const testCreateUser: UserCreateType2 = {
    username: "johndoe",
    email: "john@example.com",
    password: "secure-password",
    // id is optional (primaryKey)
    // isActive is optional (has default)
    // role is optional (has default)
    // createdAt/updatedAt are optional (have defaults)
};

const testUpdateUser: UserUpdateType2 = {
    username: "johndoe-updated",
    // All fields are optional for update
};

console.log("Type compatibility checks passed!");
console.log({ testReadUser, testCreateUser, testUpdateUser });

export { };
