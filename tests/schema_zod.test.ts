
import { describe, expect, test } from "bun:test";
import { Schema } from "../src/database/schema/schema";
import { z } from "zod";

describe("Schema to Zod Generation", () => {
    test("should generate correct Zod schema for simple definition", () => {
        const userSchema = new Schema({
            username: { type: String, required: true },
            age: Number,
            isActive: { type: Boolean, default: true }
        });

        const zodSchemas = userSchema.toZod();

        expect(zodSchemas.create).toBeDefined();
        // username required
        expect(() => zodSchemas.create.parse({ username: "test" })).not.toThrow();
        // Missing required field
        expect(() => zodSchemas.create.parse({ age: 25 })).toThrow();
    });

    test("should handle native constructors", () => {
        const simple = new Schema({
            name: String,
            count: Number
        });

        const zSchema = simple.toZod();
        expect(() => zSchema.create.parse({ name: "a", count: 1 })).not.toThrow();
        // Missing fields - count/name are optional by default in SQL/Mongoose-lite logic if not required:true
        expect(() => zSchema.create.parse({})).not.toThrow();
    });
});
