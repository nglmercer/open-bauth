import { Context } from "hono";
import {
  DatabaseInitializer,
  BaseController,
  QueryOptions,
  RelationOptions,
  JoinOptions,
  WhereConditions,
} from "../../src/index";
import { randomUUID } from "crypto";
import { SchemaDataFilter } from "../integrations/SchemaDataFilter";
// Generic interfaces for API responses
interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string | ErrorDetail;
  message?: string;
  count?: number;
  total?: number;
}

interface ErrorDetail {
  type: string;
  message: string;
}

export interface ValidationRule {
  field: string;
  required?: boolean;
  type?: "string" | "number" | "boolean" | "array" | "object";
  min?: number;
  max?: number;
  pattern?: RegExp;
  validator?: (value: any) => boolean;
  message?: string;
}
export interface OneToOneRelationConfig {
  name: string;
  tableName: string;
  localKey: string;
  foreignKey: string;
}
export interface ControllerConfig {
  tableName: string;
  primaryKey?: string;
  validation?: {
    create?: ValidationRule[];
    update?: ValidationRule[];
  };
  oneToOneRelations?: OneToOneRelationConfig[];
  defaultFilters?: Record<string, any>;
  defaultOrder?: {
    field: string;
    direction: "ASC" | "DESC";
  };
}
const toSnake = (s: string): string => {
  return s.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`);
};

const convertKeys = (obj: any, converter: (s: string) => string): any => {
  if (Array.isArray(obj)) {
    return obj.map((v) => convertKeys(v, converter));
  } else if (
    obj !== null &&
    typeof obj === "object" &&
    obj.constructor === Object
  ) {
    return Object.keys(obj).reduce((result, key) => {
      result[converter(key)] = convertKeys(obj[key], converter);
      return result;
    }, {} as any);
  }
  return obj;
};
export class GenericController<
  T extends Record<string, any> = Record<string, any>,
> {
  private controller: BaseController<T>;
  private config: ControllerConfig;
  constructor(
    public dbInitializer: DatabaseInitializer,
    config: ControllerConfig,
  ) {
    this.config = {
      primaryKey: "id",
      ...config,
    };
    this.controller = dbInitializer.createController<T>(this.config.tableName);
  }

  // Generic validation method
  private validateData(
    data: any,
    operation: "create" | "update",
  ): { valid: boolean; errors: string[] } {
    const rules = this.config.validation?.[operation];
    if (!rules) return { valid: true, errors: [] };

    const errors: string[] = [];

    for (const rule of rules) {
      const value = data[rule.field];

      // Required field check
      if (
        rule.required &&
        (value === undefined || value === null || value === "")
      ) {
        errors.push(rule.message || `${rule.field} is required`);
        continue;
      }

      // Skip further validation if field is not present and not required
      if (value === undefined || value === null) continue;

      // Type validation
      if (rule.type) {
        const actualType = Array.isArray(value) ? "array" : typeof value;
        if (actualType !== rule.type) {
          errors.push(
            rule.message || `${rule.field} must be of type ${rule.type}`,
          );
          continue;
        }
      }

      // Min/Max validation for numbers and strings
      if (rule.min !== undefined) {
        if (typeof value === "number" && value < rule.min) {
          errors.push(
            rule.message || `${rule.field} must be at least ${rule.min}`,
          );
        } else if (typeof value === "string" && value.length < rule.min) {
          errors.push(
            rule.message ||
              `${rule.field} must be at least ${rule.min} characters`,
          );
        }
      }

      if (rule.max !== undefined) {
        if (typeof value === "number" && value > rule.max) {
          errors.push(
            rule.message || `${rule.field} must be at most ${rule.max}`,
          );
        } else if (typeof value === "string" && value.length > rule.max) {
          errors.push(
            rule.message ||
              `${rule.field} must be at most ${rule.max} characters`,
          );
        }
      }

      // Pattern validation
      if (
        rule.pattern &&
        typeof value === "string" &&
        !rule.pattern.test(value)
      ) {
        errors.push(rule.message || `${rule.field} has invalid format`);
      }

      // Custom validator
      if (rule.validator && !rule.validator(value)) {
        errors.push(rule.message || `${rule.field} is invalid`);
      }
    }

    return { valid: errors.length === 0, errors };
  }

  private buildAllJoins(): JoinOptions[] {
    const joins: JoinOptions[] = [];

    if (this.config.oneToOneRelations) {
      const oneToOneJoins = this.config.oneToOneRelations.map((rel) => {
        return this.controller.createJoin(
          rel.tableName,
          rel.localKey,
          rel.foreignKey,
          "LEFT",
          ["*"],
        );
      });
      joins.push(...oneToOneJoins);
    }

    return joins;
  }

  async getAll(c: Context): Promise<Response> {
    try {
      const limit = parseInt(c.req.query("limit") || "50");
      const offset = parseInt(c.req.query("offset") || "0");
      const orderBy =
        c.req.query("order_by") || this.config.defaultOrder?.field;
      const orderDirection = (c.req.query("order_direction") ||
        this.config.defaultOrder?.direction ||
        "ASC") as "ASC" | "DESC";

      const filters: Record<string, any> = { ...this.config.defaultFilters };

      for (const [key, value] of Object.entries(c.req.query())) {
        if (
          ![
            "limit",
            "offset",
            "order_by",
            "order_direction",
            "include_relations",
          ].includes(key) &&
          value
        ) {
          if (value.includes(",")) {
            filters[key] = value.split(",");
          } else {
            filters[key] = value;
          }
        }
      }
      let result;

      if (this.config.oneToOneRelations) {
        // Usar joins que incluyen tanto relationships como oneToOneRelations
        const joins = this.buildAllJoins();
        const options: RelationOptions<T> = {
          where: filters as WhereConditions<T>,
          joins,
          limit,
          offset,
          orderBy,
          orderDirection,
        };

        result = await this.controller.findWithRelations(options);
      } else {
        const options: QueryOptions<T> = {
          where: filters as WhereConditions<T>,
          limit,
          offset,
          orderBy,
          orderDirection,
        };

        result = await this.controller.findAll(options);
      }

      if (!result.success) {
        return c.json(
          {
            success: false,
            error: result.error || "Failed to retrieve records",
          },
          500,
        );
      }

      const processedData =
        result.data?.map((record: any) =>
          this.postprocessDataFromDatabase(record),
        ) || [];

      return c.json({
        success: true,
        data: processedData,
        count: processedData.length,
        total: result.total,
      });
    } catch (error) {
      console.error(`Error fetching ${this.config.tableName}:`, error);
      return c.json(
        {
          success: false,
          error: "Internal server error",
        },
        500,
      );
    }
  }

  // Get single record by ID
  async getById(c: Context): Promise<Response> {
    try {
      const id = c.req.param("id");
      const includeRelations = c.req.query("include_relations") === "true";

      let result;

      if (includeRelations && this.config.oneToOneRelations) {
        const joins = this.buildAllJoins();
        result = await this.controller.findByIdWithRelations(id, joins);
      } else {
        result = await this.controller.findById(id);
      }

      if (!result.success || !result.data) {
        return c.json(
          {
            success: false,
            error: {
              type: "NOT_FOUND",
              message: "Record not found",
            },
          },
          404,
        );
      }

      // Postprocess data from database
      const processedData = this.postprocessDataFromDatabase(result.data);

      return c.json({
        success: true,
        data: processedData,
        message: "Record retrieved successfully",
      });
    } catch (error) {
      console.error(`Error getting ${this.config.tableName}:`, error);
      return c.json(
        {
          success: false,
          error: {
            type: "DATABASE_ERROR",
            message: "Failed to retrieve record",
          },
        },
        500,
      );
    }
  }

  protected preprocessDataForDatabase(
    data: any,
    operation: "create" | "update",
  ): any {
    let processedData = convertKeys(data, toSnake);

    const jsonFields = this.getJsonFields();

    for (const field of jsonFields) {
      const snakeCaseField = toSnake(field);
      if (
        processedData[snakeCaseField] !== undefined &&
        processedData[snakeCaseField] !== null
      ) {
        if (
          Array.isArray(processedData[snakeCaseField]) ||
          typeof processedData[snakeCaseField] === "object"
        ) {
          processedData[snakeCaseField] = JSON.stringify(
            processedData[snakeCaseField],
          );
        }
      }
    }

    return processedData;
  }

  private postprocessDataFromDatabase(data: any): any {
    if (!data) return data;

    const processedData = { ...data };
    const jsonFields = this.getJsonFields();

    for (const field of jsonFields) {
      if (processedData[field] && typeof processedData[field] === "string") {
        try {
          processedData[field] = JSON.parse(processedData[field]);
        } catch (error) {
          // Si no es JSON válido, mantener el valor original
          console.warn(`Failed to parse JSON for field ${field}:`, error);
        }
      }
    }

    return processedData;
  }

  private getJsonFields(): string[] {
    const jsonFieldsMap: Record<string, string[]> = {
      projects: ["team"],
      //Not other tables with JSON fields yet
    };

    return jsonFieldsMap[this.config.tableName] || [];
  }

  async create(c: Context): Promise<Response> {
    try {
      const body = await c.req.json();

      const validation = this.validateData(body, "create");
      if (!validation.valid) {
        return c.json(
          { success: false, error: validation.errors.join(", ") },
          400,
        );
      }

      const primaryKey = this.config.primaryKey!;
      if (!body[primaryKey]) {
        body[primaryKey] = randomUUID();
      }

      const now = new Date().toISOString();
      if (!body.created_at) body.created_at = now;
      if (!body.updated_at) body.updated_at = now;

      const processedData = this.preprocessDataForDatabase(body, "create");
      const mainTableData = await this.filterDataBySchema(processedData);
      const createResult = await this.controller.create(mainTableData);
      if (!createResult.success || !createResult.data) {
        return c.json(
          {
            success: false,
            error: createResult.error || "Failed to create main record",
          },
          500,
        );
      }

      const newId = createResult.data[primaryKey];
      const relationResult = await this.handleOneToOneRelations(
        newId,
        body,
        "create",
      );

      if (!relationResult.success) {
        return c.json(
          {
            success: false,
            error: `Main record created, but failed to process related data: ${relationResult.errors.join(", ")}`,
          },
          500,
        );
      }

      let finalData = this.postprocessDataFromDatabase(createResult.data);

      const joins = this.buildAllJoins();
      const withRelations = await this.controller.findByIdWithRelations(
        newId,
        joins,
      );
      if (withRelations.success && withRelations.data) {
        finalData = this.postprocessDataFromDatabase(withRelations.data);
      }

      return c.json(
        {
          success: true,
          data: finalData,
          message: "Record created successfully",
        },
        201,
      );
    } catch (error) {
      console.error(`Error creating ${this.config.tableName}:`, error);
      return c.json({ success: false, error: "Failed to create record" }, 500);
    }
  }

  async update(c: Context): Promise<Response> {
    try {
      const id = c.req.param("id");
      const body = await c.req.json();

      const existingRecord = await this.controller.findById(id);
      if (!existingRecord.success || !existingRecord.data) {
        return c.json({ success: false, error: "Record not found" }, 404);
      }

      const validation = this.validateData(body, "update");
      if (!validation.valid) {
        return c.json(
          { success: false, error: validation.errors.join(", ") },
          400,
        );
      }
      body.updated_at = new Date().toISOString();
      const processedData = this.preprocessDataForDatabase(body, "update");
      const mainTableData = await this.filterDataBySchema(processedData);
      const updateResult = await this.controller.update(id, mainTableData);

      if (!updateResult.success) {
        return c.json(
          {
            success: false,
            error: updateResult.error || "Failed to update main record",
          },
          500,
        );
      }
      const relationResult = await this.handleOneToOneRelations(
        id,
        body,
        "update",
      );
      console.log("relationResult", relationResult);
      if (!relationResult.success) {
        return c.json(
          {
            success: false,
            error: `Main record updated, but failed to process related data: ${relationResult.errors.join(", ")}`,
          },
          500,
        );
      }

      let finalData = this.postprocessDataFromDatabase(updateResult.data);

      const joins = this.buildAllJoins();
      const withRelations = await this.controller.findByIdWithRelations(
        id,
        joins,
      );
      console.log("withRelations", { withRelations, finalData });
      if (withRelations.success && withRelations.data) {
        finalData = this.postprocessDataFromDatabase(withRelations.data);
      }

      return c.json({
        success: true,
        data: finalData,
        message: "Record updated successfully",
      });
    } catch (error) {
      console.error(`Error updating ${this.config.tableName}:`, error);
      return c.json({ success: false, error: "Failed to update record" }, 500);
    }
  }

  // Delete record
  async delete(c: Context): Promise<Response> {
    try {
      const id = c.req.param("id");

      // Check if record exists
      const existingRecord = await this.controller.findById(id);
      if (!existingRecord.success || !existingRecord.data) {
        return c.json(
          {
            success: false,
            error: "Record not found",
          },
          404,
        );
      }

      const result = await this.controller.delete(id);

      if (!result.success) {
        return c.json(
          {
            success: false,
            error: result.error || "Failed to delete record",
          },
          500,
        );
      }

      return c.json({
        success: true,
        message: "Record deleted successfully",
      });
    } catch (error) {
      console.error(`Error deleting ${this.config.tableName}:`, error);
      return c.json(
        {
          success: false,
          error: "Failed to delete record",
        },
        500,
      );
    }
  }

  // Search records
  async search(c: Context): Promise<Response> {
    try {
      const body = await c.req.json();
      const {
        filters = {},
        limit = 50,
        offset = 0,
        orderBy,
        orderDirection = "ASC",
      } = body;

      // Merge with default filters
      const combinedFilters = { ...this.config.defaultFilters, ...filters };
      const includeRelations = body.include_relations === true;

      let result;

      if (includeRelations && this.config.oneToOneRelations) {
        const joins = this.buildAllJoins();
        const options: RelationOptions<T> = {
          where: combinedFilters as WhereConditions<T>,
          joins,
          limit,
          offset,
          orderBy,
          orderDirection: orderDirection as "ASC" | "DESC",
        };

        result = await this.controller.findWithRelations(options);
      } else {
        result = await this.controller.search(
          combinedFilters as WhereConditions<T>,
          {
            limit,
            offset,
            orderBy,
            orderDirection: orderDirection as "ASC" | "DESC",
          },
        );
      }

      if (!result.success) {
        return c.json(
          {
            success: false,
            error: result.error || "Search failed",
          },
          500,
        );
      }

      return c.json({
        success: true,
        data: result.data || [],
        count: result.data?.length || 0,
        total: result.total,
      });
    } catch (error) {
      console.error(`Error searching ${this.config.tableName}:`, error);
      return c.json(
        {
          success: false,
          error: "Search failed",
        },
        500,
      );
    }
  }

  // Count records
  async count(c: Context): Promise<Response> {
    try {
      // Build filters from query parameters
      const filters: Record<string, any> = { ...this.config.defaultFilters };

      for (const [key, value] of Object.entries(c.req.query())) {
        if (value) {
          if (value.includes(",")) {
            filters[key] = value.split(",");
          } else {
            filters[key] = value;
          }
        }
      }

      const result = await this.controller.count(filters as WhereConditions<T>);

      if (!result.success) {
        return c.json(
          {
            success: false,
            error: result.error || "Count failed",
          },
          500,
        );
      }

      return c.json({
        success: true,
        data: { count: result.data },
      });
    } catch (error) {
      console.error(`Error counting ${this.config.tableName}:`, error);
      return c.json(
        {
          success: false,
          error: "Count failed",
        },
        500,
      );
    }
  }

  // Get random records
  async random(c: Context): Promise<Response> {
    try {
      const limit = parseInt(c.req.query("limit") || "5");
      const filters: Record<string, any> = { ...this.config.defaultFilters };

      // Build filters from query parameters
      for (const [key, value] of Object.entries(c.req.query())) {
        if (!["limit"].includes(key) && value) {
          filters[key] = value;
        }
      }

      const result = await this.controller.random(
        filters as WhereConditions<T>,
        limit,
      );

      if (!result.success) {
        return c.json(
          {
            success: false,
            error: result.error || "Failed to get random records",
          },
          500,
        );
      }

      return c.json({
        success: true,
        data: result.data || [],
        count: result.data?.length || 0,
      });
    } catch (error) {
      console.error(`Error getting random ${this.config.tableName}:`, error);
      return c.json(
        {
          success: false,
          error: "Failed to get random records",
        },
        500,
      );
    }
  }

  // Get first record matching criteria
  async findFirst(c: Context): Promise<Response> {
    try {
      const body = await c.req.json();
      const { filters = {} } = body;

      const combinedFilters = { ...this.config.defaultFilters, ...filters };

      const result = await this.controller.findFirst(
        combinedFilters as WhereConditions<T>,
      );

      if (!result.success) {
        return c.json(
          {
            success: false,
            error: result.error || "Search failed",
          },
          500,
        );
      }

      if (!result.data) {
        return c.json(
          {
            success: false,
            error: "No record found matching criteria",
          },
          404,
        );
      }

      return c.json({
        success: true,
        data: result.data,
      });
    } catch (error) {
      console.error(`Error finding first ${this.config.tableName}:`, error);
      return c.json(
        {
          success: false,
          error: "Search failed",
        },
        500,
      );
    }
  }

  // Execute custom query
  async customQuery(c: Context): Promise<Response> {
    try {
      const body = await c.req.json();
      const { sql, params = [] } = body;

      if (!sql) {
        return c.json(
          {
            success: false,
            error: "SQL query is required",
          },
          400,
        );
      }

      const result = await this.controller.query(sql, params);

      return c.json({
        success: result.success,
        data: result.data,
        error: result.error,
      });
    } catch (error) {
      console.error(
        `Error executing custom query on ${this.config.tableName}:`,
        error,
      );
      return c.json(
        {
          success: false,
          error: "Query execution failed",
        },
        500,
      );
    }
  }

  // Get table schema
  async getSchema(c: Context): Promise<Response> {
    try {
      const result = await this.controller.getSchema();

      return c.json({
        success: result.success,
        data: {
          ...result.data,
          config: this.config,
        },
        error: result.error,
      });
    } catch (error) {
      console.error(
        `Error getting schema for ${this.config.tableName}:`,
        error,
      );
      return c.json(
        {
          success: false,
          error: "Failed to get schema",
        },
        500,
      );
    }
  }
  private async handleOneToOneRelations(
    mainRecordId: string,
    data: Record<string, any>,
    operation: "create" | "update",
  ): Promise<{ success: boolean; errors: string[] }> {
    if (!this.config.oneToOneRelations) {
      return { success: true, errors: [] };
    }

    const errors: string[] = [];
    for (const relation of this.config.oneToOneRelations) {
      const relatedData = await this.filterDataBySchemaForTable(
        data,
        relation.tableName,
      );

      try {
        const relatedController = this.dbInitializer.createController(
          relation.tableName,
        );
        const existing = await relatedController.findById(mainRecordId);
        // Filter related data using schema before processing
        const processedRelatedData = this.preprocessDataForDatabase(
          relatedData,
          operation,
        );
        const filteredRelatedData = await this.filterDataBySchemaForTable(
          processedRelatedData,
          relation.tableName,
        );

        if (existing.success && existing.data) {
          const updateResult = await relatedController.update(
            mainRecordId,
            filteredRelatedData,
          );
          if (!updateResult.success) {
            errors.push(
              `Failed to update related record in '${relation.tableName}': ${updateResult.error}`,
            );
          }
        } else {
          filteredRelatedData[relation.foreignKey] = mainRecordId;
          const createResult =
            await relatedController.create(filteredRelatedData);
          if (!createResult.success) {
            errors.push(
              `Failed to create related record in '${relation.tableName}': ${createResult.error}`,
            );
          }
        }
      } catch (error: any) {
        errors.push(
          `An exception occurred while handling relation '${relation.name}': ${error.message}`,
        );
      }
    }

    return { success: errors.length === 0, errors };
  }

  private async filterDataBySchemaForTable(
    data: Record<string, any>,
    tableName: string,
  ): Promise<Record<string, any>> {
    const relatedController = this.dbInitializer.createController(tableName);
    const getSchemaFn = async () => await relatedController.getSchema();
    return SchemaDataFilter.filterAndFillDefaults(data, getSchemaFn);
  }

  private async filterDataBySchema(
    data: Record<string, any>,
  ): Promise<Record<string, any>> {
    const getSchemaFn = async () => await this.controller.getSchema();
    return SchemaDataFilter.filterAndFillDefaults(data, getSchemaFn);
  }
}
const userConfig: ControllerConfig = {
  tableName: "users",
  primaryKey: "id",
  validation: {
    create: [
      {
        field: "email",
        required: true,
        type: "string",
        pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        message: "Email must be valid",
      },
      { field: "name", required: true, type: "string", min: 1, max: 255 },
      { field: "age", type: "number", min: 13, max: 120 },
      {
        field: "password",
        required: true,
        type: "string",
        min: 8,
        validator: (value) => /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(value),
        message:
          "Password must contain at least one lowercase, uppercase, and number",
      },
    ],
    update: [
      {
        field: "email",
        type: "string",
        pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        message: "Email must be valid",
      },
      { field: "name", type: "string", min: 1, max: 255 },
      { field: "age", type: "number", min: 13, max: 120 },
      {
        field: "password",
        type: "string",
        min: 8,
        validator: (value) => /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(value),
        message:
          "Password must contain at least one lowercase, uppercase, and number",
      },
    ],
  },
  defaultFilters: {
    is_active: true,
  },
  defaultOrder: {
    field: "created_at",
    direction: "DESC",
  },
};
export class userController extends GenericController {
  constructor(dbInitializer: DatabaseInitializer) {
    super(dbInitializer, userConfig);
  }
}
