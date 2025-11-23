import { Context } from "hono";
import { DatabaseInitializer, BaseController } from "../../src/index";
import { randomUUID } from "crypto";

interface Product {
  id: string;
  name: string;
  description?: string;
  price: number;
  category_id?: string;
  image?: string;
  fallback?: string;
  is_available: boolean;
  stock_quantity: number;
  created_at: string;
  updated_at: string;
}

interface Category {
  id: string;
  name: string;
  icon?: string;
  description?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export class ProductController {
  private productController: BaseController<Product>;
  private categoryController: BaseController<Category>;

  constructor(public dbInitializer: DatabaseInitializer) {
    this.productController =
      dbInitializer.createController<Product>("products");
    this.categoryController =
      dbInitializer.createController<Category>("categories");
  }

  // Get all products with optional category filter
  async getProducts(c: Context) {
    try {
      const categoryId = c.req.query("category_id");

      // Build filter conditions
      const filter = categoryId
        ? { category_id: categoryId, is_available: true }
        : { is_available: true };

      // Create join with categories table
      // Join products.category_id with categories.id
      const categoryJoin = this.productController.createReverseJoin(
        "categories",
        "id", // column in categories table
        "category_id", // column in products table (this table)
        "LEFT",
        ["name AS category_name", "icon AS category_icon"],
      );

      // Use findWithRelations to get products with category information
      const result = await this.productController.findWithRelations({
        where: filter,
        joins: [categoryJoin],
        orderBy: "created_at",
        orderDirection: "DESC",
      });
      console.log("result get products", result);
      /*
      result get products {
        success: false,
        error: "no such column: categories.category_id",
      }
      */
      if (!result.success) {
        return c.json(
          {
            success: false,
            error: "Failed to retrieve products",
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
      console.error("Error fetching products:", error);
      return c.json(
        {
          success: false,
          error: "Failed to fetch products",
        },
        500,
      );
    }
  }

  // Get single product by ID
  async getProduct(c: Context) {
    try {
      const id = c.req.param("id");

      // Use the new findByIdWithRelations method instead of raw SQL
      // Join products.category_id with categories.id
      const categoryJoin = this.productController.createReverseJoin(
        "categories",
        "id", // column in categories table
        "category_id", // column in products table (this table)
        "LEFT",
        ["name AS category_name", "icon AS category_icon"],
      );

      const result = await this.productController.findByIdWithRelations(id, [
        categoryJoin,
      ]);

      if (!result.success || !result.data) {
        return c.json(
          {
            success: false,
            error: {
              type: "NOT_FOUND",
              message: "Product not found",
            },
          },
          404,
        );
      }

      return c.json({
        success: true,
        data: result.data,
        message: "Product retrieved successfully",
      });
    } catch (error) {
      console.error("Error getting product:", error);
      return c.json(
        {
          success: false,
          error: {
            type: "DATABASE_ERROR",
            message: "Failed to retrieve product",
          },
        },
        500,
      );
    }
  }

  // Create a new product
  async createProduct(c: Context) {
    try {
      const body = await c.req.json();

      // Validation
      if (!body.name || !body.price) {
        return c.json(
          {
            success: false,
            error: "Name and price are required",
          },
          400,
        );
      }

      if (typeof body.price !== "number" || body.price < 0) {
        return c.json(
          {
            success: false,
            error: "Price must be a positive number",
          },
          400,
        );
      }

      // Check if category exists (if provided)
      if (body.category_id) {
        const category = await this.categoryController.findById(
          body.category_id,
        );
        if (!category) {
          return c.json(
            {
              success: false,
              error: "Category not found",
            },
            400,
          );
        }
      }

      const productId = randomUUID();
      const now = new Date().toISOString();

      const productData: Product = {
        id: productId,
        name: body.name,
        description: body.description || undefined,
        price: body.price,
        category_id: body.category_id || undefined,
        image: body.image || undefined,
        fallback: body.fallback || undefined,
        is_available: body.is_available !== false,
        stock_quantity: body.stock_quantity || 0,
        created_at: now,
        updated_at: now,
      };

      const createResult = await this.productController.create(productData);

      if (!createResult.success || !createResult.data) {
        return c.json(
          {
            success: false,
            error: "Failed to create product",
          },
          500,
        );
      }

      // Get the created product with category information
      const categoryJoin = this.productController.createReverseJoin(
        "categories",
        "id",
        "category_id",
        "LEFT",
        ["name AS category_name", "icon AS category_icon"],
      );

      const productWithCategory =
        await this.productController.findByIdWithRelations(
          createResult.data.id,
          [categoryJoin],
        );

      return c.json(
        {
          success: true,
          data: productWithCategory.data || createResult.data,
          message: "Product created successfully",
        },
        201,
      );
    } catch (error) {
      console.error("Error creating product:", error);
      return c.json(
        {
          success: false,
          error: "Failed to create product",
        },
        500,
      );
    }
  }

  // Update product
  async updateProduct(c: Context) {
    try {
      const id = c.req.param("id");
      const body = await c.req.json();

      // Check if product exists
      const existingProduct = await this.productController.findById(id);
      if (!existingProduct) {
        return c.json(
          {
            success: false,
            error: "Product not found",
          },
          404,
        );
      }

      // Validate price if provided
      if (
        body.price !== undefined &&
        (typeof body.price !== "number" || body.price <= 0)
      ) {
        return c.json(
          {
            success: false,
            error: "Price must be a positive number",
          },
          400,
        );
      }

      // Check if category exists (if provided)
      if (body.category_id) {
        const category = await this.categoryController.findById(
          body.category_id,
        );
        if (!category) {
          return c.json(
            {
              success: false,
              error: "Category not found",
            },
            400,
          );
        }
      }

      // Prepare update data
      const updateData: Partial<Product> = {
        updated_at: new Date().toISOString(),
      };

      const allowedFields = [
        "name",
        "description",
        "price",
        "category_id",
        "image",
        "fallback",
        "is_available",
        "stock_quantity",
      ];

      for (const field of allowedFields) {
        if (body[field] !== undefined) {
          updateData[field as keyof Product] = body[field];
        }
      }

      if (Object.keys(updateData).length === 1) {
        // Only updated_at
        return c.json(
          {
            success: false,
            error: "No valid fields to update",
          },
          400,
        );
      }

      const updateResult = await this.productController.update(id, updateData);

      if (!updateResult.success || !updateResult.data) {
        return c.json(
          {
            success: false,
            error: "Failed to update product",
          },
          500,
        );
      }

      // Get the updated product with category information
      const categoryJoin = this.productController.createReverseJoin(
        "categories",
        "id",
        "category_id",
        "LEFT",
        ["name AS category_name", "icon AS category_icon"],
      );

      const productWithCategory =
        await this.productController.findByIdWithRelations(id, [categoryJoin]);

      return c.json({
        success: true,
        data: productWithCategory.data || updateResult.data,
        message: "Product updated successfully",
      });
    } catch (error) {
      console.error("Error updating product:", error);
      return c.json(
        {
          success: false,
          error: "Failed to update product",
        },
        500,
      );
    }
  }

  // Delete product
  async deleteProduct(c: Context) {
    try {
      const id = c.req.param("id");

      // Check if product exists
      const existingProduct = await this.productController.findById(id);
      if (!existingProduct) {
        return c.json(
          {
            success: false,
            error: "Product not found",
          },
          404,
        );
      }

      await this.productController.delete(id);

      return c.json({
        success: true,
        message: "Product deleted successfully",
      });
    } catch (error) {
      console.error("Error deleting product:", error);
      return c.json(
        {
          success: false,
          error: "Failed to delete product",
        },
        500,
      );
    }
  }

  // Get all categories
  async getCategories(c: Context) {
    try {
      const categoriesResult = await this.categoryController.findAll({
        where: { is_active: true },
      });
      const productsResult = await this.productController.findAll({
        where: { is_available: true },
      });

      if (!categoriesResult.success || !productsResult.success) {
        return c.json(
          {
            success: false,
            error: "Failed to retrieve data",
          },
          500,
        );
      }

      const categories = categoriesResult.data || [];
      const products = productsResult.data || [];

      // Count products per category
      const productCounts = products.reduce(
        (acc, product) => {
          if (product.category_id) {
            acc[product.category_id] = (acc[product.category_id] || 0) + 1;
          }
          return acc;
        },
        {} as Record<string, number>,
      );

      const categoriesWithCounts = categories.map((category) => ({
        ...category,
        product_count: productCounts[category.id] || 0,
      }));

      return c.json({
        success: true,
        data: categoriesWithCounts,
        message: "Categories retrieved successfully",
      });
    } catch (error) {
      console.error("Error getting categories:", error);
      return c.json(
        {
          success: false,
          error: "Failed to retrieve categories",
        },
        500,
      );
    }
  }

  // Create new category
  async createCategory(c: Context) {
    try {
      const body = await c.req.json();

      // Validation
      if (!body.name) {
        return c.json(
          {
            success: false,
            error: "Name is required",
          },
          400,
        );
      }

      // Check if category name already exists
      const existingCategoriesResult = await this.categoryController.findAll({
        where: { name: body.name },
      });
      if (!existingCategoriesResult.success) {
        return c.json(
          {
            success: false,
            error: "Failed to check existing categories",
          },
          500,
        );
      }

      const existingCategories = existingCategoriesResult.data || [];
      if (existingCategories.length > 0) {
        return c.json(
          {
            success: false,
            error: "Category name already exists",
          },
          400,
        );
      }

      const categoryId = randomUUID();
      const now = new Date().toISOString();

      const categoryData: Category = {
        id: categoryId,
        name: body.name,
        icon: body.icon || undefined,
        description: body.description || undefined,
        is_active: true,
        created_at: now,
        updated_at: now,
      };

      const createdCategory =
        await this.categoryController.create(categoryData);

      return c.json(
        {
          success: true,
          data: createdCategory,
          message: "Category created successfully",
        },
        201,
      );
    } catch (error) {
      console.error("Error creating category:", error);
      return c.json(
        {
          success: false,
          error: "Failed to create category",
        },
        500,
      );
    }
  }
}
