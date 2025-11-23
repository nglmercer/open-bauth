import { Hono } from "hono";
import { ProductController } from "../controllers/product.controller";
import { DatabaseInitializer } from "../../src/index";
import { randomUUID } from "crypto";
import { existsSync, mkdirSync, writeFileSync } from "fs";
import { join } from "path";

interface ProductRouterDependencies {
  dbInitializer: DatabaseInitializer;
}

export function createProductRoutes(deps: ProductRouterDependencies) {
  const app = new Hono();
  const productController = new ProductController(deps.dbInitializer);

  // Ensure uploads directory exists
  const uploadsDir = join(process.cwd(), "public", "images");
  if (!existsSync(uploadsDir)) {
    mkdirSync(uploadsDir, { recursive: true });
  }

  // Image upload endpoint
  app.post("/upload-image", async (c) => {
    try {
      const body = await c.req.parseBody();
      const file = body["image"] as File;

      if (!file) {
        return c.json(
          {
            success: false,
            error: {
              type: "VALIDATION_ERROR",
              message: "No image file provided",
            },
          },
          400,
        );
      }

      // Validate file type
      const allowedTypes = [
        "image/jpeg",
        "image/jpg",
        "image/png",
        "image/svg+xml",
        "image/webp",
      ];
      if (!allowedTypes.includes(file.type)) {
        return c.json(
          {
            success: false,
            error: {
              type: "VALIDATION_ERROR",
              message:
                "Invalid file type. Only JPEG, PNG, SVG, and WebP are allowed",
            },
          },
          400,
        );
      }

      // Validate file size (5MB max)
      const maxSize = 5 * 1024 * 1024; // 5MB
      if (file.size > maxSize) {
        return c.json(
          {
            success: false,
            error: {
              type: "VALIDATION_ERROR",
              message: "File size too large. Maximum 5MB allowed",
            },
          },
          400,
        );
      }

      // Generate unique filename
      const fileExtension = file.name.split(".").pop() || "jpg";
      const fileName = `${randomUUID().replace(/-/g, "")}.${fileExtension}`;
      const filePath = join(uploadsDir, fileName);

      // Save file
      const arrayBuffer = await file.arrayBuffer();
      const buffer = Buffer.from(arrayBuffer);
      writeFileSync(filePath, buffer);

      const imageUrl = `/images/${fileName}`;

      return c.json({
        success: true,
        data: {
          url: imageUrl,
          filename: fileName,
          originalName: file.name,
          size: file.size,
          type: file.type,
        },
        message: "Image uploaded successfully",
      });
    } catch (error) {
      console.error("Error uploading image:", error);
      return c.json(
        {
          success: false,
          error: {
            type: "UPLOAD_ERROR",
            message: "Failed to upload image",
          },
        },
        500,
      );
    }
  });

  // Product with image upload (combined endpoint)
  app.post("/products-with-image", async (c) => {
    try {
      const body = await c.req.parseBody();

      // Extract product data
      const productData = {
        name: body["name"] as string,
        description: body["description"] as string,
        price: parseFloat(body["price"] as string),
        category_id: body["category_id"] as string,
        fallback: body["fallback"] as string,
        stock_quantity: parseInt(body["stock_quantity"] as string) || 0,
      };

      // Validation
      if (!productData.name || !productData.price) {
        return c.json(
          {
            success: false,
            error: {
              type: "VALIDATION_ERROR",
              message: "Name and price are required",
            },
          },
          400,
        );
      }

      let imageUrl: string | null = null;

      // Handle image upload if provided
      const file = body["image"] as File;
      if (file && file.size > 0) {
        // Validate file type
        const allowedTypes = [
          "image/jpeg",
          "image/jpg",
          "image/png",
          "image/svg+xml",
          "image/webp",
        ];
        if (!allowedTypes.includes(file.type)) {
          return c.json(
            {
              success: false,
              error: {
                type: "VALIDATION_ERROR",
                message:
                  "Invalid file type. Only JPEG, PNG, SVG, and WebP are allowed",
              },
            },
            400,
          );
        }

        // Validate file size (5MB max)
        const maxSize = 5 * 1024 * 1024; // 5MB
        if (file.size > maxSize) {
          return c.json(
            {
              success: false,
              error: {
                type: "VALIDATION_ERROR",
                message: "File size too large. Maximum 5MB allowed",
              },
            },
            400,
          );
        }

        // Generate unique filename
        const fileExtension = file.name.split(".").pop() || "jpg";
        const fileName = `${randomUUID().replace(/-/g, "")}.${fileExtension}`;
        const filePath = join(uploadsDir, fileName);

        // Save file
        const arrayBuffer = await file.arrayBuffer();
        const buffer = Buffer.from(arrayBuffer);
        writeFileSync(filePath, buffer);

        imageUrl = `/images/${fileName}`;
      }

      // Create product using controller
      const productWithImage = {
        ...productData,
        image: imageUrl,
      };

      // Create a temporary context for the controller
      const tempContext = {
        req: {
          json: async () => productWithImage,
        },
      } as any;

      const result = await productController.createProduct(tempContext);
      const resultData = await result.json();

      if (!resultData.success) {
        return c.json(resultData, result);
      }

      const product = resultData.data;

      return c.json(
        {
          success: true,
          data: product,
          message: "Product created successfully with image",
        },
        201,
      );
    } catch (error) {
      console.error("Error creating product with image:", error);
      return c.json(
        {
          success: false,
          error: {
            type: "DATABASE_ERROR",
            message: "Failed to create product",
          },
        },
        500,
      );
    }
  });

  // Category routes
  app.get(
    "/categories",
    productController.getCategories.bind(productController),
  );
  app.post(
    "/categories",
    productController.createCategory.bind(productController),
  );

  // Product CRUD routes
  app.get("/products", productController.getProducts.bind(productController));
  app.get(
    "/products/:id",
    productController.getProduct.bind(productController),
  );
  app.post(
    "/products",
    productController.createProduct.bind(productController),
  );
  app.put(
    "/products/:id",
    productController.updateProduct.bind(productController),
  );
  app.delete(
    "/products/:id",
    productController.deleteProduct.bind(productController),
  );

  return app;
}
