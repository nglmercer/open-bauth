import { Database } from "bun:sqlite";
import { DatabaseInitializer } from "../src/index";
import { merged } from "./integrations/newSchemas";
import { randomUUID } from "crypto";

// Food data with proper image URLs and fallbacks
const foodData = {
  burgers: [
    {
      id: 1,
      name: "Quarter Pounder With Cheese",
      price: 3.99,
      image: "/images/quarter-pounder-cheese.svg",
      fallback: "🍔",
    },
    {
      id: 2,
      name: "Double Quarter Pounder With Cheese",
      price: 4.79,
      image: "/images/double-quarter-pounder.jpg",
      fallback: "🍔",
    },
    {
      id: 3,
      name: "Quarter Pounder With Cheese Deluxe",
      price: 4.29,
      image: "/images/quarter-pounder-deluxe.jpg",
      fallback: "🍔",
    },
    {
      id: 4,
      name: "Big Mac",
      price: 3.99,
      image: "/images/big-mac.jpg",
      fallback: "🍔",
    },
    {
      id: 5,
      name: "McDouble",
      price: 1.99,
      image: "/images/mcdouble.jpg",
      fallback: "🍔",
    },
    {
      id: 6,
      name: "Quarter Pounder With Cheese Bacon",
      price: 4.99,
      image: "/images/quarter-pounder-bacon.jpg",
      fallback: "🍔",
    },
  ],
  sandwiches: [
    {
      id: 7,
      name: "Chicken Sandwich",
      price: 4.49,
      image: "/images/chicken-sandwich.jpg",
      fallback: "🥪",
    },
    {
      id: 8,
      name: "Fish Sandwich",
      price: 3.79,
      image: "/images/fish-sandwich.jpg",
      fallback: "🥪",
    },
  ],
  sides: [
    {
      id: 9,
      name: "Large Fries",
      price: 2.99,
      image: "/images/large-fries.svg",
      fallback: "🍟",
    },
    {
      id: 10,
      name: "Medium Fries",
      price: 2.49,
      image: "/images/medium-fries.jpg",
      fallback: "🍟",
    },
    {
      id: 11,
      name: "Small Fries",
      price: 1.99,
      image: "/images/small-fries.jpg",
      fallback: "🍟",
    },
  ],
  drinks: [
    {
      id: 12,
      name: "Medium Soda",
      price: 1.99,
      image: "/images/medium-soda.svg",
      fallback: "🥤",
    },
    {
      id: 13,
      name: "Large Soda",
      price: 2.29,
      image: "/images/large-soda.jpg",
      fallback: "🥤",
    },
    {
      id: 14,
      name: "M&Ms McFlurry",
      price: 3.99,
      image: "/images/mcflurry.jpg",
      fallback: "🍦",
    },
  ],
};

// Categories configuration
const categories = [
  { id: "meals", name: "Meals", icon: "🍽️" },
  { id: "burgers", name: "Burgers", icon: "🍔" },
  { id: "sandwiches", name: "Sandwiches", icon: "🥪" },
  { id: "sides", name: "Sides", icon: "🍟" },
  { id: "drinks", name: "Drinks", icon: "🥤" },
];

async function seedProducts() {
  console.log("🌱 Starting product seeding...");

  // Initialize database
  const db = new Database("auth.db");
  const dbInitializer = new DatabaseInitializer({
    database: db,
    externalSchemas: merged.getAll(),
  });
  await dbInitializer.initialize();

  try {
    // Clear existing data
    console.log("🧹 Clearing existing product data...");
    db.prepare("DELETE FROM products").run();
    db.prepare("DELETE FROM categories").run();

    // Insert categories
    console.log("📂 Inserting categories...");
    const categoryInsert = db.prepare(`
      INSERT INTO categories (id, name, icon, description, is_active)
      VALUES (?, ?, ?, ?, 1)
    `);

    const categoryMap = new Map();
    for (const category of categories) {
      const categoryId = randomUUID().replace(/-/g, "");
      categoryInsert.run(
        categoryId,
        category.name,
        category.icon,
        `${category.name} category`,
      );
      categoryMap.set(category.id, categoryId);
      console.log(`  ✅ Created category: ${category.name}`);
    }

    // Insert products
    console.log("🍔 Inserting products...");
    const productInsert = db.prepare(`
      INSERT INTO products (id, name, description, price, category_id, image, fallback, is_available, stock_quantity)
      VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
    `);

    let totalProducts = 0;

    // Insert burgers
    for (const product of foodData.burgers) {
      const productId = randomUUID().replace(/-/g, "");
      productInsert.run(
        productId,
        product.name,
        `Delicious ${product.name.toLowerCase()}`,
        product.price,
        categoryMap.get("burgers"),
        product.image,
        product.fallback,
        Math.floor(Math.random() * 50) + 10, // Random stock between 10-60
      );
      totalProducts++;
    }

    // Insert sandwiches
    for (const product of foodData.sandwiches) {
      const productId = randomUUID().replace(/-/g, "");
      productInsert.run(
        productId,
        product.name,
        `Fresh ${product.name.toLowerCase()}`,
        product.price,
        categoryMap.get("sandwiches"),
        product.image,
        product.fallback,
        Math.floor(Math.random() * 30) + 5, // Random stock between 5-35
      );
      totalProducts++;
    }

    // Insert sides
    for (const product of foodData.sides) {
      const productId = randomUUID().replace(/-/g, "");
      productInsert.run(
        productId,
        product.name,
        `Crispy ${product.name.toLowerCase()}`,
        product.price,
        categoryMap.get("sides"),
        product.image,
        product.fallback,
        Math.floor(Math.random() * 100) + 20, // Random stock between 20-120
      );
      totalProducts++;
    }

    // Insert drinks
    for (const product of foodData.drinks) {
      const productId = randomUUID().replace(/-/g, "");
      productInsert.run(
        productId,
        product.name,
        `Refreshing ${product.name.toLowerCase()}`,
        product.price,
        categoryMap.get("drinks"),
        product.image,
        product.fallback,
        Math.floor(Math.random() * 80) + 15, // Random stock between 15-95
      );
      totalProducts++;
    }

    console.log(
      `✅ Successfully seeded ${categories.length} categories and ${totalProducts} products!`,
    );
    console.log("🎉 Product seeding completed!");
  } catch (error) {
    console.error("❌ Error seeding products:", error);
  } finally {
    db.close();
  }
}

// Run the seeding if this file is executed directly
if (import.meta.main) {
  await seedProducts();
}

export { seedProducts };
