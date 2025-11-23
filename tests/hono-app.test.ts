import {
  test,
  expect,
  describe,
  beforeAll,
  afterAll,
  beforeEach,
  afterEach,
} from "bun:test";
import app, { dbInitializer, db } from "../examples/hono";

import { testUtils } from "./setup";

// Función para generar emails únicos
function generateUniqueEmail(base: string): string {
  return `${base}_${Date.now()}@example.com`;
}

// Resetear la base de datos antes de cada test
beforeEach(async () => {
  await dbInitializer.reset();
  await dbInitializer.seedDefaults();
});

describe("Public Routes", () => {
  test("GET / returns welcome message for guest", async () => {
    const res = await app.request("/auth");
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.message).toBe("Welcome, guest! Please log in.");
  });
});
describe("Registration", () => {
  test("allows basic user registration", async () => {
    const newUser = {
      first_name: "Test",
      last_name: "User",
      email: generateUniqueEmail("test"),
      password: "password123",
    };
    const res = await app.request("/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(newUser),
    });
    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.data.user).toBeDefined();
    expect(data.data.token).toBeDefined();
    expect(data.data.refreshToken).toBeDefined();
  });

  test("allows registration with role", async () => {
    const newUser = {
      first_name: "Mod",
      last_name: "User",
      email: generateUniqueEmail("mod"),
      password: "modpassword",
      role_name: "moderator",
      permission_names: ["edit:content"],
    };
    const res = await app.request("/auth/register-with-role", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(newUser),
    });
    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.message).toBe("User registered successfully");
  });

  test("prevents duplicate email registration", async () => {
    const duplicateEmail = generateUniqueEmail("duplicate");
    // First registration
    await app.request("/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        first_name: "Test",
        last_name: "User",
        email: duplicateEmail,
        password: "password123",
      }),
    });
    // Second attempt
    const res = await app.request("/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        first_name: "Test2",
        last_name: "User2",
        email: duplicateEmail,
        password: "password456",
      }),
    });
    expect(res.status).toBe(409);
    const data = await res.json();
    expect(data.success).toBe(false);
    expect(data.error).toMatchObject({
      type: "USER_ALREADY_EXISTS",
      message: "A user with this email already exists",
    });
  });
});
describe("Login", () => {
  test("allows successful login", async () => {
    // Register user first
    const loginEmail = generateUniqueEmail("login");
    await app.request("/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        first_name: "Test",
        last_name: "User",
        email: loginEmail,
        password: "password123",
      }),
    });
    const credentials = { email: loginEmail, password: "password123" };
    const res = await app.request("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credentials),
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.data.token).toBeDefined();
    expect(data.data.user).toBeDefined();
    expect(data.data.refreshToken).toBeDefined();
  });

  test("rejects invalid credentials", async () => {
    // Register user
    const invalidEmail = generateUniqueEmail("invalid");
    await app.request("/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        first_name: "Test",
        last_name: "User",
        email: invalidEmail,
        password: "password123",
      }),
    });
    const credentials = { email: invalidEmail, password: "wrongpassword" };
    const res = await app.request("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credentials),
    });
    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.success).toBe(false);
    expect(data.error).toMatchObject({
      type: "INVALID_CREDENTIALS",
      message: "Invalid credentials",
    });
  });

  test("rejects login for inactive user", async () => {
    // Register inactive user
    const inactiveEmail = generateUniqueEmail("inactive");
    await app.request("/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        first_name: "Inactive",
        last_name: "User",
        email: inactiveEmail,
        password: "password123",
        is_active: false,
      }),
    });
    const credentials = { email: inactiveEmail, password: "password123" };
    const res = await app.request("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credentials),
    });
    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.success).toBe(false);
    expect(data.error).toMatchObject({
      type: "ACCOUNT_INACTIVE",
      message: "User account is deactivated",
    });
  });
});
describe("Protected Routes", () => {
  test("allows authenticated user to access profile", async () => {
    // Register and login
    const profileEmail = generateUniqueEmail("profile");
    await app.request("/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        first_name: "Test",
        last_name: "User",
        email: profileEmail,
        password: "password123",
      }),
    });
    const loginRes = await app.request("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: profileEmail, password: "password123" }),
    });
    const {
      data: { token },
    } = await loginRes.json();
    const res = await app.request("/api/profile", {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.message).toBe("This is your private profile data.");
    expect(data.user.email).toBe(profileEmail);
  });

  test("rejects unauthorized profile access", async () => {
    const res = await app.request("/api/profile");
    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.error).toBe("Authorization header is missing");
  });

  test("allows moderator to access mod content", async () => {
    // Register moderator
    const mod2Email = generateUniqueEmail("mod2");
    await app.request("/auth/register-with-role", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        first_name: "Mod",
        last_name: "User",
        email: mod2Email,
        password: "modpass",
        role_name: "moderator",
        permission_names: ["edit:content"],
      }),
    });
    const loginRes = await app.request("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: mod2Email, password: "modpass" }),
    });
    const {
      data: { token },
    } = await loginRes.json();
    const res = await app.request("/api/mod/content", {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.message).toBe("Here is the content you can moderate.");
  });

  test("allows admin to access user list", async () => {
    // Register admin
    const adminEmail = generateUniqueEmail("admin");
    await app.request("/auth/register-with-role", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        first_name: "Admin",
        last_name: "User",
        email: adminEmail,
        password: "adminpass",
        role_name: "admin",
        permission_names: ["manage:users"],
      }),
    });
    const loginRes = await app.request("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: adminEmail, password: "adminpass" }),
    });
    const {
      data: { token },
    } = await loginRes.json();
    const res = await app.request("/api/admin/users", {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.users).toBeDefined();
  });

  test("rejects non-moderator from mod content", async () => {
    // Register regular user
    const regularEmail = generateUniqueEmail("regular");
    await app.request("/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        first_name: "Regular",
        last_name: "User",
        email: regularEmail,
        password: "regpass",
      }),
    });
    const loginRes = await app.request("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: regularEmail, password: "regpass" }),
    });
    const {
      data: { token },
    } = await loginRes.json();
    const res = await app.request("/api/mod/content", {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(403);
    const data = await res.json();
    expect(data.error).toBe("Access denied. Required role not found.");
  });
});
