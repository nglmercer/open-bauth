// src/controllers/admin.controller.ts
import { Context } from "hono";
import { AuthService } from "../../src/index";

export class AdminController {
  constructor(private authService: AuthService) {}

  getAllUsers = async (c: Context) => {
    const { users, total } = await this.authService.getUsers();
    return c.json({
      success: true,
      data: { users, total },
    });
  };
}
