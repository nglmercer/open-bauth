// src/controllers/auth.controller.ts
import { Context } from 'hono';
import { AuthService } from '../../dist/index';
import { ApiError } from '../api.types';
import { AuthErrorType } from '../../dist/index';

export class AuthController {
  constructor(private authService: AuthService) {}

  // Bind `this` to ensure `authService` is available
  register = async (c: Context) => {
    const body = await c.req.json();
    console.log('AuthController.register body:', body);
    const result = await this.authService.register(body);
    console.log('AuthController.register result:', result);

    if (!result.success) {
      // Devolver respuesta JSON directa en lugar de lanzar excepción
      return c.json({
        success: false,
        error: {
          message: result.error!.message,
          type: result.error!.type,
          timestamp: new Date().toISOString(),
        },
      }, 400); // Siempre devolver 400 para errores de registro
    }
    
    // Generate refresh token
    const jwtService = (this.authService as any).jwtService;
    const refreshToken = await jwtService.generateRefreshToken(result.user?.id || '');
    
    return c.json({
        success: true,
        data: {
          user: result.user,
          token: result.token,
          refreshToken: refreshToken
        }
    }, 200); // Cambiar a 200 como esperan los tests
  };

  login = async (c: Context) => {
    const body = await c.req.json();
    const result = await this.authService.login(body);

    if (!result.success) {
      // Devolver respuesta JSON directa en lugar de lanzar excepción
      return c.json({
        success: false,
        error: {
          message: result.error!.message,
          type: result.error!.type,
          timestamp: new Date().toISOString(),
        },
      }, 400); // Todos los errores de login deben devolver 400
    }
    
    // Generate refresh token
    const jwtService = (this.authService as any).jwtService;
    const refreshToken = await jwtService.generateRefreshToken(result.user?.id || '');
    
    return c.json({
        success: true,
        data: {
          user: result.user,
          token: result.token,
          refreshToken: refreshToken
        }
    });
  };

  getProfile = (c: Context) => {
    const auth = c.get('auth'); // From middleware
    return c.json({
      message: "This is your private profile data.",
      user: auth.user,
      roles: auth.roles,
      permissions: auth.permissions,
    });
  };
  refreshToken = async (c: Context) => {
    try {
      const body = await c.req.json();
      const { refreshToken } = body;

      if (!refreshToken) {
        return c.json({
          success: false,
          error: {
            message: 'Refresh token is required',
            type: AuthErrorType.INVALID_CREDENTIALS,
            timestamp: new Date().toISOString(),
          },
        }, 400);
      }

      // Get JWT service from auth service (we need to access it)
      const jwtService = (this.authService as any).jwtService;
      
      // Verify refresh token and get user ID
      const userId = await jwtService.verifyRefreshToken(refreshToken);
      
      // Get user data with roles
      const user = await this.authService.findUserById(String(userId), { includeRoles: true });
      if (!user || !user.is_active) {
        return c.json({
          success: false,
          error: {
            message: 'User not found or inactive',
            type: AuthErrorType.USER_NOT_FOUND,
            timestamp: new Date().toISOString(),
          },
        }, 401);
      }

      // Generate new access token and refresh token
      const newAccessToken = await jwtService.generateToken(user);
      const newRefreshToken = await jwtService.generateRefreshToken(user.id || '');

      return c.json({
        success: true,
        data: {
          user,
          token: newAccessToken,
          refreshToken: newRefreshToken
        }
      });

    } catch (error: any) {
      console.log("error refreshToken", error)
      // Devolver respuesta JSON directa en lugar de lanzar excepción
      return c.json({
        success: false,
        error: {
          message: error.message || 'Internal server error during token refresh',
          type: AuthErrorType.TOKEN_ERROR,
          timestamp: new Date().toISOString(),
        },
      }, 500);
    }
  };
}