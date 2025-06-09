import { AuthUser } from '../api/controllers/types/auth.types';

declare global {
  namespace Express {
    // Extend the User interface to match AuthUser
    interface User extends AuthUser {}

    interface Request {
      user?: AuthUser;
      deviceId?: string;
    }
  }
}

// This file is a module
export {};
