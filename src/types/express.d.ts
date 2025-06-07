import { Session } from '../core/authentication/types';

declare global {
  namespace Express {
    interface Request {
      user?: {
        [key: string]: any;
        id: string;
        email: string;
        sessionId?: string;
      };
      deviceId?: string;
    }
  }
}

// This file is a module
export {};
