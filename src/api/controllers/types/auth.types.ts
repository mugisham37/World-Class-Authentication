/**
 * Authentication Types
 * Centralized type definitions for authentication system
 */

/**
 * Base interfaces without index signatures for better type safety
 */

export interface BaseUser {
  id: string;
  email: string;
  username: string;
  emailVerified: boolean;
  createdAt: Date;
  updatedAt: Date;
  firstName?: string;
  lastName?: string;
}

export interface BaseSession {
  id: string;
  userId: string;
  ipAddress: string;
  userAgent: string;
  deviceId: string;
  lastActiveAt: Date;
  createdAt: Date;
  expiresAt: Date;
}

export interface BaseAuthUser {
  id: string;
  email: string;
  sessionId: string;
  roles?: string[];
}

/**
 * Authenticated user with extended properties
 * Used in request objects and authentication flows
 */
export interface AuthUser extends BaseAuthUser {
  permissions?: string[];
}

/**
 * Service response interfaces
 */

export interface AuthenticationServiceResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  user: BaseUser;
  sessionId: string;
}

export interface TokenRefreshServiceResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface PasswordResetServiceResponse {
  token: string;
  userId: string;
}

export interface EmailVerificationServiceResponse {
  token: string;
  userId: string;
}

/**
 * Request/Response DTOs
 */

export interface RegisterRequestDto {
  email: string;
  password: string;
  username: string;
  firstName?: string;
  lastName?: string;
}

export interface LoginRequestDto {
  email: string;
  password: string;
}

export interface ChangePasswordRequestDto {
  currentPassword: string;
  newPassword: string;
}

export interface ResetPasswordRequestDto {
  token: string;
  password: string;
}

export interface UpdateUserProfileRequestDto {
  username?: string;
  firstName?: string;
  lastName?: string;
}

export interface VerifyEmailRequestDto {
  token: string;
}

export interface ForgotPasswordRequestDto {
  email: string;
}

/**
 * API Response DTOs
 */

export interface UserProfileResponseDto {
  id: string;
  email: string;
  username: string;
  emailVerified: boolean;
  createdAt: Date;
  updatedAt: Date;
  firstName?: string;
  lastName?: string;
}

export interface SessionResponseDto {
  id: string;
  ipAddress: string;
  userAgent: string;
  deviceId: string;
  lastActiveAt: Date;
  createdAt: Date;
  expiresAt: Date;
  current: boolean;
}

export interface LoginResponseDto {
  accessToken: string;
  expiresIn: number;
  user: UserProfileResponseDto;
  sessionId: string;
}

export interface TokenRefreshResponseDto {
  accessToken: string;
  expiresIn: number;
}

export interface RegisterResponseDto {
  userId: string;
  email: string;
  username: string;
  emailVerified: boolean;
  verificationToken?: string; // Only for development
}

/**
 * Type guards for runtime validation
 */

export function isBaseUser(obj: any): obj is BaseUser {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    typeof obj.id === 'string' &&
    typeof obj.email === 'string' &&
    typeof obj.username === 'string' &&
    typeof obj.emailVerified === 'boolean' &&
    obj.createdAt instanceof Date &&
    obj.updatedAt instanceof Date
  );
}

export function isBaseSession(obj: any): obj is BaseSession {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    typeof obj.id === 'string' &&
    typeof obj.userId === 'string' &&
    typeof obj.ipAddress === 'string' &&
    typeof obj.userAgent === 'string' &&
    typeof obj.deviceId === 'string' &&
    obj.lastActiveAt instanceof Date &&
    obj.createdAt instanceof Date &&
    obj.expiresAt instanceof Date
  );
}

export function isBaseAuthUser(obj: any): obj is BaseAuthUser {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    typeof obj.id === 'string' &&
    typeof obj.email === 'string' &&
    typeof obj.sessionId === 'string'
  );
}

export function isAuthUser(obj: any): obj is AuthUser {
  // First check if it's a BaseAuthUser
  if (!isBaseAuthUser(obj)) {
    return false;
  }

  // Then check if permissions property exists and is valid
  if ('permissions' in obj) {
    return (
      Array.isArray(obj.permissions) &&
      obj.permissions.every((permission: any) => typeof permission === 'string')
    );
  }

  // If permissions doesn't exist, it's still a valid AuthUser
  return true;
}

export function isAuthenticationServiceResponse(obj: any): obj is AuthenticationServiceResponse {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    typeof obj.accessToken === 'string' &&
    typeof obj.refreshToken === 'string' &&
    typeof obj.expiresIn === 'number' &&
    isBaseUser(obj.user) &&
    typeof obj.sessionId === 'string'
  );
}

export function isTokenRefreshServiceResponse(obj: any): obj is TokenRefreshServiceResponse {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    typeof obj.accessToken === 'string' &&
    typeof obj.refreshToken === 'string' &&
    typeof obj.expiresIn === 'number'
  );
}

export function isPasswordResetServiceResponse(obj: any): obj is PasswordResetServiceResponse {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    typeof obj.token === 'string' &&
    typeof obj.userId === 'string'
  );
}

/**
 * Utility functions for data transformation
 */

export function mapToUserProfileResponse(user: BaseUser): UserProfileResponseDto {
  return {
    id: user.id,
    email: user.email,
    username: user.username,
    emailVerified: user.emailVerified,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    firstName: user.firstName,
    lastName: user.lastName,
  };
}

export function mapToSessionResponse(
  session: BaseSession,
  currentSessionId?: string
): SessionResponseDto {
  return {
    id: session.id,
    ipAddress: session.ipAddress,
    userAgent: session.userAgent,
    deviceId: session.deviceId,
    lastActiveAt: session.lastActiveAt,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
    current: session.id === currentSessionId,
  };
}

export function mapToLoginResponse(authResult: AuthenticationServiceResponse): LoginResponseDto {
  return {
    accessToken: authResult.accessToken,
    expiresIn: authResult.expiresIn,
    user: mapToUserProfileResponse(authResult.user),
    sessionId: authResult.sessionId,
  };
}

/**
 * Validation helpers
 */

export function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

export function validatePassword(password: string): boolean {
  // At least 8 characters, 1 uppercase, 1 lowercase, 1 number
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
  return passwordRegex.test(password);
}

export function validateUsername(username: string): boolean {
  // 3-30 characters, alphanumeric and underscore only
  const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
  return usernameRegex.test(username);
}

/**
 * Error code constants
 */

export const AUTH_ERROR_CODES = {
  NOT_AUTHENTICATED: 'NOT_AUTHENTICATED',
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  EMAIL_ALREADY_EXISTS: 'EMAIL_ALREADY_EXISTS',
  USERNAME_ALREADY_EXISTS: 'USERNAME_ALREADY_EXISTS',
  USER_NOT_FOUND: 'USER_NOT_FOUND',
  SESSION_NOT_FOUND: 'SESSION_NOT_FOUND',
  INVALID_SESSION: 'INVALID_SESSION',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  INVALID_TOKEN: 'INVALID_TOKEN',
  EMAIL_NOT_VERIFIED: 'EMAIL_NOT_VERIFIED',
  PASSWORD_TOO_WEAK: 'PASSWORD_TOO_WEAK',
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
} as const;

export type AuthErrorCode = (typeof AUTH_ERROR_CODES)[keyof typeof AUTH_ERROR_CODES];

/**
 * Configuration interfaces
 */

export interface AuthConfig {
  jwt: {
    accessTokenSecret: string;
    refreshTokenSecret: string;
    accessTokenExpiresIn: string;
    refreshTokenExpiresIn: string;
  };
  session: {
    maxSessions: number;
    sessionTimeout: number;
  };
  password: {
    minLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumbers: boolean;
    requireSpecialChars: boolean;
  };
  email: {
    verificationRequired: boolean;
    verificationTokenExpiry: number;
  };
}

/**
 * Middleware interfaces
 */

export interface AuthMiddlewareOptions {
  required?: boolean;
  roles?: string[];
  permissions?: string[];
}

/**
 * Service interfaces for dependency injection
 */

export interface IAuthService {
  authenticateWithPassword(
    email: string,
    password: string,
    ipAddress: string,
    userAgent: string,
    deviceId: string
  ): Promise<AuthenticationServiceResponse>;

  refreshTokens(
    refreshToken: string,
    ipAddress: string,
    userAgent: string
  ): Promise<TokenRefreshServiceResponse>;

  logout(sessionId: string, userId: string, ipAddress: string, userAgent: string): Promise<void>;

  logoutAll(userId: string, ipAddress: string, userAgent: string): Promise<void>;
}

export interface IIdentityService {
  createUser(
    email: string,
    password: string,
    username: string,
    firstName?: string,
    lastName?: string
  ): Promise<BaseUser>;

  getUserById(userId: string): Promise<BaseUser | null>;

  updateUser(userId: string, updateData: UpdateUserProfileRequestDto): Promise<BaseUser>;

  changePassword(userId: string, currentPassword: string, newPassword: string): Promise<void>;

  deleteUser(userId: string): Promise<void>;
}

export interface ISessionService {
  getUserSessions(userId: string): Promise<BaseSession[]>;

  getSessionById(sessionId: string): Promise<BaseSession | null>;

  terminateSession(sessionId: string): Promise<void>;

  terminateAllUserSessions(userId: string): Promise<void>;

  createSession(
    userId: string,
    ipAddress: string,
    userAgent: string,
    deviceId: string
  ): Promise<BaseSession>;

  updateSessionActivity(sessionId: string): Promise<void>;
}

export interface IEmailVerificationService {
  createVerificationToken(userId: string): Promise<string>;

  verifyEmail(token: string): Promise<string>;

  resendVerificationEmail(userId: string): Promise<string>;

  isEmailVerified(userId: string): Promise<boolean>;
}

export interface IPasswordResetService {
  createResetToken(email: string): Promise<PasswordResetServiceResponse>;

  resetPassword(token: string, newPassword: string): Promise<string>;

  validateResetToken(token: string): Promise<boolean>;
}
