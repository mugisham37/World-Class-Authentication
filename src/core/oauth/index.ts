/**
 * OAuth Core Module
 *
 * This module provides OAuth 2.0 and OpenID Connect functionality for the authentication system.
 * It includes configuration, token management, and OAuth flow implementations.
 */

// Export configuration modules
export * from './oauth.config';
export * from './token.config';

// Export types
export type { OAuthConfig } from './oauth.config';
export type { TokenConfig } from './token.config';
