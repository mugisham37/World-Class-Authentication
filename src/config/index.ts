/**
 * Configuration System
 *
 * This module exports a unified configuration system that provides strongly-typed
 * access to all application configuration settings. The configuration is loaded from
 * environment variables and validated using Zod schemas.
 *
 * Features:
 * - Type-safe configuration with Zod validation
 * - Environment-specific configuration (.env, .env.development, .env.production, etc.)
 * - Default values for all configuration options
 * - Comprehensive validation with helpful error messages
 * - Modular configuration organized by domain
 */

// Export environment utilities
export { env } from './environment';

// Helper functions for environment detection
export const isDevelopment = (): boolean => env.isDevelopment();
export const isProduction = (): boolean => env.isProduction();
export const isTest = (): boolean => env.isTest();

// Export all configuration modules
export { appConfig } from './app-config';
export { auditConfig } from './audit-config';
export { complianceConfig } from './compliance-config';
export { dbConfig } from './database-config';
export { mfaConfig } from './mfa-config';
export { oauthConfig } from './oauth-config';
export { performanceConfig } from './performance-config';
export { quantumConfig } from './quantum-config';
export { recoveryConfig } from './recovery-config';
export { riskConfig } from './risk-config';
export { samlConfig } from './saml-config';
export { securityConfig } from './security-config';

// Export configuration types
export type { AppConfig } from './app-config';
export type { AuditConfig } from './audit-config';
export type { ComplianceConfig } from './compliance-config';
export type { DatabaseConfig } from './database-config';
export type { Environment } from './environment';
export type { MfaConfig } from './mfa-config';
export type { OAuthConfig } from './oauth-config';
export type { PerformanceConfig } from './performance-config';
export type { QuantumConfig } from './quantum-config';
export type { RecoveryConfig } from './recovery-config';
export type { RiskConfig } from './risk-config';
export type { SamlConfig } from './saml-config';
export type { SecurityConfig } from './security-config';
