import type { Request, Response, NextFunction } from 'express';
import { env } from '../../config/environment';
import { logger } from '../../infrastructure/logging/logger';
import { getCurrentCorrelationId } from './correlation-id.middleware';
import crypto from 'crypto';

/**
 * Security headers options
 */
interface SecurityHeadersOptions {
  // Content Security Policy
  contentSecurityPolicy: boolean;
  // X-Content-Type-Options
  contentTypeOptions: boolean;
  // X-Frame-Options
  frameOptions: boolean;
  // X-XSS-Protection
  xssProtection: boolean;
  // Referrer-Policy
  referrerPolicy: boolean;
  // Permissions-Policy
  permissionsPolicy: boolean;
  // Strict-Transport-Security
  strictTransportSecurity: boolean;
  // Cache-Control
  cacheControl: boolean;
  // Cross-Origin-Embedder-Policy
  crossOriginEmbedderPolicy: boolean;
  // Cross-Origin-Opener-Policy
  crossOriginOpenerPolicy: boolean;
  // Cross-Origin-Resource-Policy
  crossOriginResourcePolicy: boolean;
  // Generate CSP nonce
  generateNonce: boolean;
}

/**
 * Default security headers options
 */
const defaultOptions: SecurityHeadersOptions = {
  contentSecurityPolicy: true,
  contentTypeOptions: true,
  frameOptions: true,
  xssProtection: true,
  referrerPolicy: true,
  permissionsPolicy: true,
  strictTransportSecurity: env.isProduction(),
  cacheControl: true,
  crossOriginEmbedderPolicy: env.isProduction(),
  crossOriginOpenerPolicy: env.isProduction(),
  crossOriginResourcePolicy: env.isProduction(),
  generateNonce: true,
};

/**
 * Create security headers middleware with custom options
 * @param options Security headers options
 * @returns Security headers middleware
 */
export function createSecurityHeadersMiddleware(options: Partial<SecurityHeadersOptions> = {}) {
  // Merge options with defaults
  const mergedOptions: SecurityHeadersOptions = { ...defaultOptions, ...options };

  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const correlationId =
        getCurrentCorrelationId() || (req.headers['x-correlation-id'] as string) || 'unknown';

      // Generate CSP nonce if enabled
      let nonce: string | undefined;
      if (mergedOptions.generateNonce) {
        nonce = crypto.randomBytes(16).toString('base64');
        // Store nonce in request for use in templates
        (req as any).cspNonce = nonce;
      }

      // Content Security Policy
      if (mergedOptions.contentSecurityPolicy) {
        const cspDirectives = [
          "default-src 'self'",
          "script-src 'self'" + (nonce ? ` 'nonce-${nonce}'` : ''),
          "style-src 'self'" + (nonce ? ` 'nonce-${nonce}'` : ''),
          "img-src 'self' data:",
          "font-src 'self'",
          "connect-src 'self'",
          "frame-src 'none'",
          "object-src 'none'",
          "base-uri 'self'",
          "form-action 'self'",
        ];

        res.setHeader('Content-Security-Policy', cspDirectives.join('; '));
      }

      // X-Content-Type-Options
      if (mergedOptions.contentTypeOptions) {
        res.setHeader('X-Content-Type-Options', 'nosniff');
      }

      // X-Frame-Options
      if (mergedOptions.frameOptions) {
        res.setHeader('X-Frame-Options', 'DENY');
      }

      // X-XSS-Protection
      if (mergedOptions.xssProtection) {
        res.setHeader('X-XSS-Protection', '1; mode=block');
      }

      // Referrer-Policy
      if (mergedOptions.referrerPolicy) {
        res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
      }

      // Permissions-Policy
      if (mergedOptions.permissionsPolicy) {
        res.setHeader(
          'Permissions-Policy',
          'camera=(), microphone=(), geolocation=(), interest-cohort=(), payment=()'
        );
      }

      // Strict-Transport-Security
      if (mergedOptions.strictTransportSecurity && env.isProduction()) {
        res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
      }

      // Cache-Control
      if (mergedOptions.cacheControl) {
        // Default to no-store for API routes
        if (req.path.startsWith('/api/')) {
          res.setHeader('Cache-Control', 'no-store, max-age=0');
        } else {
          // For static assets, allow caching but require revalidation
          res.setHeader('Cache-Control', 'no-cache, must-revalidate');
        }
      }

      // Cross-Origin-Embedder-Policy
      if (mergedOptions.crossOriginEmbedderPolicy && env.isProduction()) {
        res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
      }

      // Cross-Origin-Opener-Policy
      if (mergedOptions.crossOriginOpenerPolicy && env.isProduction()) {
        res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
      }

      // Cross-Origin-Resource-Policy
      if (mergedOptions.crossOriginResourcePolicy && env.isProduction()) {
        res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
      }

      // Log headers in debug mode
      logger.debug(`[${correlationId}] Security headers applied`, {
        path: req.path,
        method: req.method,
        correlationId,
      });

      next();
    } catch (error) {
      logger.error('Security headers middleware error', {
        error,
        correlationId: getCurrentCorrelationId(),
      });
      // Continue without security headers on error
      next();
    }
  };
}

/**
 * Default security headers middleware
 */
export const securityHeaders = createSecurityHeadersMiddleware();

/**
 * API security headers middleware
 * Stricter security headers for API routes
 */
export const apiSecurityHeaders = createSecurityHeadersMiddleware({
  contentSecurityPolicy: true,
  contentTypeOptions: true,
  frameOptions: true,
  xssProtection: true,
  referrerPolicy: true,
  permissionsPolicy: true,
  strictTransportSecurity: true,
  cacheControl: true,
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: true,
  generateNonce: false,
});

/**
 * Static assets security headers middleware
 * Less strict security headers for static assets
 */
export const staticSecurityHeaders = createSecurityHeadersMiddleware({
  contentSecurityPolicy: false,
  contentTypeOptions: true,
  frameOptions: false,
  xssProtection: false,
  referrerPolicy: true,
  permissionsPolicy: false,
  strictTransportSecurity: env.isProduction(),
  cacheControl: true,
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: false,
  crossOriginResourcePolicy: false,
  generateNonce: false,
});
