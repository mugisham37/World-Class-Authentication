import type { Request, Response } from 'express';
import { BaseController } from './base.controller';
import { sendCreatedResponse } from '../responses';
import {
  AuthenticationError,
  BadRequestError,
  NotFoundError,
  UnauthorizedError,
} from '../../utils/error-handling';
import { logger } from '../../infrastructure/logging/logger';
import { OAuthService } from '../../core/oauth/oauth.service';
import { AuthUser, isAuthUser } from './types/auth.types';

// Import the OAuth service
// In a real application with proper DI, this would be injected
const oauthService = new OAuthService(
  // These dependencies would be properly injected in a real application
  // For now, we'll use the service methods but handle any errors that might occur
  // due to missing dependencies
  null as any, // clientRepository
  null as any, // tokenRepository
  null as any, // authorizationCodeRepository
  null as any, // userRepository
  null as any // eventEmitter
);

/**
 * OAuth 2.0 controller
 * Handles OAuth 2.0 and OpenID Connect endpoints
 */
export class OAuthController extends BaseController {
  /**
   * Authorize endpoint
   * @route GET /oauth/authorize
   */
  authorize = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const {
      response_type,
      client_id,
      redirect_uri,
      scope,
      state,
      code_challenge,
      code_challenge_method,
    } = req.query as Record<string, string>;

    // Validate required parameters
    if (!response_type) {
      throw new BadRequestError('Response type is required', 'RESPONSE_TYPE_REQUIRED');
    }

    if (!client_id) {
      throw new BadRequestError('Client ID is required', 'CLIENT_ID_REQUIRED');
    }

    if (!redirect_uri) {
      throw new BadRequestError('Redirect URI is required', 'REDIRECT_URI_REQUIRED');
    }

    // Check if user is authenticated
    if (!req.user || !isAuthUser(req.user)) {
      // Store authorization request in session and redirect to login
      // In a real implementation, we would store the request parameters in the session
      // and redirect to the login page

      // For now, we'll just return an error
      throw new AuthenticationError('User authentication required', 'AUTHENTICATION_REQUIRED');
    }

    try {
      // Validate client and redirect URI
      await oauthService.validateClient(client_id);

      // Generate authorization code
      const code = await oauthService.generateAuthorizationCode(
        client_id,
        req.user.id,
        redirect_uri,
        scope || '',
        code_challenge,
        code_challenge_method
      );

      // Build redirect URL
      const redirectUrl = new URL(redirect_uri);
      redirectUrl.searchParams.append('code', code);

      if (state) {
        redirectUrl.searchParams.append('state', state);
      }

      // Redirect to client with authorization code
      res.redirect(redirectUrl.toString());
    } catch (error) {
      logger.error('Error in authorize endpoint', {
        error,
        client_id,
        redirect_uri,
        userId: req.user && isAuthUser(req.user) ? req.user.id : undefined,
      });

      // Handle error by redirecting to client with error
      if (redirect_uri) {
        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.append('error', 'server_error');
        redirectUrl.searchParams.append(
          'error_description',
          'An error occurred during authorization'
        );

        if (state) {
          redirectUrl.searchParams.append('state', state);
        }

        res.redirect(redirectUrl.toString());
      } else {
        // If no redirect URI, return error response
        throw new BadRequestError('Invalid authorization request', 'INVALID_REQUEST');
      }
    }
  });

  /**
   * Token endpoint
   * @route POST /oauth/token
   */
  token = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const {
      grant_type,
      code,
      redirect_uri,
      client_id,
      client_secret,
      refresh_token,
      scope,
      code_verifier,
    } = req.body;

    // Validate grant type
    if (!grant_type) {
      throw new BadRequestError('Grant type is required', 'GRANT_TYPE_REQUIRED');
    }

    try {
      let tokenResponse;

      // Handle different grant types
      switch (grant_type) {
        case 'authorization_code':
          // Validate required parameters
          if (!code) {
            throw new BadRequestError('Authorization code is required', 'CODE_REQUIRED');
          }

          if (!redirect_uri) {
            throw new BadRequestError('Redirect URI is required', 'REDIRECT_URI_REQUIRED');
          }

          if (!client_id) {
            throw new BadRequestError('Client ID is required', 'CLIENT_ID_REQUIRED');
          }

          // Exchange authorization code for tokens
          tokenResponse = await oauthService.exchangeAuthorizationCode(
            code,
            client_id,
            client_secret,
            redirect_uri,
            code_verifier
          );
          break;

        case 'refresh_token':
          // Validate required parameters
          if (!refresh_token) {
            throw new BadRequestError('Refresh token is required', 'REFRESH_TOKEN_REQUIRED');
          }

          if (!client_id) {
            throw new BadRequestError('Client ID is required', 'CLIENT_ID_REQUIRED');
          }

          // Refresh access token
          tokenResponse = await oauthService.refreshToken(
            refresh_token,
            client_id,
            client_secret,
            scope
          );
          break;

        case 'client_credentials':
          // Validate required parameters
          if (!client_id) {
            throw new BadRequestError('Client ID is required', 'CLIENT_ID_REQUIRED');
          }

          if (!client_secret) {
            throw new BadRequestError('Client secret is required', 'CLIENT_SECRET_REQUIRED');
          }

          // Generate tokens using client credentials
          tokenResponse = await oauthService.clientCredentialsGrant(
            client_id,
            client_secret,
            scope || ''
          );
          break;

        default:
          throw new BadRequestError(
            `Unsupported grant type: ${grant_type}`,
            'UNSUPPORTED_GRANT_TYPE'
          );
      }

      // Return token response
      res.status(200).json(tokenResponse);
    } catch (error) {
      logger.error('Error in token endpoint', {
        error,
        grant_type,
        client_id,
      });

      // For OAuth errors, we need to return a specific format
      if (error instanceof BadRequestError || error instanceof UnauthorizedError) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: error.message,
        });
      } else if (error instanceof NotFoundError) {
        res.status(400).json({
          error: 'invalid_grant',
          error_description: 'The provided authorization grant is invalid',
        });
      } else {
        res.status(500).json({
          error: 'server_error',
          error_description: 'An error occurred processing the request',
        });
      }
    }
  });

  /**
   * Revoke token endpoint
   * @route POST /oauth/revoke
   */
  revokeToken = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const { token, token_type_hint, client_id, client_secret } = req.body;

    // Validate required parameters
    if (!token) {
      throw new BadRequestError('Token is required', 'TOKEN_REQUIRED');
    }

    if (!client_id) {
      throw new BadRequestError('Client ID is required', 'CLIENT_ID_REQUIRED');
    }

    try {
      // Revoke token
      await oauthService.revokeToken(token, token_type_hint, client_id, client_secret);

      // Return success response (empty response with 200 status)
      res.status(200).json({});
    } catch (error) {
      logger.error('Error in revoke token endpoint', {
        error,
        client_id,
      });

      // For OAuth errors, we need to return a specific format
      if (error instanceof BadRequestError || error instanceof UnauthorizedError) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: error.message,
        });
      } else {
        res.status(500).json({
          error: 'server_error',
          error_description: 'An error occurred processing the request',
        });
      }
    }
  });

  /**
   * Introspect token endpoint
   * @route POST /oauth/introspect
   */
  introspectToken = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const { token, token_type_hint, client_id, client_secret } = req.body;

    // Validate required parameters
    if (!token) {
      throw new BadRequestError('Token is required', 'TOKEN_REQUIRED');
    }

    if (!client_id) {
      throw new BadRequestError('Client ID is required', 'CLIENT_ID_REQUIRED');
    }

    try {
      // Introspect token
      const introspectionResult = await oauthService.introspectToken(
        token,
        token_type_hint,
        client_id,
        client_secret
      );

      // Return introspection result
      res.status(200).json(introspectionResult);
    } catch (error) {
      logger.error('Error in introspect token endpoint', {
        error,
        client_id,
      });

      // For OAuth errors, we need to return a specific format
      if (error instanceof BadRequestError || error instanceof UnauthorizedError) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: error.message,
        });
      } else {
        res.status(500).json({
          error: 'server_error',
          error_description: 'An error occurred processing the request',
        });
      }
    }
  });

  /**
   * UserInfo endpoint (OpenID Connect)
   * @route GET /oauth/userinfo
   */
  userInfo = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Get access token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedError('Bearer token is required', 'BEARER_TOKEN_REQUIRED');
    }

    const accessToken = authHeader.substring(7);

    try {
      // Get user info
      const userInfo = await oauthService.getUserInfo(accessToken);

      // Return user info
      res.status(200).json(userInfo);
    } catch (error) {
      logger.error('Error in userinfo endpoint', {
        error,
      });

      // For OAuth errors, we need to return a specific format
      if (error instanceof BadRequestError || error instanceof UnauthorizedError) {
        res.status(401).json({
          error: 'invalid_token',
          error_description: error.message,
        });
      } else if (error instanceof NotFoundError) {
        res.status(401).json({
          error: 'invalid_token',
          error_description: 'The access token is invalid',
        });
      } else {
        res.status(500).json({
          error: 'server_error',
          error_description: 'An error occurred processing the request',
        });
      }
    }
  });

  /**
   * Register client endpoint (Dynamic Client Registration)
   * @route POST /oauth/register
   */
  registerClient = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Get initial access token from Authorization header
    const authHeader = req.headers.authorization;
    let initialAccessToken: string | undefined;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      initialAccessToken = authHeader.substring(7);
    }

    try {
      // Register client
      const clientInfo = await oauthService.registerClient(req.body, initialAccessToken);

      // Return client information
      sendCreatedResponse(res, 'Client registered successfully', clientInfo);
    } catch (error) {
      logger.error('Error in register client endpoint', {
        error,
      });

      // For OAuth errors, we need to return a specific format
      if (error instanceof BadRequestError) {
        res.status(400).json({
          error: 'invalid_client_metadata',
          error_description: error.message,
        });
      } else if (error instanceof UnauthorizedError) {
        res.status(401).json({
          error: 'invalid_token',
          error_description: error.message,
        });
      } else {
        res.status(500).json({
          error: 'server_error',
          error_description: 'An error occurred processing the request',
        });
      }
    }
  });
}

// Create instance
export const oauthController = new OAuthController();
