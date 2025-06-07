import type { Request, Response } from 'express';
import { BaseController } from './base.controller';
import { sendOkResponse, sendCreatedResponse } from '../responses';
import { AuthenticationError, BadRequestError, NotFoundError } from '../../utils/error-handling';
import { logger } from '../../infrastructure/logging/logger';
import { SAMLService } from '../../core/sso/saml.service';

// Extend Express Request to include session
declare module 'express-session' {
  interface SessionData {
    ssoSessionId?: string;
    userId?: string;
  }
}

// Import the SAML service
// In a real application with proper DI, this would be injected
const samlService = new SAMLService(
  // These dependencies would be properly injected in a real application
  null as any, // eventEmitter
  null as any // userService
);

/**
 * SSO controller
 * Handles Single Sign-On functionality including SAML 2.0
 */
export class SSOController extends BaseController {
  /**
   * Get service provider metadata
   * @route GET /sso/metadata
   */
  getMetadata = this.handleAsync(async (_req: Request, res: Response): Promise<void> => {
    try {
      // Get service provider metadata
      const metadata = samlService.getServiceProviderMetadata();

      // Set content type to XML
      res.setHeader('Content-Type', 'application/xml');

      // Return metadata
      res.status(200).send(metadata);
    } catch (error) {
      logger.error('Error getting service provider metadata', { error });
      throw error;
    }
  });

  /**
   * Initiate SAML login
   * @route GET /sso/login/:idpId
   */
  initiateLogin = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const { idpId } = req.params;
    const { RelayState } = req.query;

    try {
      // Generate SAML authentication request
      const samlRequest = await samlService.generateAuthnRequest(
        idpId || '',
        RelayState ? String(RelayState) : undefined
      );

      // Build redirect URL
      const redirectUrl = new URL(samlRequest.destination);
      redirectUrl.searchParams.append('SAMLRequest', samlRequest.encodedRequest);

      if (samlRequest.relayState) {
        redirectUrl.searchParams.append('RelayState', samlRequest.relayState);
      }

      // Redirect to identity provider
      res.redirect(redirectUrl.toString());
    } catch (error) {
      logger.error('Error initiating SAML login', { error, idpId });
      throw error;
    }
  });

  /**
   * Process SAML assertion (ACS endpoint)
   * @route POST /sso/acs
   */
  processAssertion = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const { SAMLResponse, RelayState } = req.body;

    if (!SAMLResponse) {
      throw new BadRequestError('SAML response is required', 'SAML_RESPONSE_REQUIRED');
    }

    try {
      // Process SAML response
      const samlUser = await samlService.processAssertionResponse(SAMLResponse);

      // Extract identity provider ID from RelayState or other means
      // In a real implementation, this would be extracted from the SAML response
      // or stored in the session when the request was generated
      const idpId = RelayState?.split(':')?.[0] || 'default-idp';

      // Provision or update user
      const user = await samlService.provisionUser(samlUser, idpId);

      // Create SSO session
      const ssoSession = await samlService.createSSOSession(user.id, samlUser, idpId);

      // Create application session
      // In a real implementation, this would create a session in your application
      // and set cookies or other session identifiers

      // For now, we'll just store the SSO session ID in the user's session
      if (req.session) {
        req.session.ssoSessionId = ssoSession.id;
        req.session.userId = user.id;
      }

      // Determine redirect URL
      let redirectUrl = '/';
      if (RelayState && RelayState.includes(':')) {
        // Extract redirect URL from RelayState
        redirectUrl = RelayState.split(':')?.[1] || '/';
      }

      // Redirect to application
      res.redirect(redirectUrl);
    } catch (error) {
      logger.error('Error processing SAML assertion', { error });
      res.redirect('/login?error=saml_error');
    }
  });

  /**
   * Initiate SAML logout
   * @route GET /sso/logout
   */
  initiateLogout = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Get SSO session ID from user's session
    const ssoSessionId = req.session?.ssoSessionId;

    if (!ssoSessionId) {
      // No SSO session, just redirect to login page
      return res.redirect('/login');
    }

    try {
      // Generate SAML logout request
      const logoutRequest = await samlService.generateLogoutRequest(ssoSessionId);

      if (!logoutRequest) {
        // No logout request generated, just terminate session locally
        delete req.session.ssoSessionId;
        delete req.session.userId;
        return res.redirect('/login');
      }

      // Build redirect URL
      const redirectUrl = new URL(logoutRequest.destination);
      redirectUrl.searchParams.append('SAMLRequest', logoutRequest.encodedRequest);

      // Redirect to identity provider
      res.redirect(redirectUrl.toString());
    } catch (error) {
      logger.error('Error initiating SAML logout', { error, ssoSessionId });

      // Terminate session locally on error
      delete req.session.ssoSessionId;
      delete req.session.userId;

      res.redirect('/login?error=logout_error');
    }
  });

  /**
   * Process SAML logout response
   * @route POST /sso/slo
   */
  processLogout = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const { SAMLResponse } = req.body;

    if (!SAMLResponse) {
      throw new BadRequestError('SAML response is required', 'SAML_RESPONSE_REQUIRED');
    }

    try {
      // Process SAML logout response
      await samlService.processLogoutResponse(SAMLResponse);

      // Terminate session locally
      delete req.session.ssoSessionId;
      delete req.session.userId;

      // Redirect to login page
      res.redirect('/login?logout=success');
    } catch (error) {
      logger.error('Error processing SAML logout response', { error });

      // Terminate session locally on error
      delete req.session.ssoSessionId;
      delete req.session.userId;

      res.redirect('/login?error=logout_error');
    }
  });

  /**
   * List identity providers
   * @route GET /sso/identity-providers
   */
  listIdentityProviders = this.handleAsync(async (_req: Request, res: Response): Promise<void> => {
    try {
      // In a real implementation, this would query the database
      // For now, we'll just return all identity providers from the service
      const identityProviders = Array.from((samlService as any).identityProviders.values()).map(
        (idp: any) => ({
          id: idp.id,
          name: idp.name,
          entityId: idp.entityId,
          isActive: idp.isActive,
        })
      );

      sendOkResponse(res, 'Identity providers retrieved successfully', identityProviders);
    } catch (error) {
      logger.error('Error listing identity providers', { error });
      throw error;
    }
  });

  /**
   * Get identity provider
   * @route GET /sso/identity-providers/:id
   */
  getIdentityProvider = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const { id } = req.params;

    try {
      // Get identity provider
      const idp = await samlService.findIdPById(id || '');

      if (!idp) {
        throw new NotFoundError('Identity provider not found');
      }

      // Remove sensitive information
      const sanitizedIdp = {
        ...idp,
        certificate: idp.certificate ? 'REDACTED' : null,
      };

      sendOkResponse(res, 'Identity provider retrieved successfully', sanitizedIdp);
    } catch (error) {
      logger.error('Error getting identity provider', { error, id });
      throw error;
    }
  });

  /**
   * Create identity provider
   * @route POST /sso/identity-providers
   */
  createIdentityProvider = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    try {
      // Register identity provider
      const idp = await samlService.registerIdP(req.body);

      // Remove sensitive information
      const sanitizedIdp = {
        ...idp,
        certificate: idp.certificate ? 'REDACTED' : null,
      };

      sendCreatedResponse(res, 'Identity provider created successfully', sanitizedIdp);
    } catch (error) {
      logger.error('Error creating identity provider', { error });
      throw error;
    }
  });

  /**
   * Update identity provider
   * @route PUT /sso/identity-providers/:id
   */
  updateIdentityProvider = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const { id } = req.params;

    try {
      // Update identity provider
      const idp = await samlService.updateIdP(id || '', req.body);

      // Remove sensitive information
      const sanitizedIdp = {
        ...idp,
        certificate: idp.certificate ? 'REDACTED' : null,
      };

      sendOkResponse(res, 'Identity provider updated successfully', sanitizedIdp);
    } catch (error) {
      logger.error('Error updating identity provider', { error, id });
      throw error;
    }
  });

  /**
   * Delete identity provider
   * @route DELETE /sso/identity-providers/:id
   */
  deleteIdentityProvider = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const { id } = req.params;

    try {
      // Delete identity provider
      await samlService.deleteIdP(id || '');

      sendOkResponse(res, 'Identity provider deleted successfully');
    } catch (error) {
      logger.error('Error deleting identity provider', { error, id });
      throw error;
    }
  });

  /**
   * Get user's SSO sessions
   * @route GET /sso/sessions
   */
  getUserSessions = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    try {
      // Get user's SSO sessions
      const sessions = await samlService.findSessionsByUserId(req.user.id);

      // Remove sensitive information
      const sanitizedSessions = sessions.map(session => ({
        id: session.id,
        idpId: session.idpId,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
        lastValidatedAt: session.lastValidatedAt,
      }));

      sendOkResponse(res, 'SSO sessions retrieved successfully', sanitizedSessions);
    } catch (error) {
      logger.error("Error getting user's SSO sessions", { error, userId: req.user.id });
      throw error;
    }
  });

  /**
   * Terminate SSO session
   * @route DELETE /sso/sessions/:id
   */
  terminateSession = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const { id } = req.params;

    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    try {
      // Get session
      const session = await samlService.findSessionById(id || '');

      // Check if session exists and belongs to the user
      if (!session || session.userId !== req.user.id) {
        throw new NotFoundError('SSO session not found');
      }

      // Terminate session
      await samlService.terminateSession(id || '');

      sendOkResponse(res, 'SSO session terminated successfully');
    } catch (error) {
      logger.error('Error terminating SSO session', { error, id, userId: req.user?.id });
      throw error;
    }
  });
}

// Create instance
export const ssoController = new SSOController();
