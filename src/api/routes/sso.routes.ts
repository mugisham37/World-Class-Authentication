import { Router } from 'express';
import { ssoController } from '../controllers';
import { authenticate } from '../middlewares/auth.middleware';
import { validate } from '../middlewares/input-validation.middleware';
import { ssoValidators } from '../validators/sso.validators';

/**
 * SSO routes
 * Handles Single Sign-On functionality including SAML 2.0
 */
const router = Router();

/**
 * @route GET /sso/metadata
 * @desc Get service provider metadata
 * @access Public
 */
router.get('/metadata', ssoController.getMetadata);

/**
 * @route GET /sso/login/:idpId
 * @desc Initiate SAML login
 * @access Public
 */
router.get(
  '/login/:idpId',
  validate(ssoValidators.initiateLogin, { source: 'params' }),
  ssoController.initiateLogin
);

/**
 * @route POST /sso/acs
 * @desc Process SAML assertion (ACS endpoint)
 * @access Public
 */
router.post('/acs', validate(ssoValidators.processAssertion), ssoController.processAssertion);

/**
 * @route GET /sso/logout
 * @desc Initiate SAML logout
 * @access Public
 */
router.get('/logout', ssoController.initiateLogout);

/**
 * @route POST /sso/slo
 * @desc Process SAML logout response
 * @access Public
 */
router.post('/slo', validate(ssoValidators.processLogout), ssoController.processLogout);

/**
 * @route GET /sso/identity-providers
 * @desc List identity providers
 * @access Private/Admin
 */
router.get('/identity-providers', authenticate, ssoController.listIdentityProviders);

/**
 * @route GET /sso/identity-providers/:id
 * @desc Get identity provider
 * @access Private/Admin
 */
router.get(
  '/identity-providers/:id',
  authenticate,
  validate(ssoValidators.getIdentityProvider, { source: 'params' }),
  ssoController.getIdentityProvider
);

/**
 * @route POST /sso/identity-providers
 * @desc Create identity provider
 * @access Private/Admin
 */
router.post(
  '/identity-providers',
  authenticate,
  validate(ssoValidators.createIdentityProvider),
  ssoController.createIdentityProvider
);

/**
 * @route PUT /sso/identity-providers/:id
 * @desc Update identity provider
 * @access Private/Admin
 */
router.put(
  '/identity-providers/:id',
  authenticate,
  validate(ssoValidators.updateIdentityProvider),
  ssoController.updateIdentityProvider
);

/**
 * @route DELETE /sso/identity-providers/:id
 * @desc Delete identity provider
 * @access Private/Admin
 */
router.delete(
  '/identity-providers/:id',
  authenticate,
  validate(ssoValidators.deleteIdentityProvider, { source: 'params' }),
  ssoController.deleteIdentityProvider
);

/**
 * @route GET /sso/sessions
 * @desc Get user's SSO sessions
 * @access Private
 */
router.get('/sessions', authenticate, ssoController.getUserSessions);

/**
 * @route DELETE /sso/sessions/:id
 * @desc Terminate SSO session
 * @access Private
 */
router.delete(
  '/sessions/:id',
  authenticate,
  validate(ssoValidators.terminateSession, { source: 'params' }),
  ssoController.terminateSession
);

export const ssoRoutes = router;
