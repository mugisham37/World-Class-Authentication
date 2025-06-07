import { Router } from 'express';
import { oauthController } from '../controllers';
import { validate } from '../middlewares/input-validation.middleware';
import { oauthValidators } from '../validators/oauth.validators';

/**
 * OAuth routes
 * Handles OAuth 2.0 and OpenID Connect endpoints
 */
const router = Router();

/**
 * @route GET /oauth/authorize
 * @desc Authorize endpoint
 * @access Public
 */
router.get(
  '/authorize',
  validate(oauthValidators.authorize, { source: 'query' }),
  oauthController.authorize
);

/**
 * @route POST /oauth/token
 * @desc Token endpoint
 * @access Public
 */
router.post('/token', validate(oauthValidators.token), oauthController.token);

/**
 * @route POST /oauth/revoke
 * @desc Revoke token endpoint
 * @access Public
 */
router.post('/revoke', validate(oauthValidators.revokeToken), oauthController.revokeToken);

/**
 * @route POST /oauth/introspect
 * @desc Introspect token endpoint
 * @access Public
 */
router.post(
  '/introspect',
  validate(oauthValidators.introspectToken),
  oauthController.introspectToken
);

/**
 * @route GET /oauth/userinfo
 * @desc UserInfo endpoint (OpenID Connect)
 * @access Private (via token)
 */
router.get('/userinfo', oauthController.userInfo);

/**
 * @route POST /oauth/register
 * @desc Register client endpoint (Dynamic Client Registration)
 * @access Public/Protected
 */
router.post('/register', validate(oauthValidators.registerClient), oauthController.registerClient);

export const oauthRoutes = router;
