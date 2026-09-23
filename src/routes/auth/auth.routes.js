import { Router } from 'express';

import {
  createAuthController,
  notImplemented,
} from '../../controllers/auth/auth.controller.js';

import {
  createAuthMiddleware,
} from '../../middleware/auth.middleware.js';

export function createAuthRoutes(config) {
  const router = Router();

  const authController =
    createAuthController(config);

  const authMiddleware =
    createAuthMiddleware(config);

  // --------------------------------------------------
  // Primary authentication
  // --------------------------------------------------

  router.post(
    '/login',
    authController.login,
  );

  // --------------------------------------------------
  // Two-factor authentication
  // --------------------------------------------------

  router.post(
    '/2fa/verify',
    authController.verifyTwoFactor,
  );

  router.post(
    '/2fa/resend',
    authController.resendTwoFactor,
  );

  // --------------------------------------------------
  // Refresh authenticated session
  // --------------------------------------------------

  router.post(
    '/refresh',
    authController.refreshSession,
  );

  // --------------------------------------------------
  // Password recovery
  // --------------------------------------------------

  router.post(
    '/forgot-password',
    notImplemented,
  );

  // --------------------------------------------------
  // Logout
  //
  // Proper session/refresh-token logout will be
  // implemented in Step 11.8.
  // --------------------------------------------------

  router.post(
    '/logout',
    authController.logout,
  );

  // --------------------------------------------------
  // Current authenticated user
  // --------------------------------------------------

  router.get(
    '/me',
    authMiddleware.authenticate,
    authController.getCurrentUser,
  );

  return router;
}