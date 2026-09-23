import {
  createJwtSecurity,
} from '../security/jwtSecurity.js';

export function createAuthMiddleware(config) {
  const jwtSecurity =
    createJwtSecurity(config);

  function authenticate(
    req,
    res,
    next,
  ) {
    // ----------------------------------------------
    // Authorization header
    // ----------------------------------------------

    const authorization =
      req.headers.authorization;

    if (
      typeof authorization !== 'string' ||
      !authorization.trim()
    ) {
      return res.status(401).json({
        success: false,
        code: 'AUTHENTICATION_REQUIRED',
        message:
          'Authentication required',
      });
    }

    // ----------------------------------------------
    // Bearer token
    //
    // Expected:
    // Authorization: Bearer <access-token>
    // ----------------------------------------------

    const parts =
      authorization.trim().split(/\s+/);

    if (
      parts.length !== 2 ||
      parts[0].toLowerCase() !==
        'bearer' ||
      !parts[1]
    ) {
      return res.status(401).json({
        success: false,
        code:
          'INVALID_AUTHORIZATION_HEADER',
        message:
          'Invalid authorization header',
      });
    }

    const token = parts[1];

    // ----------------------------------------------
    // Verify access token
    // ----------------------------------------------

    const verification =
      jwtSecurity.verifyAccessToken(
        token,
      );

    if (!verification.valid) {
      if (
        verification.reason ===
        'TOKEN_EXPIRED'
      ) {
        return res.status(401).json({
          success: false,
          code:
            'ACCESS_TOKEN_EXPIRED',
          message:
            'Access token has expired',
        });
      }

      return res.status(401).json({
        success: false,
        code:
          'INVALID_ACCESS_TOKEN',
        message:
          'Invalid access token',
      });
    }

    // ----------------------------------------------
    // Authenticated request context
    //
    // Controllers/services should use this trusted
    // context instead of accepting userId or
    // tenantId from the request body.
    // ----------------------------------------------

    req.auth = Object.freeze({
      userId:
        verification.userId,

      tenantId:
        verification.tenantId,
    });

    next();
  }

  return Object.freeze({
    authenticate,
  });
}