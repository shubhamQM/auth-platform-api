import jwt from 'jsonwebtoken';

export function createJwtSecurity(config) {
  const accessTokenConfig =
    config?.authentication?.accessToken;

  if (!accessTokenConfig) {
    throw new TypeError(
      'authentication.accessToken configuration is required',
    );
  }

  const {
    secret,
    algorithm,
    expiresInSeconds,
    issuer,
    audience,
  } = accessTokenConfig;

  // --------------------------------------------------
  // Configuration validation
  // --------------------------------------------------

  if (
    typeof secret !== 'string' ||
    !secret.trim()
  ) {
    throw new TypeError(
      'Access token signing secret is required',
    );
  }

  if (algorithm !== 'HS256') {
    throw new TypeError(
      'Access token algorithm must be HS256',
    );
  }

  if (
    !Number.isInteger(expiresInSeconds) ||
    expiresInSeconds < 60
  ) {
    throw new TypeError(
      'Access token expiry must be an integer of at least 60 seconds',
    );
  }

  if (
    typeof issuer !== 'string' ||
    !issuer.trim()
  ) {
    throw new TypeError(
      'Access token issuer is required',
    );
  }

  if (
    typeof audience !== 'string' ||
    !audience.trim()
  ) {
    throw new TypeError(
      'Access token audience is required',
    );
  }

  // --------------------------------------------------
  // Sign access token
  // --------------------------------------------------

  function signAccessToken({
    userId,
    tenantId,
  } = {}) {
    if (
      typeof userId !== 'string' ||
      !userId.trim()
    ) {
      throw new TypeError(
        'userId is required to create an access token',
      );
    }

    if (
      typeof tenantId !== 'string' ||
      !tenantId.trim()
    ) {
      throw new TypeError(
        'tenantId is required to create an access token',
      );
    }

    return jwt.sign(
      {
        tenantId,
      },
      secret,
      {
        algorithm,

        subject:
          userId,

        issuer,

        audience,

        expiresIn:
          expiresInSeconds,
      },
    );
  }

  // --------------------------------------------------
  // Verify access token
  // --------------------------------------------------

  function verifyAccessToken(token) {
    if (
      typeof token !== 'string' ||
      !token.trim()
    ) {
      return {
        valid: false,
        reason: 'INVALID_TOKEN',
      };
    }

    try {
      const payload =
        jwt.verify(
          token,
          secret,
          {
            algorithms: [
              algorithm,
            ],

            issuer,

            audience,
          },
        );

      if (
        typeof payload.sub !== 'string' ||
        !payload.sub.trim() ||
        typeof payload.tenantId !==
          'string' ||
        !payload.tenantId.trim()
      ) {
        return {
          valid: false,
          reason: 'INVALID_TOKEN',
        };
      }

      return {
        valid: true,

        userId:
          payload.sub,

        tenantId:
          payload.tenantId,

        issuedAt:
          payload.iat,

        expiresAt:
          payload.exp,
      };
    } catch (error) {
      if (
        error?.name ===
        'TokenExpiredError'
      ) {
        return {
          valid: false,
          reason: 'TOKEN_EXPIRED',
        };
      }

      return {
        valid: false,
        reason: 'INVALID_TOKEN',
      };
    }
  }

  return Object.freeze({
    signAccessToken,
    verifyAccessToken,
  });
}