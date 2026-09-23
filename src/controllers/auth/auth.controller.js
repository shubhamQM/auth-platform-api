import {
  createAuthService,
} from '../../services/auth/auth.service.js';

export function createAuthController(config) {
  const authService =
    createAuthService(config);

  // --------------------------------------------------
  // Login
  // --------------------------------------------------

  async function login(req, res, next) {
    try {
      const {
        email,
        password,
        captchaToken,
      } = req.body ?? {};

      const result =
        await authService.login({
          email,
          password,
          captchaToken,
        });

      // ----------------------------------------------
      // Invalid CAPTCHA
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason === 'CAPTCHA_INVALID'
      ) {
        return res.status(400).json({
          success: false,
          code: 'CAPTCHA_INVALID',
          message:
            'CAPTCHA verification failed',
        });
      }

      // ----------------------------------------------
      // Invalid email/password
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'INVALID_CREDENTIALS'
      ) {
        return res.status(401).json({
          success: false,
          code: 'INVALID_CREDENTIALS',
          message:
            'Invalid email or password',
        });
      }

      // ----------------------------------------------
      // Inactive account
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'ACCOUNT_INACTIVE'
      ) {
        return res.status(403).json({
          success: false,
          code: 'ACCOUNT_INACTIVE',
          message:
            'Account is inactive',
        });
      }

      // ----------------------------------------------
      // Primary authentication successful
      // ----------------------------------------------

      if (
        result.success &&
        result.requiresTwoFactor
      ) {
        const response = {
          success: true,

          message:
            'Two-factor authentication required',

          requiresTwoFactor: true,

          challengeId:
            result.challengeId,

          mode:
            result.mode,

          expiresAt:
            result.expiresAt,
        };

        // --------------------------------------------
        // DEVELOPMENT ONLY
        // --------------------------------------------

        if (
          config.twoFactor
            ?.development
            ?.exposeOtp === true &&
          result.developmentOtp
        ) {
          response.developmentOtp =
            result.developmentOtp;
        }

        return res
          .status(200)
          .json(response);
      }

      // ----------------------------------------------
      // Unexpected login state
      // ----------------------------------------------

      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message:
          'Unable to complete authentication',
      });
    } catch (error) {
      next(error);
    }
  }

  // --------------------------------------------------
  // Verify two-factor authentication
  // --------------------------------------------------

  async function verifyTwoFactor(
    req,
    res,
    next,
  ) {
    try {
      const {
        challengeId,
        emailCode,
        mobileCode,
      } = req.body ?? {};

      const result =
        await authService
          .verifyTwoFactor({
            challengeId,
            emailCode,
            mobileCode,
          });

      // ----------------------------------------------
      // Invalid / already consumed challenge
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'INVALID_CHALLENGE'
      ) {
        return res.status(400).json({
          success: false,
          code: 'INVALID_CHALLENGE',
          message:
            'Invalid or unavailable two-factor authentication challenge',
        });
      }

      // ----------------------------------------------
      // Expired challenge
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'CHALLENGE_EXPIRED'
      ) {
        return res.status(400).json({
          success: false,
          code: 'CHALLENGE_EXPIRED',
          message:
            'Two-factor authentication challenge has expired',
        });
      }

      // ----------------------------------------------
      // Invalid OTP
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason === 'INVALID_OTP'
      ) {
        return res.status(401).json({
          success: false,
          code: 'INVALID_OTP',
          message:
            'Invalid verification code',
          details: {
            attemptsRemaining:
              result.attemptsRemaining,
          },
        });
      }

      // ----------------------------------------------
      // Maximum attempts reached
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'MAX_ATTEMPTS_EXCEEDED'
      ) {
        return res.status(429).json({
          success: false,
          code: 'MAX_ATTEMPTS_EXCEEDED',
          message:
            'Maximum verification attempts exceeded',
        });
      }

      // ----------------------------------------------
      // 2FA successful
      //
      // Authentication is now complete.
      //
      // auth.service has:
      // - created the authenticated session
      // - issued the access token
      // - generated the initial refresh token
      // ----------------------------------------------

      if (
        result.success &&
        result.twoFactorVerified === true
      ) {
        return res.status(200).json({
          success: true,

          message:
            'Two-factor authentication verified',

          twoFactorVerified: true,

          accessToken:
            result.accessToken,

          tokenType:
            result.tokenType,

          expiresIn:
            result.expiresIn,

          refreshToken:
            result.refreshToken,

          session:
            result.session,

          user:
            result.user,
        });
      }

      // ----------------------------------------------
      // Unexpected verification state
      // ----------------------------------------------

      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message:
          'Unable to complete two-factor authentication',
      });
    } catch (error) {
      next(error);
    }
  }

  // --------------------------------------------------
  // Refresh authenticated session
  // --------------------------------------------------

  async function refreshSession(
    req,
    res,
    next,
  ) {
    try {
      const {
        refreshToken,
      } = req.body ?? {};

      const result =
        await authService
          .refreshSession({
            refreshToken,
          });

      // ----------------------------------------------
      // Invalid refresh token
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'INVALID_REFRESH_TOKEN'
      ) {
        return res.status(401).json({
          success: false,
          code: 'INVALID_REFRESH_TOKEN',
          message:
            'Invalid refresh token',
        });
      }

      // ----------------------------------------------
      // Session expired
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'SESSION_EXPIRED'
      ) {
        return res.status(401).json({
          success: false,
          code: 'SESSION_EXPIRED',
          message:
            'Authentication session has expired',
        });
      }

      // ----------------------------------------------
      // Refresh-token rotation conflict
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'REFRESH_TOKEN_REUSED'
      ) {
        return res.status(401).json({
          success: false,
          code: 'REFRESH_TOKEN_REUSED',
          message:
            'Refresh token is no longer valid',
        });
      }

      // ----------------------------------------------
      // User no longer exists / tenant mismatch
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'USER_NOT_FOUND'
      ) {
        return res.status(401).json({
          success: false,
          code: 'USER_NOT_FOUND',
          message:
            'Authenticated user is unavailable',
        });
      }

      // ----------------------------------------------
      // Account disabled
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'ACCOUNT_INACTIVE'
      ) {
        return res.status(403).json({
          success: false,
          code: 'ACCOUNT_INACTIVE',
          message:
            'Account is inactive',
        });
      }

      // ----------------------------------------------
      // Refresh successful
      //
      // The returned refresh token replaces the
      // previously supplied refresh token.
      // ----------------------------------------------

      if (result.success) {
        return res.status(200).json({
          success: true,

          message:
            'Authentication session refreshed',

          accessToken:
            result.accessToken,

          tokenType:
            result.tokenType,

          expiresIn:
            result.expiresIn,

          refreshToken:
            result.refreshToken,

          session:
            result.session,

          user:
            result.user,
        });
      }

      // ----------------------------------------------
      // Unexpected refresh state
      // ----------------------------------------------

      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message:
          'Unable to refresh authentication session',
      });
    } catch (error) {
      next(error);
    }
  }

  // --------------------------------------------------
  // Logout authenticated session
  // --------------------------------------------------

  async function logout(
    req,
    res,
    next,
  ) {
    try {
      const {
        refreshToken,
      } = req.body ?? {};

      const result =
        await authService.logout({
          refreshToken,
        });

      // ----------------------------------------------
      // Invalid / unavailable refresh token
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'INVALID_REFRESH_TOKEN'
      ) {
        return res.status(401).json({
          success: false,
          code: 'INVALID_REFRESH_TOKEN',
          message:
            'Invalid refresh token',
        });
      }

      // ----------------------------------------------
      // Logout successful
      // ----------------------------------------------

      if (result.success) {
        return res.status(200).json({
          success: true,

          message:
            'Logged out successfully',

          session:
            result.session,
        });
      }

      // ----------------------------------------------
      // Unexpected logout state
      // ----------------------------------------------

      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message:
          'Unable to logout',
      });
    } catch (error) {
      next(error);
    }
  }

  // --------------------------------------------------
  // Resend two-factor authentication OTP
  // --------------------------------------------------

  async function resendTwoFactor(
    req,
    res,
    next,
  ) {
    try {
      const {
        challengeId,
        channel,
      } = req.body ?? {};

      const result =
        await authService
          .resendTwoFactor({
            challengeId,
            channel,
          });

      // ----------------------------------------------
      // Invalid / consumed challenge
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'INVALID_CHALLENGE'
      ) {
        return res.status(400).json({
          success: false,
          code: 'INVALID_CHALLENGE',
          message:
            'Invalid or unavailable two-factor authentication challenge',
        });
      }

      // ----------------------------------------------
      // Expired challenge
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'CHALLENGE_EXPIRED'
      ) {
        return res.status(400).json({
          success: false,
          code: 'CHALLENGE_EXPIRED',
          message:
            'Two-factor authentication challenge has expired',
        });
      }

      // ----------------------------------------------
      // Invalid channel
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'INVALID_CHANNEL'
      ) {
        return res.status(400).json({
          success: false,
          code: 'INVALID_CHANNEL',
          message:
            'Invalid two-factor authentication channel',
        });
      }

      // ----------------------------------------------
      // Channel not required
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'CHANNEL_NOT_REQUIRED'
      ) {
        return res.status(400).json({
          success: false,
          code: 'CHANNEL_NOT_REQUIRED',
          message:
            'Requested authentication channel is not required for this challenge',
        });
      }

      // ----------------------------------------------
      // Verification attempt limit reached
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'MAX_ATTEMPTS_EXCEEDED'
      ) {
        return res.status(429).json({
          success: false,
          code: 'MAX_ATTEMPTS_EXCEEDED',
          message:
            'Maximum verification attempts exceeded',
        });
      }

      // ----------------------------------------------
      // Resend limit reached
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'MAX_RESENDS_EXCEEDED'
      ) {
        return res.status(429).json({
          success: false,
          code: 'MAX_RESENDS_EXCEEDED',
          message:
            'Maximum OTP resend attempts exceeded',
        });
      }

      // ----------------------------------------------
      // Resend successful
      // ----------------------------------------------

      if (result.success) {
        const response = {
          success: true,

          message:
            'Verification code resent successfully',

          challengeId:
            result.challengeId,

          mode:
            result.mode,

          channel:
            result.channel,

          expiresAt:
            result.expiresAt,

          resendCount:
            result.resendCount,

          resendsRemaining:
            result.resendsRemaining,
        };

        // --------------------------------------------
        // DEVELOPMENT ONLY
        //
        // Never expose result.delivery.
        // --------------------------------------------

        if (
          config.twoFactor
            ?.development
            ?.exposeOtp === true &&
          result.developmentOtp
        ) {
          response.developmentOtp =
            result.developmentOtp;
        }

        return res
          .status(200)
          .json(response);
      }

      // ----------------------------------------------
      // Unexpected resend state
      // ----------------------------------------------

      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message:
          'Unable to resend verification code',
      });
    } catch (error) {
      next(error);
    }
  }

  // --------------------------------------------------
  // Current authenticated user
  // --------------------------------------------------

  async function getCurrentUser(
    req,
    res,
    next,
  ) {
    try {
      // ----------------------------------------------
      // Trusted authentication context
      //
      // req.auth is created by auth.middleware after
      // successful JWT verification.
      // ----------------------------------------------

      const {
        userId,
        tenantId,
      } = req.auth ?? {};

      const result =
        await authService
          .getCurrentUser({
            userId,
            tenantId,
          });

      // ----------------------------------------------
      // Invalid authentication context
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'INVALID_AUTH_CONTEXT'
      ) {
        return res.status(401).json({
          success: false,
          code: 'INVALID_AUTH_CONTEXT',
          message:
            'Invalid authentication context',
        });
      }

      // ----------------------------------------------
      // User no longer exists / tenant mismatch
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'USER_NOT_FOUND'
      ) {
        return res.status(401).json({
          success: false,
          code: 'USER_NOT_FOUND',
          message:
            'Authenticated user is unavailable',
        });
      }

      // ----------------------------------------------
      // Account disabled after token issuance
      // ----------------------------------------------

      if (
        !result.success &&
        result.reason ===
          'ACCOUNT_INACTIVE'
      ) {
        return res.status(403).json({
          success: false,
          code: 'ACCOUNT_INACTIVE',
          message:
            'Account is inactive',
        });
      }

      // ----------------------------------------------
      // Current user loaded successfully
      // ----------------------------------------------

      if (result.success) {
        return res.status(200).json({
          success: true,

          user:
            result.user,
        });
      }

      // ----------------------------------------------
      // Unexpected state
      // ----------------------------------------------

      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message:
          'Unable to load authenticated user',
      });
    } catch (error) {
      next(error);
    }
  }

  // --------------------------------------------------
  // Public controller methods
  // --------------------------------------------------

  return Object.freeze({
    login,
    verifyTwoFactor,
    refreshSession,
    logout,
    resendTwoFactor,
    getCurrentUser,
  });
}

// --------------------------------------------------
// Placeholder controller
// --------------------------------------------------

export async function notImplemented(
  req,
  res,
) {
  return res.status(501).json({
    success: false,
    code: 'NOT_IMPLEMENTED',
    message: 'Not implemented',
  });
}