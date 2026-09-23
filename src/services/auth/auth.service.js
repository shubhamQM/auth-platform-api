import crypto from "node:crypto";

import { createUserRepository } from "../../repositories/user.repository.js";

import { createRoleRepository } from "../../repositories/role.repository.js";

import { createPortalRepository } from "../../repositories/portal.repository.js";

import { createAuthSessionRepository } from "../../repositories/authSession.repository.js";

import { verifyPassword } from "../../security/passwordSecurity.js";

import { createCaptchaSecurity } from "../../security/captchaSecurity.js";

import { createJwtSecurity } from "../../security/jwtSecurity.js";

import { createRefreshTokenSecurity } from "../../security/refreshTokenSecurity.js";

import { createTwoFactorService } from "./twoFactor.service.js";

export function createAuthService(config) {
  const userRepository = createUserRepository(config);

  const roleRepository = createRoleRepository(config);

  const portalRepository = createPortalRepository(config);

  const authSessionRepository = createAuthSessionRepository();

  const captchaSecurity = createCaptchaSecurity(config);

  const jwtSecurity = createJwtSecurity(config);

  const refreshTokenSecurity = createRefreshTokenSecurity(config);

  const twoFactorService = createTwoFactorService(config);

  // --------------------------------------------------
  // Login
  // --------------------------------------------------

  async function login({ email, password, captchaToken }) {
    // ----------------------------------------------
    // Basic request validation
    // ----------------------------------------------

    if (
      typeof email !== "string" ||
      !email.trim() ||
      typeof password !== "string" ||
      !password
    ) {
      return {
        success: false,
        reason: "INVALID_CREDENTIALS",
      };
    }

    // ----------------------------------------------
    // CAPTCHA validation
    // TEMPORARILY DISABLED
    //
    // Reason:
    // Current development environment cannot verify
    // Google's TLS certificate chain.
    //
    // IMPORTANT:
    // Re-enable before production deployment.
    // ----------------------------------------------

    // const captchaValid =
    //   await captchaSecurity.verifyCaptcha(
    //     captchaToken,
    //   );

    // if (!captchaValid) {
    //   return {
    //     success: false,
    //     reason: 'CAPTCHA_INVALID',
    //   };
    // }

    // ----------------------------------------------
    // Normalize email
    // ----------------------------------------------

    const normalizedEmail = email.trim().toLowerCase();

    // ----------------------------------------------
    // Find user
    // ----------------------------------------------

    const user =
      await userRepository.findByEncryptedEmailWithPassword(normalizedEmail);

    if (!user) {
      return {
        success: false,
        reason: "INVALID_CREDENTIALS",
      };
    }

    // ----------------------------------------------
    // Account status
    // ----------------------------------------------

    if (user.isActive !== true) {
      return {
        success: false,
        reason: "ACCOUNT_INACTIVE",
      };
    }

    // ----------------------------------------------
    // Password verification
    // ----------------------------------------------

    const passwordValid = await verifyPassword(password, user.password);

    if (!passwordValid) {
      return {
        success: false,
        reason: "INVALID_CREDENTIALS",
      };
    }

    // ----------------------------------------------
    // Credentials verified
    //
    // Master User uses:
    //   orgCode
    //   phoneNo
    //
    // Auth internals continue using:
    //   tenantId
    //   mobile
    //
    // This keeps JWT/session/challenge compatibility
    // while the master schema uses its new naming.
    // ----------------------------------------------

    const challenge = await twoFactorService.createChallenge({
      userId: user.userId,

      tenantId: user.orgCode,

      email: user.email,

      mobile: user.phoneNo,
    });

    // ----------------------------------------------
    // Pending 2FA
    // ----------------------------------------------

    const result = {
      success: true,
      requiresTwoFactor: true,

      challengeId: challenge.challengeId,

      mode: challenge.mode,

      expiresAt: challenge.expiresAt,

      user: {
        userId: user.userId,

        orgCode: user.orgCode,
      },

      delivery: challenge.delivery,
    };

    if (challenge.developmentOtp) {
      result.developmentOtp = challenge.developmentOtp;
    }

    return result;
  }

  // --------------------------------------------------
  // Verify two-factor authentication
  // --------------------------------------------------

  async function verifyTwoFactor({ challengeId, emailCode, mobileCode } = {}) {
    const result = await twoFactorService.verifyChallenge({
      challengeId,
      emailCode,
      mobileCode,
    });

    if (!result.success) {
      return result;
    }

    // ----------------------------------------------
    // 2FA completed successfully
    // ----------------------------------------------

    const sessionId = crypto.randomUUID();

    const refreshToken = refreshTokenSecurity.generateRefreshToken({
      sessionId,
    });

    const refreshTokenHash =
      refreshTokenSecurity.hashRefreshToken(refreshToken);

    const sessionExpiresAt = new Date(
      Date.now() + config.authentication.session.expiresInSeconds * 1000,
    );

    // ----------------------------------------------
    // Persist authenticated session
    //
    // result.tenantId comes from the 2FA challenge.
    // The challenge received user.orgCode during
    // login.
    // ----------------------------------------------

    await authSessionRepository.createSession({
      sessionId,

      userId: result.userId,

      tenantId: result.tenantId,

      refreshTokenHash,

      expiresAt: sessionExpiresAt,
    });

    // ----------------------------------------------
    // Issue short-lived access token
    // ----------------------------------------------

    const accessToken = jwtSecurity.signAccessToken({
      userId: result.userId,

      tenantId: result.tenantId,
    });

    // ----------------------------------------------
    // Authentication completed
    // ----------------------------------------------

    return {
      success: true,
      twoFactorVerified: true,

      challengeId: result.challengeId,

      accessToken,

      tokenType: "Bearer",

      expiresIn: config.authentication.accessToken.expiresInSeconds,

      refreshToken,

      session: {
        sessionId,

        expiresAt: sessionExpiresAt,
      },

      user: {
        userId: result.userId,

        orgCode: result.tenantId,
      },
    };
  }

  // --------------------------------------------------
  // Refresh authenticated session
  // --------------------------------------------------

  async function refreshSession({ refreshToken } = {}) {
    // ----------------------------------------------
    // Basic token validation / parsing
    // ----------------------------------------------

    const parsedToken = refreshTokenSecurity.parseRefreshToken(refreshToken);

    if (!parsedToken) {
      return {
        success: false,
        reason: "INVALID_REFRESH_TOKEN",
      };
    }

    const { sessionId } = parsedToken;

    // ----------------------------------------------
    // Load active session
    // ----------------------------------------------

    const session =
      await authSessionRepository.findSessionForRefresh(sessionId);

    if (!session) {
      return {
        success: false,
        reason: "INVALID_REFRESH_TOKEN",
      };
    }

    // ----------------------------------------------
    // Session expiry
    // ----------------------------------------------

    if (
      !(session.expiresAt instanceof Date) ||
      session.expiresAt.getTime() <= Date.now()
    ) {
      await authSessionRepository.revokeSession(sessionId);

      return {
        success: false,
        reason: "SESSION_EXPIRED",
      };
    }

    // ----------------------------------------------
    // Verify supplied refresh token
    // ----------------------------------------------

    const refreshTokenValid = refreshTokenSecurity.verifyRefreshToken({
      token: refreshToken,

      tokenHash: session.refreshTokenHash,
    });

    if (!refreshTokenValid) {
      return {
        success: false,
        reason: "INVALID_REFRESH_TOKEN",
      };
    }

    // ----------------------------------------------
    // Load current master user
    // ----------------------------------------------

    const user = await userRepository.findByUserId(session.userId);

    if (!user) {
      await authSessionRepository.revokeSession(sessionId);

      return {
        success: false,
        reason: "USER_NOT_FOUND",
      };
    }

    // ----------------------------------------------
    // Organization / tenant boundary
    //
    // AuthSession retains tenantId internally.
    // Master User now stores orgCode.
    // ----------------------------------------------

    if (user.orgCode !== session.tenantId) {
      await authSessionRepository.revokeSession(sessionId);

      return {
        success: false,
        reason: "USER_NOT_FOUND",
      };
    }

    // ----------------------------------------------
    // Current account status
    // ----------------------------------------------

    if (user.isActive !== true) {
      await authSessionRepository.revokeSession(sessionId);

      return {
        success: false,
        reason: "ACCOUNT_INACTIVE",
      };
    }

    // ----------------------------------------------
    // Generate replacement refresh token
    // ----------------------------------------------

    const newRefreshToken = refreshTokenSecurity.generateRefreshToken({
      sessionId,
    });

    const newRefreshTokenHash =
      refreshTokenSecurity.hashRefreshToken(newRefreshToken);

    // ----------------------------------------------
    // Atomically rotate refresh token
    // ----------------------------------------------

    const rotatedSession = await authSessionRepository.rotateRefreshToken({
      sessionId,

      currentRefreshTokenHash: session.refreshTokenHash,

      newRefreshTokenHash,
    });

    if (!rotatedSession) {
      return {
        success: false,
        reason: "REFRESH_TOKEN_REUSED",
      };
    }

    // ----------------------------------------------
    // Issue replacement access token
    //
    // JWT retains tenantId internally.
    // Its value comes from master user.orgCode.
    // ----------------------------------------------

    const accessToken = jwtSecurity.signAccessToken({
      userId: user.userId,

      tenantId: user.orgCode,
    });

    // ----------------------------------------------
    // Refresh completed
    // ----------------------------------------------

    return {
      success: true,

      accessToken,

      tokenType: "Bearer",

      expiresIn: config.authentication.accessToken.expiresInSeconds,

      refreshToken: newRefreshToken,

      session: {
        sessionId: session.sessionId,

        expiresAt: session.expiresAt,
      },

      user: {
        userId: user.userId,

        orgCode: user.orgCode,
      },
    };
  }

  // --------------------------------------------------
  // Logout authenticated session
  // --------------------------------------------------

  async function logout({ refreshToken } = {}) {
    // ----------------------------------------------
    // Parse refresh token
    // ----------------------------------------------

    const parsedToken = refreshTokenSecurity.parseRefreshToken(refreshToken);

    if (!parsedToken) {
      return {
        success: false,
        reason: "INVALID_REFRESH_TOKEN",
      };
    }

    const { sessionId } = parsedToken;

    // ----------------------------------------------
    // Load active session
    // ----------------------------------------------

    const session =
      await authSessionRepository.findSessionForRefresh(sessionId);

    if (!session) {
      return {
        success: false,
        reason: "INVALID_REFRESH_TOKEN",
      };
    }

    // ----------------------------------------------
    // Verify refresh token belongs to session
    // ----------------------------------------------

    const refreshTokenValid = refreshTokenSecurity.verifyRefreshToken({
      token: refreshToken,

      tokenHash: session.refreshTokenHash,
    });

    if (!refreshTokenValid) {
      return {
        success: false,
        reason: "INVALID_REFRESH_TOKEN",
      };
    }

    // ----------------------------------------------
    // Revoke session
    // ----------------------------------------------

    const revokedSession = await authSessionRepository.revokeSession(sessionId);

    if (!revokedSession) {
      return {
        success: false,
        reason: "INVALID_REFRESH_TOKEN",
      };
    }

    return {
      success: true,

      session: {
        sessionId: revokedSession.sessionId,

        revokedAt: revokedSession.revokedAt,
      },
    };
  }

  // --------------------------------------------------
  // Resend two-factor authentication OTP
  // --------------------------------------------------

  async function resendTwoFactor({ challengeId, channel } = {}) {
    const result = await twoFactorService.resendChallenge({
      challengeId,
      channel,
    });

    if (!result.success) {
      return result;
    }

    const response = {
      success: true,

      challengeId: result.challengeId,

      mode: result.mode,

      channel: result.channel,

      expiresAt: result.expiresAt,

      resendCount: result.resendCount,

      resendsRemaining: result.resendsRemaining,

      delivery: result.delivery,
    };

    if (result.developmentOtp) {
      response.developmentOtp = result.developmentOtp;
    }

    return response;
  }

  // --------------------------------------------------
  // Get current authenticated user
  // --------------------------------------------------

  async function getCurrentUser({ userId, tenantId } = {}) {
    // ----------------------------------------------
    // Trusted identity validation
    //
    // tenantId is the internal JWT claim.
    // It represents the current master orgCode.
    // ----------------------------------------------

    if (
      typeof userId !== "string" ||
      !userId.trim() ||
      typeof tenantId !== "string" ||
      !tenantId.trim()
    ) {
      return {
        success: false,
        reason: "INVALID_AUTH_CONTEXT",
      };
    }

    // ----------------------------------------------
    // Load current user
    // ----------------------------------------------

    const user = await userRepository.findByUserId(userId);

    if (!user) {
      return {
        success: false,
        reason: "USER_NOT_FOUND",
      };
    }

    // ----------------------------------------------
    // Organization / tenant boundary
    // ----------------------------------------------

    if (user.orgCode !== tenantId) {
      return {
        success: false,
        reason: "USER_NOT_FOUND",
      };
    }

    // ----------------------------------------------
    // Current account status
    // ----------------------------------------------

    if (user.isActive !== true) {
      return {
        success: false,
        reason: "ACCOUNT_INACTIVE",
      };
    }

    // ----------------------------------------------
    // Normalize assigned role codes
    // ----------------------------------------------

    const roleCodes = Array.isArray(user.roleCode)
      ? [
          ...new Set(
            user.roleCode.filter(
              (roleCode) => typeof roleCode === "string" && roleCode.trim(),
            ),
          ),
        ]
      : [];

    // ----------------------------------------------
    // Resolve User -> Role -> Portal
    //
    // User.roleCode[]
    //       ↓
    // Role.roleCode
    //       ↓
    // Role.portalCode[]
    //       ↓
    // Portal.portalCode
    // ----------------------------------------------

    let portals = [];

    if (roleCodes.length > 0) {
      const roles = await roleRepository.findByRoleCodes(roleCodes);

      const portalCodes = [
        ...new Set(
          roles.flatMap((role) =>
            Array.isArray(role.portalCode)
              ? role.portalCode.filter(
                  (portalCode) =>
                    typeof portalCode === "string" && portalCode.trim(),
                )
              : [],
          ),
        ),
      ];

      // --------------------------------------------
      // Resolve portal details
      // --------------------------------------------

      if (portalCodes.length > 0) {
        const resolvedPortals =
          await portalRepository.findByPortalCodes(portalCodes);

        // Preserve Role.portalCode ordering.

        const portalByCode = new Map(
          resolvedPortals.map((portal) => [portal.portalCode, portal]),
        );

        portals = portalCodes
          .map((portalCode) => portalByCode.get(portalCode))
          .filter((portal) => portal && portal.isActive === true)
          .map((portal) => ({
            portalCode: portal.portalCode,

            name: portal.name,
            websiteUrl: portal.websiteUrl,
            description: portal.description,

            isActive: portal.isActive,
          }));
      }
    }

    // ----------------------------------------------
    // Safe authenticated-user response
    // ----------------------------------------------

    return {
      success: true,

      user: {
        userId: user.userId,

        userCode: user.userCode,

        orgCode: user.orgCode,

        fullName: user.fullName,

        firstName: user.firstName,

        middleName: user.middleName,

        lastName: user.lastName,

        email: user.email,

        phoneNo: user.phoneNo,

        userType: user.userType,

        roleCode: roleCodes,

        activeRoleCode: user.activeRoleCode,

        portals,
      },
    };
  }

  return Object.freeze({
    login,
    verifyTwoFactor,
    refreshSession,
    logout,
    resendTwoFactor,
    getCurrentUser,
  });
}
