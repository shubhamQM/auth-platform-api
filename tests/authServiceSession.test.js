import crypto from "node:crypto";
import mongoose from "mongoose";

import {
  connectDatabase,
  disconnectDatabase,
} from "../src/config/database.js";

import { config } from "../src/config/env.js";

import {
  createAuthService,
} from "../src/services/auth/auth.service.js";

import {
  createAuthSessionRepository,
} from "../src/repositories/authSession.repository.js";

import {
  createAuthSessionModel,
} from "../src/models/AuthSession.js";

import {
  createUserModel,
} from "../src/models/User.js";

import {
  createRefreshTokenSecurity,
} from "../src/security/refreshTokenSecurity.js";

import {
  normalizeConfig,
} from "../src/config/normalizeConfig.js";

async function run() {
  let testUserId = null;
  let authConfig = null;

  const createdSessionIds = new Set();

  try {
    console.log("");
    console.log("====================================");
    console.log("AUTH SERVICE SESSION TEST");
    console.log("====================================");

    // --------------------------------------------------
    // 1. Connect to shared userManagement database
    // --------------------------------------------------

    console.log(
      "\nConnecting to userManagement...",
    );

    await connectDatabase();

    console.log("Connected.");

    // --------------------------------------------------
    // 2. Build normalized reusable auth configuration
    //
    // env.js contains application-level configuration.
    // The reusable auth package expects its own
    // normalized configuration shape.
    // --------------------------------------------------

    authConfig = normalizeConfig({
      masterEncryptionKey:
        config.encryption.masterEncryptionKey,

      masterHmacKey:
        config.encryption.masterHmacKey,

      encryptionKeyVersion:
        config.encryption.encryptionKeyVersion,

      hmacKeyVersion:
        config.encryption.hmacKeyVersion,

      captchaSecretKey:
        config.captcha.secretKey,

      authentication:
        config.authentication,

      twoFactor:
        config.twoFactor,
    });

    // --------------------------------------------------
    // 3. Create dependencies
    // --------------------------------------------------

    const authService =
      createAuthService(
        authConfig,
      );

    const sessionRepository =
      createAuthSessionRepository(
        mongoose.connection,
      );

    const refreshTokenSecurity =
      createRefreshTokenSecurity(
        authConfig,
      );

    const User =
      createUserModel(
        authConfig,
        mongoose.connection,
      );

    const AuthSession =
      createAuthSessionModel(
        mongoose.connection,
      );

// --------------------------------------------------
// 4. Create isolated temporary user
// --------------------------------------------------

const uniqueId =
  crypto.randomUUID();

testUserId =
  `USR-AUTH-SVC-${uniqueId}`;

const userCode =
  `AUTH-SVC-${uniqueId}`;

const tenantId =
  `TEN-AUTH-SVC-${uniqueId}`;

const email =
  `auth-service-${uniqueId}@example.test`;

await User.create({
  userId:
    testUserId,

  userCode,

  tenantId,

  firstName:
    "Auth",

  lastName:
    "ServiceTest",

  email,

  mobile:
    "9000000001",

  userType:
    "employee",

  roleIds: [],

  department:
    "AUTH_TEST",

  designation:
    "TEST_USER",

  isProfileComplete:
    true,

  createdBySystem:
    true,

  isActive:
    true,
});

console.log(
  "\nTemporary encrypted user created.",
);

// --------------------------------------------------
// Diagnostic repository check
//
// Verify that authService can retrieve the same
// temporary user before testing refresh-session
// behavior.
// --------------------------------------------------

const repositoryCheck =
  await authService.getCurrentUser({
    userId:
      testUserId,

    tenantId,
  });

console.log(
  "Repository user check:",
  repositoryCheck,
);
    // ==================================================
    // TEST 1
    // Successful refresh + rotation
    // ==================================================

    console.log("");
    console.log(
      "TEST 1: Successful refresh + rotation",
    );

    const sessionId1 =
      crypto.randomUUID();

    createdSessionIds.add(
      sessionId1,
    );

    const tokenA =
      refreshTokenSecurity
        .generateRefreshToken({
          sessionId:
            sessionId1,
        });

    const tokenAHash =
      refreshTokenSecurity
        .hashRefreshToken(
          tokenA,
        );

    const expiresAt1 =
      new Date(
        Date.now() +
          60 * 60 * 1000,
      );

    await sessionRepository
      .createSession({
        sessionId:
          sessionId1,

        userId:
          testUserId,

        tenantId,

        refreshTokenHash:
          tokenAHash,

        expiresAt:
          expiresAt1,
      });

    const refreshResult1 =
      await authService
        .refreshSession({
          refreshToken:
            tokenA,
        });

    if (
      refreshResult1.success !==
      true
    ) {
      throw new Error(
        `Expected successful refresh, received: ${refreshResult1.reason}`,
      );
    }

    if (
      typeof refreshResult1
        .accessToken !== "string" ||
      !refreshResult1.accessToken
    ) {
      throw new Error(
        "Replacement access token was not issued",
      );
    }

    if (
      typeof refreshResult1
        .refreshToken !== "string" ||
      !refreshResult1.refreshToken
    ) {
      throw new Error(
        "Replacement refresh token was not issued",
      );
    }

    if (
      refreshResult1.refreshToken ===
      tokenA
    ) {
      throw new Error(
        "Refresh token was not rotated",
      );
    }

    if (
      refreshResult1
        .session
        .sessionId !==
      sessionId1
    ) {
      throw new Error(
        "Session ID changed during refresh",
      );
    }

    if (
      new Date(
        refreshResult1
          .session
          .expiresAt,
      ).getTime() !==
      expiresAt1.getTime()
    ) {
      throw new Error(
        "Session expiry changed during refresh",
      );
    }

    console.log(
      "Successful refresh: passed",
    );

    console.log(
      "Access token issued: true",
    );

    console.log(
      "Refresh token rotated: true",
    );

    console.log(
      "Session ID preserved: true",
    );

    console.log(
      "Absolute session expiry preserved: true",
    );

    // ==================================================
    // TEST 2
    // Old token must be rejected after rotation
    // ==================================================

    console.log("");
    console.log(
      "TEST 2: Old refresh token rejection",
    );

    const oldTokenResult =
      await authService
        .refreshSession({
          refreshToken:
            tokenA,
        });

    if (
      oldTokenResult.success !==
        false ||
      oldTokenResult.reason !==
        "INVALID_REFRESH_TOKEN"
    ) {
      throw new Error(
        `Expected INVALID_REFRESH_TOKEN, received: ${oldTokenResult.reason}`,
      );
    }

    console.log(
      "Old refresh token rejected: true",
    );

    // ==================================================
    // TEST 3
    // Malformed refresh token
    // ==================================================

    console.log("");
    console.log(
      "TEST 3: Malformed refresh token",
    );

    const malformedResult =
      await authService
        .refreshSession({
          refreshToken:
            "not-a-valid-refresh-token",
        });

    if (
      malformedResult.success !==
        false ||
      malformedResult.reason !==
        "INVALID_REFRESH_TOKEN"
    ) {
      throw new Error(
        "Malformed refresh token was not rejected correctly",
      );
    }

    console.log(
      "Malformed refresh token rejected: true",
    );

    // ==================================================
    // TEST 4
    // Expired session
    // ==================================================

    console.log("");
    console.log(
      "TEST 4: Expired session",
    );

    const sessionId2 =
      crypto.randomUUID();

    createdSessionIds.add(
      sessionId2,
    );

    const expiredToken =
      refreshTokenSecurity
        .generateRefreshToken({
          sessionId:
            sessionId2,
        });

    const expiredTokenHash =
      refreshTokenSecurity
        .hashRefreshToken(
          expiredToken,
        );

    await sessionRepository
      .createSession({
        sessionId:
          sessionId2,

        userId:
          testUserId,

        tenantId,

        refreshTokenHash:
          expiredTokenHash,

        expiresAt:
          new Date(
            Date.now() -
              60 * 1000,
          ),
      });

    const expiredResult =
      await authService
        .refreshSession({
          refreshToken:
            expiredToken,
        });

    if (
      expiredResult.success !==
        false ||
      expiredResult.reason !==
        "SESSION_EXPIRED"
    ) {
      throw new Error(
        `Expected SESSION_EXPIRED, received: ${expiredResult.reason}`,
      );
    }

    const expiredSession =
      await AuthSession
        .findOne({
          sessionId:
            sessionId2,
        })
        .lean()
        .exec();

    if (
      !expiredSession ||
      expiredSession.isRevoked !==
        true ||
      !expiredSession.revokedAt
    ) {
      throw new Error(
        "Expired session was not revoked",
      );
    }

    console.log(
      "Expired session rejected: true",
    );

    console.log(
      "Expired session automatically revoked: true",
    );

    // ==================================================
    // TEST 5
    // Inactive account
    // ==================================================

    console.log("");
    console.log(
      "TEST 5: Inactive account",
    );

    const sessionId3 =
      crypto.randomUUID();

    createdSessionIds.add(
      sessionId3,
    );

    const inactiveToken =
      refreshTokenSecurity
        .generateRefreshToken({
          sessionId:
            sessionId3,
        });

    const inactiveTokenHash =
      refreshTokenSecurity
        .hashRefreshToken(
          inactiveToken,
        );

    await sessionRepository
      .createSession({
        sessionId:
          sessionId3,

        userId:
          testUserId,

        tenantId,

        refreshTokenHash:
          inactiveTokenHash,

        expiresAt:
          new Date(
            Date.now() +
              60 * 60 * 1000,
          ),
      });

    // --------------------------------------------------
    // isActive is encrypted.
    //
    // Use document.save() so the encryption plugin's
    // pre-save hook encrypts the updated Boolean.
    // --------------------------------------------------

    const temporaryUser =
      await User.findOne({
        userId:
          testUserId,
      }).exec();

    if (!temporaryUser) {
      throw new Error(
        "Temporary user could not be loaded",
      );
    }

    temporaryUser.isActive =
      false;

    await temporaryUser.save();

    const inactiveResult =
      await authService
        .refreshSession({
          refreshToken:
            inactiveToken,
        });

    if (
      inactiveResult.success !==
        false ||
      inactiveResult.reason !==
        "ACCOUNT_INACTIVE"
    ) {
      throw new Error(
        `Expected ACCOUNT_INACTIVE, received: ${inactiveResult.reason}`,
      );
    }

    const inactiveSession =
      await AuthSession
        .findOne({
          sessionId:
            sessionId3,
        })
        .lean()
        .exec();

    if (
      !inactiveSession ||
      inactiveSession.isRevoked !==
        true ||
      !inactiveSession.revokedAt
    ) {
      throw new Error(
        "Inactive-account session was not revoked",
      );
    }

    console.log(
      "Inactive account rejected: true",
    );

    console.log(
      "Inactive-account session revoked: true",
    );

    // --------------------------------------------------
    // Restore temporary user for remaining tests
    // --------------------------------------------------

    const userToRestore =
      await User.findOne({
        userId:
          testUserId,
      }).exec();

    if (!userToRestore) {
      throw new Error(
        "Temporary user could not be restored",
      );
    }

    userToRestore.isActive =
      true;

    await userToRestore.save();

    console.log(
      "Temporary user restored to active.",
    );

    // ==================================================
    // TEST 6
    // Logout service
    // ==================================================

    console.log("");
    console.log(
      "TEST 6: Logout service",
    );

    const sessionId4 =
      crypto.randomUUID();

    createdSessionIds.add(
      sessionId4,
    );

    const logoutToken =
      refreshTokenSecurity
        .generateRefreshToken({
          sessionId:
            sessionId4,
        });

    const logoutTokenHash =
      refreshTokenSecurity
        .hashRefreshToken(
          logoutToken,
        );

    await sessionRepository
      .createSession({
        sessionId:
          sessionId4,

        userId:
          testUserId,

        tenantId,

        refreshTokenHash:
          logoutTokenHash,

        expiresAt:
          new Date(
            Date.now() +
              60 * 60 * 1000,
          ),
      });

    const logoutResult =
      await authService.logout({
        refreshToken:
          logoutToken,
      });

    if (
      logoutResult.success !==
      true
    ) {
      throw new Error(
        `Expected successful logout, received: ${logoutResult.reason}`,
      );
    }

    if (
      logoutResult
        .session
        .sessionId !==
      sessionId4
    ) {
      throw new Error(
        "Logout returned incorrect session ID",
      );
    }

    if (
      !logoutResult
        .session
        .revokedAt
    ) {
      throw new Error(
        "Logout did not return revokedAt",
      );
    }

    console.log(
      "Logout service: passed",
    );

    // --------------------------------------------------
    // Same token must fail after logout
    // --------------------------------------------------

    const afterLogoutResult =
      await authService
        .refreshSession({
          refreshToken:
            logoutToken,
        });

    if (
      afterLogoutResult.success !==
        false ||
      afterLogoutResult.reason !==
        "INVALID_REFRESH_TOKEN"
    ) {
      throw new Error(
        "Logged-out session remained refreshable",
      );
    }

    console.log(
      "Refresh after logout rejected: true",
    );

    // ==================================================
    // TEST 7
    // Invalid logout token must not revoke valid session
    // ==================================================

    console.log("");
    console.log(
      "TEST 7: Invalid logout token",
    );

    const sessionId5 =
      crypto.randomUUID();

    createdSessionIds.add(
      sessionId5,
    );

    const validLogoutToken =
      refreshTokenSecurity
        .generateRefreshToken({
          sessionId:
            sessionId5,
        });

    const validLogoutTokenHash =
      refreshTokenSecurity
        .hashRefreshToken(
          validLogoutToken,
        );

    await sessionRepository
      .createSession({
        sessionId:
          sessionId5,

        userId:
          testUserId,

        tenantId,

        refreshTokenHash:
          validLogoutTokenHash,

        expiresAt:
          new Date(
            Date.now() +
              60 * 60 * 1000,
          ),
      });

    // Same sessionId, different random secret.
    const fakeLogoutToken =
      refreshTokenSecurity
        .generateRefreshToken({
          sessionId:
            sessionId5,
        });

    const invalidLogoutResult =
      await authService.logout({
        refreshToken:
          fakeLogoutToken,
      });

    if (
      invalidLogoutResult.success !==
        false ||
      invalidLogoutResult.reason !==
        "INVALID_REFRESH_TOKEN"
    ) {
      throw new Error(
        "Invalid logout token was not rejected",
      );
    }

    const stillActiveSession =
      await sessionRepository
        .findSessionForRefresh(
          sessionId5,
        );

    if (!stillActiveSession) {
      throw new Error(
        "Invalid logout token revoked a valid session",
      );
    }

    console.log(
      "Invalid logout token rejected: true",
    );

    console.log(
      "Valid session remained active: true",
    );
        // ==================================================
    // TEST 8
    // Missing user must revoke session
    // ==================================================

    console.log("");
    console.log(
      "TEST 8: Missing user",
    );

    const sessionId6 =
      crypto.randomUUID();

    createdSessionIds.add(
      sessionId6,
    );

    const missingUserToken =
      refreshTokenSecurity
        .generateRefreshToken({
          sessionId:
            sessionId6,
        });

    const missingUserTokenHash =
      refreshTokenSecurity
        .hashRefreshToken(
          missingUserToken,
        );

    const missingUserId =
      `USR-AUTH-MISSING-${crypto.randomUUID()}`;

    await sessionRepository
      .createSession({
        sessionId:
          sessionId6,

        userId:
          missingUserId,

        tenantId,

        refreshTokenHash:
          missingUserTokenHash,

        expiresAt:
          new Date(
            Date.now() +
              60 * 60 * 1000,
          ),
      });

    const missingUserResult =
      await authService
        .refreshSession({
          refreshToken:
            missingUserToken,
        });

    if (
      missingUserResult.success !==
        false ||
      missingUserResult.reason !==
        "USER_NOT_FOUND"
    ) {
      throw new Error(
        `Expected USER_NOT_FOUND, received: ${missingUserResult.reason}`,
      );
    }

    const missingUserSession =
      await AuthSession
        .findOne({
          sessionId:
            sessionId6,
        })
        .lean()
        .exec();

    if (
      !missingUserSession ||
      missingUserSession.isRevoked !==
        true ||
      !missingUserSession.revokedAt
    ) {
      throw new Error(
        "Missing-user session was not revoked",
      );
    }

    console.log(
      "Missing user rejected: true",
    );

    console.log(
      "Missing-user session revoked: true",
    );

    // ==================================================
    // TEST 9
    // Tenant mismatch must revoke session
    // ==================================================

    console.log("");
    console.log(
      "TEST 9: Tenant mismatch",
    );

    const sessionId7 =
      crypto.randomUUID();

    createdSessionIds.add(
      sessionId7,
    );

    const tenantMismatchToken =
      refreshTokenSecurity
        .generateRefreshToken({
          sessionId:
            sessionId7,
        });

    const tenantMismatchTokenHash =
      refreshTokenSecurity
        .hashRefreshToken(
          tenantMismatchToken,
        );

    const mismatchedTenantId =
      `TEN-AUTH-MISMATCH-${crypto.randomUUID()}`;

    await sessionRepository
      .createSession({
        sessionId:
          sessionId7,

        // Existing user, but session claims
        // a different tenant.
        userId:
          testUserId,

        tenantId:
          mismatchedTenantId,

        refreshTokenHash:
          tenantMismatchTokenHash,

        expiresAt:
          new Date(
            Date.now() +
              60 * 60 * 1000,
          ),
      });

    const tenantMismatchResult =
      await authService
        .refreshSession({
          refreshToken:
            tenantMismatchToken,
        });

    if (
      tenantMismatchResult.success !==
        false ||
      tenantMismatchResult.reason !==
        "USER_NOT_FOUND"
    ) {
      throw new Error(
        `Expected USER_NOT_FOUND for tenant mismatch, received: ${tenantMismatchResult.reason}`,
      );
    }

    const tenantMismatchSession =
      await AuthSession
        .findOne({
          sessionId:
            sessionId7,
        })
        .lean()
        .exec();

    if (
      !tenantMismatchSession ||
      tenantMismatchSession.isRevoked !==
        true ||
      !tenantMismatchSession.revokedAt
    ) {
      throw new Error(
        "Tenant-mismatch session was not revoked",
      );
    }

    console.log(
      "Tenant mismatch rejected: true",
    );

    console.log(
      "Tenant-mismatch session revoked: true",
    );

    // ==================================================
    // Final result
    // ==================================================

    console.log("");
    console.log(
      "------------------------------------",
    );
    console.log(
      "AUTH SERVICE SESSION TEST PASSED",
    );
    console.log(
      "------------------------------------",
    );
  } catch (error) {
    console.error("");
    console.error(
      "AUTH SERVICE SESSION TEST FAILED",
    );

    console.error(error);

    process.exitCode = 1;
  } finally {
    // --------------------------------------------------
    // Cleanup
    //
    // Delete only records created by this test.
    // --------------------------------------------------

    if (
      mongoose.connection.readyState ===
      1
    ) {
      try {
        if (
          createdSessionIds.size >
          0
        ) {
          const AuthSession =
            createAuthSessionModel(
              mongoose.connection,
            );

          await AuthSession.deleteMany({
            sessionId: {
              $in: [
                ...createdSessionIds,
              ],
            },
          });
        }

        if (
          testUserId &&
          authConfig
        ) {
          const User =
            createUserModel(
              authConfig,
              mongoose.connection,
            );

          await User.deleteOne({
            userId:
              testUserId,
          });
        }

        console.log("");
        console.log(
          "Temporary test data cleaned up.",
        );
      } catch (error) {
        console.error(
          "Failed to clean up test data:",
          error,
        );

        process.exitCode = 1;
      }
    }

    try {
      await disconnectDatabase();
    } catch (error) {
      console.error(
        "Failed to disconnect MongoDB:",
        error,
      );

      process.exitCode = 1;
    }
  }
}

run();