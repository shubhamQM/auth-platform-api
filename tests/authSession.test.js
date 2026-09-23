import crypto from 'node:crypto';
import mongoose from 'mongoose';

import {
  connectDatabase,
  disconnectDatabase,
} from '../src/config/database.js';

import {
  config,
} from '../src/config/env.js';

import {
  createAuthSessionRepository,
} from '../src/repositories/authSession.repository.js';

import {
  createAuthSessionModel,
} from '../src/models/AuthSession.js';

import {
  createRefreshTokenSecurity,
} from '../src/security/refreshTokenSecurity.js';

async function run() {
  let sessionId = null;

  try {
    console.log('');
    console.log('====================================');
    console.log('AUTH SESSION INTEGRATION TEST');
    console.log('====================================');

    // --------------------------------------------------
    // 1. Connect to shared userManagement database
    // --------------------------------------------------

    console.log(
      '\nConnecting to userManagement...',
    );

    await connectDatabase();

    console.log('Connected.');

    // --------------------------------------------------
    // 2. Create dependencies
    // --------------------------------------------------

    const repository =
      createAuthSessionRepository(
        mongoose.connection,
      );

const refreshTokenSecurity =
  createRefreshTokenSecurity({
    masterEncryptionKey:
      config.encryption
        .masterEncryptionKey,

    masterHmacKey:
      config.encryption
        .masterHmacKey,

    encryptionKeyVersion:
      config.encryption
        .encryptionKeyVersion,

    hmacKeyVersion:
      config.encryption
        .hmacKeyVersion,

    authentication:
      config.authentication,

    twoFactor:
      config.twoFactor,
  });

    const AuthSession =
      createAuthSessionModel(
        mongoose.connection,
      );

    // --------------------------------------------------
    // 3. Create unique test session
    // --------------------------------------------------

    sessionId =
      crypto.randomUUID();

    const userId =
      'USR-AUTH-SESSION-TEST';

    const tenantId =
      'TEN-AUTH-SESSION-TEST';

    const expiresAt =
      new Date(
        Date.now() +
          60 * 60 * 1000,
      );

    // --------------------------------------------------
    // 4. Generate Token A
    // --------------------------------------------------

    const refreshTokenA =
      refreshTokenSecurity
        .generateRefreshToken({
          sessionId,
        });

    const refreshTokenHashA =
      refreshTokenSecurity
        .hashRefreshToken(
          refreshTokenA,
        );

    console.log(
      '\nRefresh Token A generated.',
    );

    // --------------------------------------------------
    // 5. Create session
    //
    // Only the hash must be persisted.
    // --------------------------------------------------

    await repository.createSession({
      sessionId,
      userId,
      tenantId,
      refreshTokenHash:
        refreshTokenHashA,
      expiresAt,
    });

    console.log(
      'Session created.',
    );

    // --------------------------------------------------
    // 6. Confirm session can be loaded
    // --------------------------------------------------

    const sessionA =
      await repository
        .findSessionForRefresh(
          sessionId,
        );

    if (!sessionA) {
      throw new Error(
        'Created session could not be loaded',
      );
    }

    console.log(
      'Active session retrieved.',
    );

    // --------------------------------------------------
    // 7. Confirm Token A matches stored hash
    // --------------------------------------------------

    const tokenAValid =
      refreshTokenSecurity
        .verifyRefreshToken({
          token:
            refreshTokenA,

          tokenHash:
            sessionA.refreshTokenHash,
        });

    if (tokenAValid !== true) {
      throw new Error(
        'Refresh Token A did not match stored hash',
      );
    }

    console.log(
      'Refresh Token A verification: true',
    );

    // --------------------------------------------------
    // 8. Confirm raw refresh token is not stored
    //
    // Read the raw Mongo document to make sure there is
    // no refreshToken field containing Token A.
    // --------------------------------------------------

    const rawSession =
      await AuthSession.collection
        .findOne({
          sessionId,
        });

    if (!rawSession) {
      throw new Error(
        'Raw session document was not found',
      );
    }

    if (
      Object.prototype
        .hasOwnProperty
        .call(
          rawSession,
          'refreshToken',
        )
    ) {
      throw new Error(
        'Raw refresh token field was persisted',
      );
    }

    if (
      rawSession.refreshTokenHash ===
      refreshTokenA
    ) {
      throw new Error(
        'Raw refresh token was stored instead of a hash',
      );
    }

    if (
      rawSession.refreshTokenHash !==
      refreshTokenHashA
    ) {
      throw new Error(
        'Persisted refresh-token hash does not match expected hash',
      );
    }

    console.log(
      'Raw refresh token persistence: false',
    );

    console.log(
      'Refresh-token hash persistence: true',
    );

    // --------------------------------------------------
    // 9. Generate replacement Token B
    // --------------------------------------------------

    const refreshTokenB =
      refreshTokenSecurity
        .generateRefreshToken({
          sessionId,
        });

    const refreshTokenHashB =
      refreshTokenSecurity
        .hashRefreshToken(
          refreshTokenB,
        );

    // --------------------------------------------------
    // 10. Rotate Token A -> Token B
    // --------------------------------------------------

    const rotatedSession =
      await repository
        .rotateRefreshToken({
          sessionId,

          currentRefreshTokenHash:
            refreshTokenHashA,

          newRefreshTokenHash:
            refreshTokenHashB,
        });

    if (!rotatedSession) {
      throw new Error(
        'Refresh-token rotation failed',
      );
    }

    console.log(
      '\nToken A -> Token B rotation: passed',
    );

    // --------------------------------------------------
    // 11. Token A must now be invalid
    // --------------------------------------------------

    const oldTokenValid =
      refreshTokenSecurity
        .verifyRefreshToken({
          token:
            refreshTokenA,

          tokenHash:
            rotatedSession
              .refreshTokenHash,
        });

    if (oldTokenValid !== false) {
      throw new Error(
        'Old Refresh Token A remained valid after rotation',
      );
    }

    console.log(
      'Old Token A rejected: true',
    );

    // --------------------------------------------------
    // 12. Token B must be valid
    // --------------------------------------------------

    const tokenBValid =
      refreshTokenSecurity
        .verifyRefreshToken({
          token:
            refreshTokenB,

          tokenHash:
            rotatedSession
              .refreshTokenHash,
        });

    if (tokenBValid !== true) {
      throw new Error(
        'Refresh Token B is not valid after rotation',
      );
    }

    console.log(
      'New Token B verification: true',
    );

    // --------------------------------------------------
    // 13. Stale Token A cannot rotate again
    //
    // Repository must atomically reject the stale hash.
    // --------------------------------------------------

    const staleRotation =
      await repository
        .rotateRefreshToken({
          sessionId,

          currentRefreshTokenHash:
            refreshTokenHashA,

          newRefreshTokenHash:
            refreshTokenHashA,
        });

    if (staleRotation !== null) {
      throw new Error(
        'Stale refresh token was allowed to rotate session',
      );
    }

    console.log(
      'Stale Token A rotation rejected: true',
    );

    // --------------------------------------------------
    // 14. Revoke current session
    // --------------------------------------------------

    const revokedSession =
      await repository
        .revokeSession(
          sessionId,
        );

    if (!revokedSession) {
      throw new Error(
        'Session revocation failed',
      );
    }

    if (
      revokedSession.isRevoked !==
      true
    ) {
      throw new Error(
        'Session was not marked revoked',
      );
    }

    if (
      !(revokedSession.revokedAt instanceof Date)
    ) {
      throw new Error(
        'revokedAt was not set',
      );
    }

    console.log(
      '\nSession revocation: passed',
    );

    // --------------------------------------------------
    // 15. Revoked session must not be available
    //     for refresh
    // --------------------------------------------------

    const sessionAfterLogout =
      await repository
        .findSessionForRefresh(
          sessionId,
        );

    if (sessionAfterLogout !== null) {
      throw new Error(
        'Revoked session remained available for refresh',
      );
    }

    console.log(
      'Revoked session refresh lookup: rejected',
    );

    // --------------------------------------------------
    // 16. Rotation after revocation must fail
    // --------------------------------------------------

    const rotationAfterRevocation =
      await repository
        .rotateRefreshToken({
          sessionId,

          currentRefreshTokenHash:
            refreshTokenHashB,

          newRefreshTokenHash:
            refreshTokenHashA,
        });

    if (
      rotationAfterRevocation !==
      null
    ) {
      throw new Error(
        'Revoked session allowed refresh-token rotation',
      );
    }

    console.log(
      'Rotation after revocation: rejected',
    );

    // --------------------------------------------------
    // Final result
    // --------------------------------------------------

    console.log('');
    console.log('------------------------------------');
    console.log('AUTH SESSION TEST PASSED');
    console.log('------------------------------------');
  } catch (error) {
    console.error('');
    console.error(
      'AUTH SESSION TEST FAILED',
    );

    console.error(error);

    process.exitCode = 1;
  } finally {
    // --------------------------------------------------
    // Remove only this test's session
    // --------------------------------------------------

    if (
      sessionId &&
      mongoose.connection.readyState === 1
    ) {
      try {
        const AuthSession =
          createAuthSessionModel(
            mongoose.connection,
          );

        await AuthSession.deleteOne({
          sessionId,
        });

        console.log(
          '\nTest session cleaned up.',
        );
      } catch (error) {
        console.error(
          'Failed to clean up test session:',
          error,
        );

        process.exitCode = 1;
      }
    }

    try {
      await disconnectDatabase();
    } catch (error) {
      console.error(
        'Failed to disconnect MongoDB:',
        error,
      );

      process.exitCode = 1;
    }
  }
}

run();