import mongoose from 'mongoose';

import {
  createAuthSessionModel,
} from '../models/AuthSession.js';

export function createAuthSessionRepository(
  connection = mongoose.connection,
) {
  const AuthSession =
    createAuthSessionModel(connection);

  // --------------------------------------------------
  // Create session
  // --------------------------------------------------

  async function createSession({
    sessionId,
    userId,
    tenantId,
    refreshTokenHash,
    expiresAt,
  }) {
    return AuthSession.create({
      sessionId,
      userId,
      tenantId,
      refreshTokenHash,
      expiresAt,

      isRevoked: false,
      revokedAt: null,
    });
  }

  // --------------------------------------------------
  // Find session for refresh
  //
  // refreshTokenHash is explicitly selected because
  // it is select:false in the schema.
  //
  // Expiry is still checked by application logic.
  // --------------------------------------------------

  async function findSessionForRefresh(
    sessionId,
  ) {
    return AuthSession.findOne({
      sessionId,
      isRevoked: false,
    })
      .select('+refreshTokenHash')
      .exec();
  }

  // --------------------------------------------------
  // Rotate refresh token
  //
  // Atomically replace the current refresh-token hash.
  //
  // The expected current hash is part of the query.
  // Therefore the same refresh token cannot
  // successfully rotate the session twice.
  //
  // Returns null if:
  // - session does not exist
  // - session is revoked
  // - current token hash no longer matches
  // --------------------------------------------------

  async function rotateRefreshToken({
    sessionId,
    currentRefreshTokenHash,
    newRefreshTokenHash,
  }) {
    return AuthSession.findOneAndUpdate(
      {
        sessionId,
        isRevoked: false,
        refreshTokenHash:
          currentRefreshTokenHash,
      },
      {
        $set: {
          refreshTokenHash:
            newRefreshTokenHash,
        },
      },
      {
returnDocument: 'after',
      },
    )
      .select('+refreshTokenHash')
      .exec();
  }

  // --------------------------------------------------
  // Revoke one session
  // --------------------------------------------------

  async function revokeSession(
    sessionId,
  ) {
    return AuthSession.findOneAndUpdate(
      {
        sessionId,
        isRevoked: false,
      },
      {
        $set: {
          isRevoked: true,
          revokedAt: new Date(),
        },
      },
      {
        returnDocument: 'after',
      },
    ).exec();
  }

  // --------------------------------------------------
  // Revoke all active sessions for a user
  //
  // Not exposed through an API yet.
  // Keeping the repository capability available for
  // future "logout all devices" / security operations.
  // --------------------------------------------------

  async function revokeAllUserSessions({
    userId,
    tenantId,
  }) {
    const revokedAt = new Date();

    return AuthSession.updateMany(
      {
        userId,
        tenantId,
        isRevoked: false,
      },
      {
        $set: {
          isRevoked: true,
          revokedAt,
        },
      },
    ).exec();
  }

  return Object.freeze({
    createSession,
    findSessionForRefresh,
    rotateRefreshToken,
    revokeSession,
    revokeAllUserSessions,
  });
}