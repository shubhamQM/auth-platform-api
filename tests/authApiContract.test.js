import crypto from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import mongoose from "mongoose";

import app from "../src/app.js";

import {
  connectDatabase,
  disconnectDatabase,
} from "../src/config/database.js";

import { config } from "../src/config/env.js";

import {
  normalizeConfig,
} from "../src/config/normalizeConfig.js";

import {
  createOtpSecurity,
} from "../src/security/otpSecurity.js";

import {
  createAuthChallengeModel,
} from "../src/models/AuthChallenge.js";

// --------------------------------------------------
// Test state
// --------------------------------------------------

const createdChallengeIds =
  new Set();

let authConfig;
let AuthChallenge;
let otpSecurity;

// --------------------------------------------------
// Helpers
// --------------------------------------------------

function assertErrorContract(
  response,
  {
    status,
    code,
  }
) {
  assert.equal(
    response.status,
    status,
    `Expected HTTP ${status}, received ${response.status}`
  );

  assert.equal(
    response.body?.success,
    false,
    "Expected success=false"
  );

  assert.equal(
    response.body?.code,
    code,
    `Expected error code ${code}`
  );

  assert.equal(
    typeof response.body?.message,
    "string",
    "Expected error message to be a string"
  );

  assert.ok(
    response.body.message.trim(),
    "Expected error message to be non-empty"
  );
}

// --------------------------------------------------
// Database lifecycle
// --------------------------------------------------

test.before(async () => {
  await connectDatabase();

  authConfig =
    normalizeConfig({
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

      captchaSecretKey:
        config.captcha.secretKey,

      authentication:
        config.authentication,

      twoFactor:
        config.twoFactor,
    });

  AuthChallenge =
    createAuthChallengeModel(
      mongoose.connection
    );

  otpSecurity =
    createOtpSecurity(authConfig);
});

test.after(async () => {
  try {
    if (
      mongoose.connection.readyState ===
        1 &&
      createdChallengeIds.size > 0
    ) {
      await AuthChallenge.deleteMany({
        challengeId: {
          $in: [
            ...createdChallengeIds,
          ],
        },
      });
    }
  } finally {
    await disconnectDatabase();
  }
});

// ==================================================
// LOGIN CONTRACT
// ==================================================

test(
  "POST /api/auth/login returns INVALID_CREDENTIALS contract",
  async () => {
    const response = await request(app)
      .post("/api/auth/login")
      .send({
        email:
          "auth-contract-user-that-does-not-exist@example.test",

        password:
          "InvalidPassword@123",

        // CAPTCHA verification is temporarily
        // bypassed in the backend during development.
        captchaToken:
          "development-test-token",
      });

    assertErrorContract(
      response,
      {
        status: 401,
        code:
          "INVALID_CREDENTIALS",
      }
    );

    assert.equal(
      response.body.message,
      "Invalid email or password"
    );
  }
);

// ==================================================
// VERIFY 2FA — INVALID CHALLENGE
// ==================================================

test(
  "POST /api/auth/2fa/verify returns INVALID_CHALLENGE contract",
  async () => {
    const response = await request(app)
      .post(
        "/api/auth/2fa/verify"
      )
      .send({
        challengeId:
          "invalid-contract-challenge",

        emailCode:
          "000000",
      });

    assertErrorContract(
      response,
      {
        status: 400,
        code:
          "INVALID_CHALLENGE",
      }
    );
  }
);

// ==================================================
// VERIFY 2FA — INVALID OTP + DETAILS CONTRACT
// ==================================================

test(
  "POST /api/auth/2fa/verify returns INVALID_OTP details contract",
  async () => {
    const challengeId =
      `AUTH-CONTRACT-${crypto.randomUUID()}`;

    createdChallengeIds.add(
      challengeId
    );

    const validOtp =
      "123456";

    const emailOtpHash =
      otpSecurity.hashOtp({
        challengeId,
        channel: "email",
        otp: validOtp,
      });

    await AuthChallenge.create({
      challengeId,

      userId:
        `USR-CONTRACT-${crypto.randomUUID()}`,

      tenantId:
        `TEN-CONTRACT-${crypto.randomUUID()}`,

      mode:
        "email",

      emailOtpHash,

      emailVerified:
        false,

      mobileVerified:
        false,

      attempts:
        0,

      resendCount:
        0,

      expiresAt:
        new Date(
          Date.now() +
            5 * 60 * 1000
        ),

      isConsumed:
        false,
    });

    // Deliberately send an incorrect OTP.
    const response = await request(app)
      .post(
        "/api/auth/2fa/verify"
      )
      .send({
        challengeId,

        emailCode:
          "000000",
      });

    assertErrorContract(
      response,
      {
        status: 401,
        code:
          "INVALID_OTP",
      }
    );

    assert.equal(
      response.body.message,
      "Invalid verification code"
    );

    // ------------------------------------------------
    // Step 14 contract:
    //
    // endpoint-specific error metadata belongs
    // inside "details".
    // ------------------------------------------------

    assert.ok(
      response.body.details &&
        typeof response.body
          .details === "object",
      "Expected error details object"
    );

    assert.equal(
      typeof response.body
        .details
        .attemptsRemaining,
      "number",
      "Expected details.attemptsRemaining to be a number"
    );

    assert.equal(
      response.body
        .attemptsRemaining,
      undefined,
      "attemptsRemaining must not exist at the top level"
    );

    // ------------------------------------------------
    // The service increments attempts from 0 → 1.
    //
    // Therefore:
    //
    // attemptsRemaining =
    // maxAttempts - 1
    // ------------------------------------------------

    assert.equal(
      response.body
        .details
        .attemptsRemaining,
      authConfig.twoFactor
        .otp.maxAttempts - 1
    );
  }
);

// ==================================================
// RESEND 2FA CONTRACT
// ==================================================

test(
  "POST /api/auth/2fa/resend returns INVALID_CHALLENGE contract",
  async () => {
    const response = await request(app)
      .post(
        "/api/auth/2fa/resend"
      )
      .send({
        challengeId:
          "invalid-contract-challenge",

        channel:
          "email",
      });

    assertErrorContract(
      response,
      {
        status: 400,
        code:
          "INVALID_CHALLENGE",
      }
    );
  }
);

// ==================================================
// REFRESH CONTRACT
// ==================================================

test(
  "POST /api/auth/refresh returns INVALID_REFRESH_TOKEN contract",
  async () => {
    const response = await request(app)
      .post(
        "/api/auth/refresh"
      )
      .send({
        refreshToken:
          "invalid-refresh-token",
      });

    assertErrorContract(
      response,
      {
        status: 401,
        code:
          "INVALID_REFRESH_TOKEN",
      }
    );
  }
);

// ==================================================
// LOGOUT CONTRACT
// ==================================================

test(
  "POST /api/auth/logout returns INVALID_REFRESH_TOKEN contract",
  async () => {
    const response = await request(app)
      .post(
        "/api/auth/logout"
      )
      .send({
        refreshToken:
          "invalid-refresh-token",
      });

    assertErrorContract(
      response,
      {
        status: 401,
        code:
          "INVALID_REFRESH_TOKEN",
      }
    );
  }
);

// ==================================================
// /ME CONTRACT
// ==================================================

test(
  "GET /api/auth/me rejects missing access token",
  async () => {
    const response =
      await request(app).get(
        "/api/auth/me"
      );

    assert.equal(
      response.status,
      401
    );

    assert.equal(
      response.body?.success,
      false
    );

    assert.equal(
      typeof response.body?.code,
      "string"
    );

    assert.ok(
      response.body.code.trim()
    );

    assert.equal(
      typeof response.body?.message,
      "string"
    );

    assert.ok(
      response.body.message.trim()
    );
  }
);

// ==================================================
// NOT IMPLEMENTED CONTRACT
// ==================================================

test(
  "POST /api/auth/forgot-password returns NOT_IMPLEMENTED contract",
  async () => {
    const response = await request(app)
      .post(
        "/api/auth/forgot-password"
      )
      .send({
        email:
          "someone@example.test",
      });

    assertErrorContract(
      response,
      {
        status: 501,
        code:
          "NOT_IMPLEMENTED",
      }
    );
  }
);