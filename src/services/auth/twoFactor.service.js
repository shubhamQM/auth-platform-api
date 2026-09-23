import crypto from "node:crypto";

import { normalizeConfig } from "../../config/normalizeConfig.js";

import { createOtpSecurity } from "../../security/otpSecurity.js";

import { createAuthChallengeRepository } from "../../repositories/authChallenge.repository.js";

export function createTwoFactorService(options = {}) {
  const config = normalizeConfig(options);

  const otpSecurity = createOtpSecurity(config);

  const challengeRepository = createAuthChallengeRepository();

  // --------------------------------------------------
  // Create 2FA challenge
  // --------------------------------------------------

  async function createChallenge(user) {
    if (!user?.userId || !user?.tenantId) {
      throw new TypeError("A valid user is required to create a 2FA challenge");
    }

    const mode = config.twoFactor.mode;

    const otpConfig = config.twoFactor.otp;

    const exposeDevelopmentOtp =
      config.twoFactor.development.exposeOtp === true;

    const challengeId = crypto.randomUUID();

    const requiresEmail = mode === "email" || mode === "email_mobile";

    const requiresMobile = mode === "mobile" || mode === "email_mobile";

    // ----------------------------------------------
    // Validate required delivery destinations
    // ----------------------------------------------

    if (
      requiresEmail &&
      (typeof user.email !== "string" || !user.email.trim())
    ) {
      throw new Error("User does not have an email address for 2FA");
    }

    if (
      requiresMobile &&
      (typeof user.mobile !== "string" || !user.mobile.trim())
    ) {
      throw new Error("User does not have a mobile number for 2FA");
    }

    // ----------------------------------------------
    // Generate required OTPs
    // ----------------------------------------------

    const emailOtp = requiresEmail ? otpSecurity.generateOtp() : null;

    const mobileOtp = requiresMobile ? otpSecurity.generateOtp() : null;

    // ----------------------------------------------
    // Hash OTPs
    // ----------------------------------------------

    const emailOtpHash = emailOtp
      ? otpSecurity.hashOtp({
          challengeId,
          channel: "email",
          otp: emailOtp,
        })
      : undefined;

    const mobileOtpHash = mobileOtp
      ? otpSecurity.hashOtp({
          challengeId,
          channel: "mobile",
          otp: mobileOtp,
        })
      : undefined;

    // ----------------------------------------------
    // Challenge expiry
    // ----------------------------------------------

    const expiresAt = new Date(Date.now() + otpConfig.expiresInSeconds * 1000);

    // ----------------------------------------------
    // Persist challenge
    // ----------------------------------------------

    await challengeRepository.createChallenge({
      challengeId,

      userId: user.userId,
      tenantId: user.tenantId,

      mode,

      emailOtpHash,
      mobileOtpHash,

      expiresAt,
    });

    // ----------------------------------------------
    // Internal result
    // ----------------------------------------------

    const result = {
      challengeId,
      mode,
      expiresAt,

      delivery: {
        email: requiresEmail
          ? {
              destination: user.email,
              otp: emailOtp,
            }
          : null,

        mobile: requiresMobile
          ? {
              destination: user.mobile,
              otp: mobileOtp,
            }
          : null,
      },
    };

    if (exposeDevelopmentOtp) {
      result.developmentOtp = {
        email: requiresEmail ? emailOtp : null,

        mobile: requiresMobile ? mobileOtp : null,
      };
    }

    return result;
  }

  // --------------------------------------------------
  // Verify 2FA challenge
  // --------------------------------------------------

  async function verifyChallenge({ challengeId, emailCode, mobileCode } = {}) {
    // ----------------------------------------------
    // Basic challenge validation
    // ----------------------------------------------

    if (typeof challengeId !== "string" || !challengeId.trim()) {
      return {
        success: false,
        reason: "INVALID_CHALLENGE",
      };
    }

    const normalizedChallengeId = challengeId.trim();

    const challenge = await challengeRepository.findChallengeForVerification(
      normalizedChallengeId,
    );

    if (!challenge) {
      return {
        success: false,
        reason: "INVALID_CHALLENGE",
      };
    }

    // ----------------------------------------------
    // Expiry
    // ----------------------------------------------

    if (
      !(challenge.expiresAt instanceof Date) ||
      challenge.expiresAt.getTime() <= Date.now()
    ) {
      return {
        success: false,
        reason: "CHALLENGE_EXPIRED",
      };
    }

    // ----------------------------------------------
    // Attempt limit
    // ----------------------------------------------

    if (challenge.attempts >= config.twoFactor.otp.maxAttempts) {
      return {
        success: false,
        reason: "MAX_ATTEMPTS_EXCEEDED",
      };
    }

    // ----------------------------------------------
    // Determine channels from the CHALLENGE mode.
    //
    // Do not use the current configured mode here.
    // A challenge must be verified according to the
    // mode with which it was originally created.
    // ----------------------------------------------

    const requiresEmail =
      challenge.mode === "email" || challenge.mode === "email_mobile";

    const requiresMobile =
      challenge.mode === "mobile" || challenge.mode === "email_mobile";

    // ----------------------------------------------
    // Verify email OTP
    // ----------------------------------------------

    let emailValid = !requiresEmail || challenge.emailVerified === true;

    if (requiresEmail && !emailValid) {
      emailValid =
        typeof emailCode === "string" &&
        emailCode.length > 0 &&
        typeof challenge.emailOtpHash === "string" &&
        otpSecurity.verifyOtp({
          challengeId: normalizedChallengeId,

          channel: "email",

          otp: emailCode,

          otpHash: challenge.emailOtpHash,
        });
    }

    // ----------------------------------------------
    // Verify mobile OTP
    // ----------------------------------------------

    let mobileValid = !requiresMobile || challenge.mobileVerified === true;

    if (requiresMobile && !mobileValid) {
      mobileValid =
        typeof mobileCode === "string" &&
        mobileCode.length > 0 &&
        typeof challenge.mobileOtpHash === "string" &&
        otpSecurity.verifyOtp({
          challengeId: normalizedChallengeId,

          channel: "mobile",

          otp: mobileCode,

          otpHash: challenge.mobileOtpHash,
        });
    }

    // ----------------------------------------------
    // Invalid OTP
    //
    // One verification request counts as one failed
    // attempt, even for email_mobile mode.
    // ----------------------------------------------

    if (!emailValid || !mobileValid) {
      const updatedChallenge = await challengeRepository.incrementAttempts(
        normalizedChallengeId,
      );

      const attempts = updatedChallenge?.attempts ?? challenge.attempts + 1;

      return {
        success: false,

        reason:
          attempts >= config.twoFactor.otp.maxAttempts
            ? "MAX_ATTEMPTS_EXCEEDED"
            : "INVALID_OTP",

        attemptsRemaining: Math.max(
          0,
          config.twoFactor.otp.maxAttempts - attempts,
        ),
      };
    }

    // ----------------------------------------------
    // Mark required channels verified
    // ----------------------------------------------

    if (requiresEmail && challenge.emailVerified !== true) {
      await challengeRepository.markEmailVerified(normalizedChallengeId);
    }

    if (requiresMobile && challenge.mobileVerified !== true) {
      await challengeRepository.markMobileVerified(normalizedChallengeId);
    }

    // ----------------------------------------------
    // Consume challenge
    //
    // At this point every required channel has
    // successfully verified.
    // ----------------------------------------------

    const consumedChallenge = await challengeRepository.consumeChallenge(
      normalizedChallengeId,
    );

    if (!consumedChallenge) {
      return {
        success: false,
        reason: "INVALID_CHALLENGE",
      };
    }

    // ----------------------------------------------
    // 2FA complete
    //
    // JWT/session issuance comes later.
    // ----------------------------------------------

    return {
      success: true,

      userId: consumedChallenge.userId,

      tenantId: consumedChallenge.tenantId,

      challengeId: consumedChallenge.challengeId,
    };
  }
    // --------------------------------------------------
  // Resend 2FA OTP
  // --------------------------------------------------

  async function resendChallenge({
    challengeId,
    channel,
  } = {}) {
    // ----------------------------------------------
    // Validate challenge ID
    // ----------------------------------------------

    if (
      typeof challengeId !== "string" ||
      !challengeId.trim()
    ) {
      return {
        success: false,
        reason: "INVALID_CHALLENGE",
      };
    }

    const normalizedChallengeId =
      challengeId.trim();

    // ----------------------------------------------
    // Validate requested channel
    // ----------------------------------------------

    if (
      channel !== "email" &&
      channel !== "mobile"
    ) {
      return {
        success: false,
        reason: "INVALID_CHANNEL",
      };
    }

    // ----------------------------------------------
    // Find active challenge
    // ----------------------------------------------

    const challenge =
      await challengeRepository
        .findChallengeForVerification(
          normalizedChallengeId,
        );

    if (!challenge) {
      return {
        success: false,
        reason: "INVALID_CHALLENGE",
      };
    }

    // ----------------------------------------------
    // Expired challenge
    //
    // Resend does not revive an already expired
    // authentication challenge.
    // ----------------------------------------------

    if (
      !(challenge.expiresAt instanceof Date) ||
      challenge.expiresAt.getTime() <= Date.now()
    ) {
      return {
        success: false,
        reason: "CHALLENGE_EXPIRED",
      };
    }

    // ----------------------------------------------
    // Maximum verification attempts
    //
    // Resend must not bypass an OTP lockout.
    // ----------------------------------------------

    if (
      challenge.attempts >=
      config.twoFactor.otp.maxAttempts
    ) {
      return {
        success: false,
        reason: "MAX_ATTEMPTS_EXCEEDED",
      };
    }

    // ----------------------------------------------
    // Validate channel against challenge mode
    // ----------------------------------------------

    const requiresEmail =
      challenge.mode === "email" ||
      challenge.mode === "email_mobile";

    const requiresMobile =
      challenge.mode === "mobile" ||
      challenge.mode === "email_mobile";

    if (
      (channel === "email" &&
        !requiresEmail) ||
      (channel === "mobile" &&
        !requiresMobile)
    ) {
      return {
        success: false,
        reason: "CHANNEL_NOT_REQUIRED",
      };
    }

    // ----------------------------------------------
    // Resend limit
    // ----------------------------------------------

    const otpConfig =
      config.twoFactor.otp;

    if (
      challenge.resendCount >=
      otpConfig.maxResends
    ) {
      return {
        success: false,
        reason: "MAX_RESENDS_EXCEEDED",
      };
    }

    // ----------------------------------------------
    // Generate replacement OTP
    // ----------------------------------------------

    const otp =
      otpSecurity.generateOtp();

    const otpHash =
      otpSecurity.hashOtp({
        challengeId:
          normalizedChallengeId,

        channel,

        otp,
      });

    // ----------------------------------------------
    // Refresh OTP expiry
    // ----------------------------------------------

    const expiresAt = new Date(
      Date.now() +
        otpConfig.expiresInSeconds *
          1000,
    );

    // ----------------------------------------------
    // Atomically replace OTP and increment resend
    // count.
    // ----------------------------------------------

    const updatedChallenge =
      await challengeRepository
        .updateForResend({
          challengeId:
            normalizedChallengeId,

          channel,

          otpHash,

          expiresAt,

          maxResends:
            otpConfig.maxResends,
        });

    if (!updatedChallenge) {
      return {
        success: false,
        reason:
          "MAX_RESENDS_EXCEEDED",
      };
    }

    // ----------------------------------------------
    // Internal delivery result
    //
    // Actual email/SMS provider comes later.
    // ----------------------------------------------

    const result = {
      success: true,

      challengeId:
        updatedChallenge.challengeId,

      mode:
        updatedChallenge.mode,

      channel,

      expiresAt:
        updatedChallenge.expiresAt,

      resendCount:
        updatedChallenge.resendCount,

      resendsRemaining:
        Math.max(
          0,
          otpConfig.maxResends -
            updatedChallenge.resendCount,
        ),

      delivery: {
        channel,
        otp,
      },
    };

    // ----------------------------------------------
    // DEVELOPMENT ONLY
    // ----------------------------------------------

    if (
      config.twoFactor.development
        .exposeOtp === true
    ) {
      result.developmentOtp = {
        email:
          channel === "email"
            ? otp
            : null,

        mobile:
          channel === "mobile"
            ? otp
            : null,
      };
    }

    return result;
  }

  return Object.freeze({
    createChallenge,
    verifyChallenge,
    resendChallenge,
  });
}
