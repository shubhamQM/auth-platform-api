import mongoose from "mongoose";

import {
  connectDatabase,
  disconnectDatabase,
} from "../src/config/database.js";

import {
  config,
} from "../src/config/env.js";

import {
  normalizeConfig,
} from "../src/config/normalizeConfig.js";

import {
  createUserRepository,
} from "../src/repositories/user.repository.js";

import {
  verifyPassword,
} from "../src/security/passwordSecurity.js";

async function run() {
  try {
    console.log("");
    console.log(
      "===================================="
    );
    console.log(
      "AUTH PASSWORD COMPATIBILITY TEST"
    );
    console.log(
      "===================================="
    );

    // --------------------------------------------------
    // 1. Connect to shared userManagement database
    // --------------------------------------------------

    console.log(
      "\nConnecting to userManagement..."
    );

    await connectDatabase();

    console.log(
      "Connected."
    );

    // --------------------------------------------------
    // 2. Build normalized reusable auth configuration
    //
    // createUserRepository() uses the reusable package
    // configuration contract, not config.encryption alone.
    // --------------------------------------------------

    const authConfig =
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
          config.captcha
            .secretKey,

        authentication:
          config.authentication,

        twoFactor:
          config.twoFactor,
      });

    // --------------------------------------------------
    // 3. Create repository
    // --------------------------------------------------

    const repository =
      createUserRepository(
        authConfig,
        mongoose.connection
      );

    // --------------------------------------------------
    // 4. Test credentials
    //
    // These must correspond to a dedicated development
    // authentication fixture in userManagement.
    // --------------------------------------------------

    const email =
      "auth.employee1@example.edu";

    const password =
      "Employee@123";

    console.log(
      `\nSearching for: ${email}`
    );

    const user =
      await repository
        .findByEncryptedEmailWithPassword(
          email
        );

    if (!user) {
      console.error(
        "\nUSER NOT FOUND"
      );

      process.exitCode = 1;

      return;
    }

    console.log(
      "USER FOUND"
    );

    // --------------------------------------------------
    // 5. Confirm password hash was explicitly retrieved
    // --------------------------------------------------

    if (
      typeof user.password !==
        "string" ||
      !user.password
    ) {
      console.error(
        "\nPASSWORD HASH NOT FOUND"
      );

      process.exitCode = 1;

      return;
    }

    console.log(
      "Password hash retrieved."
    );

    // Never print the actual password hash.
    console.log(
      "Argon2id hash:",
      user.password.startsWith(
        "$argon2id$"
      )
    );

    // --------------------------------------------------
    // 6. Verify correct password
    // --------------------------------------------------

    const validPassword =
      await verifyPassword(
        password,
        user.password
      );

    console.log(
      "Correct password verification:",
      validPassword
    );

    // --------------------------------------------------
    // 7. Verify incorrect password is rejected
    // --------------------------------------------------

    const invalidPassword =
      await verifyPassword(
        "DefinitelyWrongPassword",
        user.password
      );

    console.log(
      "Wrong password verification:",
      invalidPassword
    );

    // --------------------------------------------------
    // 8. Final result
    // --------------------------------------------------

    if (
      validPassword !== true ||
      invalidPassword !== false
    ) {
      console.error("");

      console.error(
        "PASSWORD COMPATIBILITY FAILED"
      );

      process.exitCode = 1;

      return;
    }

    console.log("");

    console.log(
      "------------------------------------"
    );

    console.log(
      "PASSWORD COMPATIBILITY PASSED"
    );

    console.log(
      "------------------------------------"
    );
  } catch (error) {
    console.error("");

    console.error(
      "PASSWORD COMPATIBILITY FAILED"
    );

    console.error(
      error
    );

    process.exitCode = 1;
  } finally {
    try {
      await disconnectDatabase();
    } catch (error) {
      console.error(
        "Failed to disconnect MongoDB:",
        error
      );

      process.exitCode = 1;
    }
  }
}

run();