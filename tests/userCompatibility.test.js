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

async function run() {
  try {
    console.log("");
    console.log(
      "===================================="
    );
    console.log(
      "AUTH USER COMPATIBILITY TEST"
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
    // 4. Search for shared master User
    // --------------------------------------------------

    const email =
      "auth.employee1@example.edu";

    console.log(
      `\nSearching for: ${email}`
    );

    const user =
      await repository
        .findByEncryptedEmail(
          email
        );

    // --------------------------------------------------
    // 5. Check result
    // --------------------------------------------------

    if (!user) {
      console.error("");
      console.error(
        "USER NOT FOUND"
      );

      console.error(
        "Auth API could not locate the shared master user."
      );

      process.exitCode = 1;

      return;
    }

    // --------------------------------------------------
    // 6. Validate current User contract
    // --------------------------------------------------

    if (
      typeof user.userId !==
        "string" ||
      !user.userId
    ) {
      throw new Error(
        "userId was not returned correctly"
      );
    }

    if (
      typeof user.userCode !==
        "string" ||
      !user.userCode
    ) {
      throw new Error(
        "userCode was not returned correctly"
      );
    }

    if (
      typeof user.fullName !==
        "string" ||
      !user.fullName
    ) {
      throw new Error(
        "fullName was not decrypted correctly"
      );
    }

    if (
      user.email !== email
    ) {
      throw new Error(
        "email was not decrypted correctly"
      );
    }

    if (
      typeof user.phoneNo !==
        "string" ||
      !user.phoneNo
    ) {
      throw new Error(
        "phoneNo was not decrypted correctly"
      );
    }

    if (
      typeof user.orgCode !==
        "string" ||
      !user.orgCode
    ) {
      throw new Error(
        "orgCode was not returned correctly"
      );
    }

    if (
      !Array.isArray(
        user.roleCode
      )
    ) {
      throw new Error(
        "roleCode is not an array"
      );
    }

    // --------------------------------------------------
    // 7. Display non-sensitive compatibility summary
    // --------------------------------------------------

    console.log("");
    console.log(
      "USER FOUND"
    );

    console.log(
      "------------------------------------"
    );

    console.log(
      "User ID     :",
      user.userId
    );

    console.log(
      "User Code   :",
      user.userCode
    );

    console.log(
      "Org Code    :",
      user.orgCode
    );

    console.log(
      "User Type   :",
      user.userType
    );

    console.log(
      "Role Codes  :",
      user.roleCode
    );

    console.log(
      "Active Role :",
      user.activeRoleCode
    );

    console.log(
      "Active      :",
      user.isActive
    );

    console.log(
      "Email decrypted:",
      user.email === email
    );

    console.log(
      "Name decrypted:",
      Boolean(
        user.fullName
      )
    );

    console.log(
      "Phone decrypted:",
      Boolean(
        user.phoneNo
      )
    );

    console.log(
      "------------------------------------"
    );

    console.log("");

    console.log(
      "USER COMPATIBILITY PASSED"
    );
  } catch (error) {
    console.error("");

    console.error(
      "USER COMPATIBILITY FAILED"
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