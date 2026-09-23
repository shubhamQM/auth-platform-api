import mongoose from 'mongoose';

import {
  connectDatabase,
  disconnectDatabase,
} from '../src/config/database.js';

import {
  config,
} from '../src/config/env.js';

import {
  createUserRepository,
} from '../src/repositories/user.repository.js';

import {
  verifyPassword,
} from '../src/security/passwordSecurity.js';

async function run() {
  try {
    console.log('');
    console.log('====================================');
    console.log('AUTH PASSWORD COMPATIBILITY TEST');
    console.log('====================================');

    // --------------------------------------------------
    // 1. Connect to shared userManagement database
    // --------------------------------------------------

    console.log('\nConnecting to userManagement...');

    await connectDatabase();

    console.log('Connected.');

    // --------------------------------------------------
    // 2. Create repository
    // --------------------------------------------------

    const repository = createUserRepository(
      config.encryption,
      mongoose.connection,
    );

    // --------------------------------------------------
    // 3. Test credentials
    // --------------------------------------------------

    const email = 'auth.employee@example.edu';
    const password = 'Employee@123';

    console.log(`\nSearching for: ${email}`);

    const user =
      await repository.findByEncryptedEmailWithPassword(
        email,
      );

    if (!user) {
      console.error('\nUSER NOT FOUND');
      process.exitCode = 1;
      return;
    }

    console.log('USER FOUND');

    // --------------------------------------------------
    // 4. Confirm password hash was explicitly retrieved
    // --------------------------------------------------

    if (
      typeof user.password !== 'string' ||
      !user.password
    ) {
      console.error('\nPASSWORD HASH NOT FOUND');
      process.exitCode = 1;
      return;
    }

    console.log('Password hash retrieved.');

    // Do not print the actual hash.
    console.log(
      'Argon2id hash:',
      user.password.startsWith('$argon2id$'),
    );

    // --------------------------------------------------
    // 5. Verify correct password
    // --------------------------------------------------

    const validPassword =
      await verifyPassword(
        password,
        user.password,
      );

    console.log(
      'Correct password verification:',
      validPassword,
    );

    // --------------------------------------------------
    // 6. Verify incorrect password is rejected
    // --------------------------------------------------

    const invalidPassword =
      await verifyPassword(
        'DefinitelyWrongPassword',
        user.password,
      );

    console.log(
      'Wrong password verification:',
      invalidPassword,
    );

    // --------------------------------------------------
    // 7. Final result
    // --------------------------------------------------

    if (
      validPassword !== true ||
      invalidPassword !== false
    ) {
      console.error('');
      console.error(
        'PASSWORD COMPATIBILITY FAILED',
      );

      process.exitCode = 1;
      return;
    }

    console.log('');
    console.log('------------------------------------');
    console.log('PASSWORD COMPATIBILITY PASSED');
    console.log('------------------------------------');
  } catch (error) {
    console.error('');
    console.error(
      'PASSWORD COMPATIBILITY FAILED',
    );

    console.error(error);

    process.exitCode = 1;
  } finally {
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