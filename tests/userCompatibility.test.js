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

async function run() {
  try {
    console.log('');
    console.log('====================================');
    console.log('AUTH USER COMPATIBILITY TEST');
    console.log('====================================');

    // --------------------------------------------------
    // 1. Connect to shared userManagement database
    // --------------------------------------------------

    console.log('\nConnecting to userManagement...');

    await connectDatabase();

    console.log('Connected.');

    // --------------------------------------------------
    // 2. Create repository with encryption configuration
    // --------------------------------------------------

    const repository = createUserRepository(
      config.encryption,
      mongoose.connection,
    );

    // --------------------------------------------------
    // 3. Search for User created by Marketing BE
    // --------------------------------------------------

    const email = 'auth.employee@example.edu';

    console.log(`\nSearching for: ${email}`);

    const user =
      await repository.findByEncryptedEmail(email);

    // --------------------------------------------------
    // 4. Check result
    // --------------------------------------------------

    if (!user) {
      console.error('');
      console.error('USER NOT FOUND');
      console.error(
        'Auth API could not locate the Marketing-created user.',
      );

      process.exitCode = 1;
      return;
    }

    // --------------------------------------------------
    // 5. Display decrypted User data
    // --------------------------------------------------

    console.log('');
    console.log('USER FOUND');
    console.log('------------------------------------');

    console.log('User ID :', user.userId);
    console.log('Email   :', user.email);
    console.log(
      'Name    :',
      `${user.firstName} ${user.lastName}`,
    );
    console.log('Type    :', user.userType);
    console.log('Roles   :', user.roleIds);
    console.log('Active  :', user.isActive);

    console.log('------------------------------------');

    console.log('');
    console.log(
      'Encryption compatibility PASSED',
    );
  } catch (error) {
    console.error('');
    console.error(
      'Encryption compatibility FAILED',
    );

    console.error(error);

    process.exitCode = 1;
  } finally {
    // --------------------------------------------------
    // 6. Always close MongoDB connection
    // --------------------------------------------------

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