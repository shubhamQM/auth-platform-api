import mongoose from 'mongoose';
import { config } from './env.js';

export async function connectDatabase() {
  try {
    await mongoose.connect(config.userMongoUri, {
      autoCreate: false,
      autoIndex: false,
      serverSelectionTimeoutMS: 10000,
    });
  } catch {
    // Do not include the URI or driver error, which may contain credentials.
    throw new Error(
      'MongoDB connection failed. Check USER_MONGO_URI, MongoDB availability, network access, and credentials.',
    );
  }
}

export async function disconnectDatabase() {
  await mongoose.disconnect();
}
