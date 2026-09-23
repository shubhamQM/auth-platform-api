import app from './app.js';
import { config } from './config/env.js';
import { connectDatabase, disconnectDatabase } from './config/database.js';

try {
  await connectDatabase();
  console.log('MongoDB connection established');

  await new Promise((resolve, reject) => {
    const server = app.listen(config.port, resolve);
    server.once('error', reject);
  });
  console.log(`Auth Platform API is listening on port ${config.port}`);
} catch (error) {
  console.error('Failed to start Auth Platform API:', error.message);
  await disconnectDatabase();
  process.exitCode = 1;
}
