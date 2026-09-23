import { normalizeConfig } from './config/normalizeConfig.js';
import { createAuthRoutes } from './routes/auth/auth.routes.js';

export function createAuthRouter(options = {}) {
  const config = normalizeConfig(options);
  return createAuthRoutes(config);
}
