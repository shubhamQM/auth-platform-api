import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';

import { config } from './config/env.js';
import healthRoutes from './routes/health.routes.js';
import { createAuthRouter } from './createAuthRouter.js';

import {
  notFound,
} from './middleware/not-found.middleware.js';

import {
  errorHandler,
} from './middleware/error.middleware.js';

const app = express();

// --------------------------------------------------
// CORS
// --------------------------------------------------

app.use(
  cors({
    origin: config.clientOrigin,
    credentials: true,
  }),
);

// --------------------------------------------------
// Request parsing
// --------------------------------------------------

app.use(express.json());
app.use(cookieParser());

// --------------------------------------------------
// Health routes
// --------------------------------------------------

app.use('/api', healthRoutes);

// --------------------------------------------------
// Authentication routes
// --------------------------------------------------

app.use(
  '/api/auth',
  createAuthRouter({
    ...config.encryption,

    captchaSecretKey:
      config.captcha.secretKey,

    authentication:
      config.authentication,

    twoFactor:
      config.twoFactor,
  }),
);

// --------------------------------------------------
// Error handling
// --------------------------------------------------

app.use(notFound);
app.use(errorHandler);

export default app;