import express from 'express';
import cors from 'cors';

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

app.use(
  cors({
    origin: config.clientOrigin,
  }),
);

app.use(express.json());

app.use('/api', healthRoutes);

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

app.use(notFound);
app.use(errorHandler);

export default app;