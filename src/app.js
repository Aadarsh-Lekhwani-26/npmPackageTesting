/**
 * Express Application Setup
 */

import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { authRouter } from './routes/authRoutes.js';
import { demoRouter } from './routes/demoRoutes.js';
import { errorHandler } from './middleware/errorHandler.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.join(__dirname, '..', 'public');

export const app = express();

// Body parser middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend files
app.use(express.static(publicDir));

// API Mount Points
app.use('/api/auth', authRouter);
app.use('/api/demo', demoRouter);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    package: 'argoncore',
    version: '0.1.0',
    timestamp: new Date().toISOString()
  });
});

// Centralized error handling
app.use(errorHandler);
