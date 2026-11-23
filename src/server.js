/**
 * HTTP Server Entry Point
 */

import { app } from './app.js';
import { config } from './config.js';
import { authService } from './services/authService.js';

async function bootstrap() {
  try {
    // Seed initial demo accounts (alice and bob)
    await authService.seedDemoAccounts();
    console.log('[ArgonCore Demo] In-memory user store initialized with demo accounts.');

    const server = app.listen(config.port, () => {
      console.log(`====================================================`);
      console.log(` 🛡️  ArgonCore Integration Demo Application running`);
      console.log(` 🌐  Local URL: http://localhost:${config.port}`);
      console.log(` 📦  Package: argoncore@0.1.0`);
      console.log(` 📝  In-memory store ready for registration & login`);
      console.log(`====================================================`);
    });

    return server;
  } catch (err) {
    console.error('Fatal initialization error:', err);
    process.exit(1);
  }
}

bootstrap();
