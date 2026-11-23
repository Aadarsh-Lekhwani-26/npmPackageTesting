/**
 * Application Configuration & Security Parameter Profiles
 *
 * Defines Argon2 parameter presets suitable for various deployment tiers,
 * from fast interactive testing to RFC 9106 recommended maximums.
 */

export const PROFILES = {
  testing: {
    id: 'testing',
    name: 'Ultra Fast (Testing / CI)',
    memoryCost: 256, // 256 KiB
    timeCost: 1,
    parallelism: 1,
    description: 'Minimal latency (~25ms). Ideal for automated unit testing and rapid iteration.'
  },
  interactive: {
    id: 'interactive',
    name: 'Interactive Demo (Recommended)',
    memoryCost: 1024, // 1 MiB (1024 KiB)
    timeCost: 1,
    parallelism: 1,
    description: 'Fast responsive authentication (~45ms) providing excellent UX in browser demos.'
  },
  microservice: {
    id: 'microservice',
    name: 'Microservice Balanced',
    memoryCost: 4096, // 4 MiB (4096 KiB)
    timeCost: 2,
    parallelism: 2,
    description: 'Moderate memory hardness (~350ms). Balanced security for containerized services.'
  },
  owasp: {
    id: 'owasp',
    name: 'OWASP Recommended Minimum',
    memoryCost: 19456, // ~19 MiB
    timeCost: 2,
    parallelism: 1,
    description: 'Standard enterprise recommendation (~1.7s). Strong GPU attack resistance.'
  },
  rfc9106: {
    id: 'rfc9106',
    name: 'RFC 9106 Default',
    memoryCost: 65536, // 64 MiB
    timeCost: 3,
    parallelism: 4,
    description: 'Maximum security profile (~8.4s pure JS). Used on dedicated high-memory auth servers.'
  }
};

export const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  defaultProfile: 'interactive',
  // Active policy used by server to evaluate needsRehash()
  activePolicy: {
    memoryCost: 1024,
    timeCost: 1,
    parallelism: 1,
    version: 0x13
  }
};
