import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();

// Define quantum-resistant cryptography config schema with Zod
const quantumConfigSchema = z.object({
  defaultAlgorithm: z
    .enum(['dilithium', 'falcon', 'kyber', 'ntru', 'hybrid-rsa-dilithium', 'hybrid-ec-kyber'])
    .default('hybrid-rsa-dilithium'),
  defaultHashAlgorithm: z
    .enum(['sha3-256', 'sha3-384', 'sha3-512', 'shake128', 'shake256'])
    .default('sha3-256'),
  defaultKdfAlgorithm: z.enum(['argon2id', 'pbkdf2-sha3-512']).default('argon2id'),
  kdf: z.object({
    iterations: z.number().int().positive().default(100000),
    keyLength: z.number().int().positive().default(32),
    memoryCost: z.number().int().positive().default(65536), // 64 MB
    parallelism: z.number().int().positive().default(4),
  }),
  signature: z.object({
    dilithium: z.object({
      securityLevel: z.enum(['2', '3', '5']).default('3'),
    }),
    falcon: z.object({
      securityLevel: z.enum(['512', '1024']).default('1024'),
    }),
  }),
  encryption: z.object({
    kyber: z.object({
      securityLevel: z.enum(['512', '768', '1024']).default('768'),
    }),
    ntru: z.object({
      securityLevel: z
        .enum(['hrss701', 'hps2048509', 'hps2048677', 'hps4096821'])
        .default('hps2048677'),
    }),
  }),
  hybrid: z.object({
    enabled: z.boolean().default(true),
    signatureCombinations: z
      .array(
        z.object({
          name: z.string(),
          classical: z.string(),
          quantum: z.string(),
        })
      )
      .default([
        {
          name: 'hybrid-rsa-dilithium',
          classical: 'rsa',
          quantum: 'dilithium',
        },
        {
          name: 'hybrid-ec-falcon',
          classical: 'ec',
          quantum: 'falcon',
        },
      ]),
    encryptionCombinations: z
      .array(
        z.object({
          name: z.string(),
          classical: z.string(),
          quantum: z.string(),
        })
      )
      .default([
        {
          name: 'hybrid-rsa-kyber',
          classical: 'rsa',
          quantum: 'kyber',
        },
        {
          name: 'hybrid-ec-ntru',
          classical: 'ec',
          quantum: 'ntru',
        },
      ]),
  }),
  migration: z.object({
    enabled: z.boolean().default(true),
    phases: z
      .array(
        z.object({
          name: z.string(),
          description: z.string(),
          status: z.enum(['planned', 'active', 'completed']),
        })
      )
      .default([
        {
          name: 'preparation',
          description: 'Prepare for migration by implementing crypto-agility',
          status: 'completed',
        },
        {
          name: 'hybrid',
          description: 'Use hybrid classical and post-quantum algorithms',
          status: 'active',
        },
        {
          name: 'post-quantum',
          description: 'Transition to post-quantum algorithms only',
          status: 'planned',
        },
      ]),
    timeline: z.object({
      hybridPhaseStart: z.string().default('2023-01-01'),
      postQuantumPhaseTarget: z.string().default('2025-01-01'),
    }),
  }),
  cryptoAgility: z.object({
    enableNegotiation: z.boolean().default(true),
    enableVersioning: z.boolean().default(true),
    enableRotation: z.boolean().default(true),
    enableFallback: z.boolean().default(true),
    supportedAlgorithms: z
      .array(z.string())
      .default([
        'rsa',
        'ec',
        'dilithium',
        'falcon',
        'kyber',
        'ntru',
        'hybrid-rsa-dilithium',
        'hybrid-ec-falcon',
        'hybrid-rsa-kyber',
        'hybrid-ec-ntru',
      ]),
  }),
});

// Parse and validate environment variables
const rawConfig = {
  defaultAlgorithm: env.get('QUANTUM_DEFAULT_ALGORITHM') as any,
  defaultHashAlgorithm: env.get('QUANTUM_DEFAULT_HASH_ALGORITHM') as any,
  defaultKdfAlgorithm: env.get('QUANTUM_DEFAULT_KDF_ALGORITHM') as any,
  kdf: {
    iterations: env.getNumber('QUANTUM_KDF_ITERATIONS'),
    keyLength: env.getNumber('QUANTUM_KDF_KEY_LENGTH'),
    memoryCost: env.getNumber('QUANTUM_KDF_MEMORY_COST'),
    parallelism: env.getNumber('QUANTUM_KDF_PARALLELISM'),
  },
  signature: {
    dilithium: {
      securityLevel: env.get('QUANTUM_DILITHIUM_SECURITY_LEVEL') as any,
    },
    falcon: {
      securityLevel: env.get('QUANTUM_FALCON_SECURITY_LEVEL') as any,
    },
  },
  encryption: {
    kyber: {
      securityLevel: env.get('QUANTUM_KYBER_SECURITY_LEVEL') as any,
    },
    ntru: {
      securityLevel: env.get('QUANTUM_NTRU_SECURITY_LEVEL') as any,
    },
  },
  hybrid: {
    enabled: env.getBoolean('QUANTUM_HYBRID_ENABLED'),
    signatureCombinations: env.get('QUANTUM_HYBRID_SIGNATURE_COMBINATIONS')
      ? JSON.parse(env.get('QUANTUM_HYBRID_SIGNATURE_COMBINATIONS') as string)
      : undefined,
    encryptionCombinations: env.get('QUANTUM_HYBRID_ENCRYPTION_COMBINATIONS')
      ? JSON.parse(env.get('QUANTUM_HYBRID_ENCRYPTION_COMBINATIONS') as string)
      : undefined,
  },
  migration: {
    enabled: env.getBoolean('QUANTUM_MIGRATION_ENABLED'),
    phases: env.get('QUANTUM_MIGRATION_PHASES')
      ? JSON.parse(env.get('QUANTUM_MIGRATION_PHASES') as string)
      : undefined,
    timeline: {
      hybridPhaseStart: env.get('QUANTUM_MIGRATION_HYBRID_PHASE_START'),
      postQuantumPhaseTarget: env.get('QUANTUM_MIGRATION_POST_QUANTUM_PHASE_TARGET'),
    },
  },
  cryptoAgility: {
    enableNegotiation: env.getBoolean('QUANTUM_CRYPTO_AGILITY_ENABLE_NEGOTIATION'),
    enableVersioning: env.getBoolean('QUANTUM_CRYPTO_AGILITY_ENABLE_VERSIONING'),
    enableRotation: env.getBoolean('QUANTUM_CRYPTO_AGILITY_ENABLE_ROTATION'),
    enableFallback: env.getBoolean('QUANTUM_CRYPTO_AGILITY_ENABLE_FALLBACK'),
    supportedAlgorithms: env.get('QUANTUM_CRYPTO_AGILITY_SUPPORTED_ALGORITHMS')?.split(','),
  },
};

// Validate and export config
export const quantumConfig = validateConfig(quantumConfigSchema, rawConfig);

// Export config type
export type QuantumConfig = typeof quantumConfig;
