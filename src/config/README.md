# Configuration System

This module provides a comprehensive, type-safe configuration system for the World-Class-Authentication platform. It centralizes all application settings with strong validation, sensible defaults, and clear documentation.

## Key Features

- **Type Safety**: All configuration is strongly typed using TypeScript and validated with Zod schemas
- **Environment-Based Configuration**: Automatically loads the right configuration based on the current environment
- **Validation**: Comprehensive validation with helpful error messages
- **Default Values**: Sensible defaults for all configuration options
- **Domain-Specific Modules**: Configuration is organized by domain for better maintainability
- **Documentation**: Well-documented configuration options with clear descriptions

## Usage

### Basic Usage

```typescript
import { appConfig, securityConfig } from '../config';

// Access configuration values
const port = appConfig.app.port;
const jwtSecret = securityConfig.jwt.accessTokenSecret;

// Use environment helpers
import { env, isDevelopment } from '../config';

if (isDevelopment()) {
  // Development-specific code
}

// Direct access to environment variables (with type safety)
const customValue = env.get('CUSTOM_VARIABLE');
const customNumber = env.getNumber('CUSTOM_NUMBER');
const customBoolean = env.getBoolean('CUSTOM_FLAG');
```

### Available Configuration Modules

- **appConfig**: Core application settings (name, port, API prefix, etc.)
- **securityConfig**: Security settings (JWT, password policies, sessions, etc.)
- **dbConfig**: Database connection settings (PostgreSQL, Redis)
- **auditConfig**: Audit logging configuration
- **complianceConfig**: Regulatory compliance settings (GDPR, CCPA, HIPAA, etc.)
- **mfaConfig**: Multi-factor authentication settings
- **oauthConfig**: OAuth/OpenID Connect configuration
- **performanceConfig**: Performance optimization settings
- **quantumConfig**: Quantum-resistant cryptography settings
- **recoveryConfig**: Account recovery configuration
- **riskConfig**: Risk assessment and adaptive authentication
- **samlConfig**: SAML identity provider configuration

## Environment Variables

The configuration system loads environment variables from:

1. `.env` - Base configuration for all environments
2. `.env.[environment]` - Environment-specific configuration (e.g., `.env.development`)
3. `.env.[environment].local` - Local overrides (not committed to version control)

See the `.env.example` file in the project root for all available configuration options.

## Adding New Configuration

To add a new configuration module:

1. Create a new file in the `src/config` directory (e.g., `new-feature-config.ts`)
2. Define a Zod schema for validation
3. Parse and validate environment variables
4. Export the validated configuration
5. Add the new configuration to `src/config/index.ts`

Example:

```typescript
import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();

// Define schema with Zod
const newFeatureConfigSchema = z.object({
  enabled: z.boolean().default(false),
  timeout: z.number().int().positive().default(30000),
  // Add more configuration options...
});

// Parse and validate environment variables
const rawConfig = {
  enabled: env.getBoolean('NEW_FEATURE_ENABLED'),
  timeout: env.getNumber('NEW_FEATURE_TIMEOUT'),
  // Add more environment variables...
};

// Validate and export config
export const newFeatureConfig = validateConfig(newFeatureConfigSchema, rawConfig);

// Export config type
export type NewFeatureConfig = typeof newFeatureConfig;
```

## Best Practices

1. **Always provide defaults**: Every configuration option should have a sensible default
2. **Document with comments**: Add descriptive comments for each configuration option
3. **Use appropriate types**: Choose the right Zod validators for each setting
4. **Group related settings**: Organize settings into logical objects
5. **Validate thoroughly**: Add constraints like min/max for numbers, patterns for strings
6. **Keep modules focused**: Each configuration file should cover a specific domain
7. **Update .env.example**: Document new environment variables in the example file
