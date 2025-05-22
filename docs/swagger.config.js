module.exports = {
  openapi: '3.0.0',
  info: {
    title: 'World-Class Authentication API',
    version: '1.0.0',
    description: 'API documentation for the World-Class Authentication system',
    license: {
      name: 'MIT',
      url: 'https://opensource.org/licenses/MIT',
    },
    contact: {
      name: 'API Support',
      url: 'https://github.com/yourusername/world-class-authentication',
      email: 'support@example.com',
    },
  },
  servers: [
    {
      url: 'http://localhost:3000/api/v1',
      description: 'Development server',
    },
    {
      url: 'https://api.example.com/v1',
      description: 'Production server',
    },
  ],
  tags: [
    {
      name: 'Authentication',
      description: 'Authentication endpoints',
    },
    {
      name: 'Users',
      description: 'User management endpoints',
    },
    {
      name: 'MFA',
      description: 'Multi-factor authentication endpoints',
    },
    {
      name: 'OAuth',
      description: 'OAuth and SSO endpoints',
    },
    {
      name: 'Recovery',
      description: 'Account recovery endpoints',
    },
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
    },
    schemas: {
      Error: {
        type: 'object',
        properties: {
          error: {
            type: 'string',
          },
          message: {
            type: 'string',
          },
          statusCode: {
            type: 'integer',
          },
        },
      },
    },
  },
  security: [
    {
      bearerAuth: [],
    },
  ],
  paths: {},
};
