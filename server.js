require('dotenv').config();
const fastify = require('fastify')({
  logger: {
    level: 'debug',
    prettyPrint: process.env.NODE_ENV !== 'production'
  }
});
const crypto = require('crypto');
const path = require('path');

// =============================================
// Configuration
// =============================================
const CONFIG = {
  PORT: process.env.PORT || 3000,
  PRIVATE_KEY: process.env.PRIVATE_KEY?.replace(/\\n/g, '\n'),
  RSA_PADDING: crypto.constants.RSA_PKCS1_PADDING,
  AES_ALGORITHM: 'aes-256-cbc',
  IV_LENGTH: 16 // bytes for AES-256-CBC
};

// =============================================
// Helper Functions
// =============================================
const validatePrivateKey = (key) => {
  if (!key) throw new Error('PRIVATE_KEY environment variable is missing');
  if (!key.includes('-----BEGIN PRIVATE KEY-----')) {
    throw new Error('Invalid private key format. Must be PEM encoded.');
  }
  return key;
};

const handleDecryptionError = (error, fastify) => {
  fastify.log.error(error);

  if (error.code === 'ERR_OSSL_RSA_PRIVKEY_DECRYPT') {
    return {
      statusCode: 400,
      response: {
        error: 'RSA_DECRYPTION_FAILED',
        message: 'Failed to decrypt symmetric key. The private key may not match the public key used for encryption.',
        details: error.message
      }
    };
  }

  if (error.code === 'ERR_OSSL_EVP_BAD_DECRYPT') {
    return {
      statusCode: 400,
      response: {
        error: 'AES_DECRYPTION_FAILED',
        message: 'Failed to decrypt payload. Check your encryption key, IV, and data format.',
        details: error.message
      }
    };
  }

  return {
    statusCode: 500,
    response: {
      error: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred during decryption',
      details: error.message
    }
  };
};

// =============================================
// Server Setup
// =============================================

// Validate configuration on startup
try {
  CONFIG.PRIVATE_KEY = validatePrivateKey(CONFIG.PRIVATE_KEY);
} catch (error) {
  fastify.log.error('Configuration error: ' + error.message);
  process.exit(1);
}

// Swagger documentation
fastify.register(require('@fastify/swagger'), {
  exposeRoute: true,
  routePrefix: '/documentation',
  swagger: {
    info: {
      title: 'Salesforce Decryption Microservice',
      description: 'Decrypts payloads encrypted with RSA/ECB/PKCS1Padding and AES-256-CBC',
      version: '1.0.0'
    },
    host: `localhost:${CONFIG.PORT}`,
    schemes: ['http'],
    consumes: ['application/json'],
    produces: ['application/json'],
  }
});

fastify.register(require('@fastify/swagger-ui'), {
  routePrefix: '/documentation',
  uiConfig: {
    docExpansion: 'full'
  }
});

// =============================================
// Decryption Endpoint
// =============================================
fastify.post('/decrypt', {
  schema: {
    body: {
      type: 'object',
      required: ['encryptedKey', 'encryptedData'],
      properties: {
        encryptedKey: { 
          type: 'string', 
          description: 'Base64-encoded RSA-encrypted AES key (PKCS1 padding)' 
        },
        encryptedData: { 
          type: 'string', 
          description: 'Base64-encoded AES-256-CBC encrypted payload' 
        },
        iv: { 
          type: 'string', 
          default: '', 
          description: 'Base64-encoded initialization vector (16 bytes). If empty, uses zero IV.' 
        }
      }
    },
    response: {
      200: {
        type: 'object',
        description: 'Decrypted payload'
      },
      400: {
        type: 'object',
        properties: {
          error: { type: 'string' },
          message: { type: 'string' },
          details: { type: 'string' }
        }
      },
      500: {
        type: 'object',
        properties: {
          error: { type: 'string' },
          message: { type: 'string' },
          details: { type: 'string' }
        }
      }
    }
  }
}, async (request, reply) => {
  const { encryptedKey, encryptedData, iv } = request.body;

  try {
    // 1. Decrypt the AES key
    fastify.log.debug('Starting RSA decryption...');
    const decryptedSymmetricKey = crypto.privateDecrypt(
      {
        key: CONFIG.PRIVATE_KEY,
        padding: CONFIG.RSA_PADDING
      },
      Buffer.from(encryptedKey, 'base64')
    );

    // 2. Prepare IV
    const ivBuffer = iv 
      ? Buffer.from(iv, 'base64')
      : Buffer.alloc(CONFIG.IV_LENGTH); // Zero-filled IV if not provided

    // 3. Decrypt the payload
    fastify.log.debug('Starting AES decryption...');
    const decipher = crypto.createDecipheriv(
      CONFIG.AES_ALGORITHM,
      decryptedSymmetricKey,
      ivBuffer
    );
    
    let decryptedData = decipher.update(encryptedData, 'base64', 'utf8');
    decryptedData += decipher.final('utf8');

    // 4. Parse JSON
    fastify.log.debug('Parsing decrypted JSON...');
    const result = JSON.parse(decryptedData);
    
    reply.send(result);

  } catch (error) {
    const { statusCode, response } = handleDecryptionError(error, fastify);
    reply.status(statusCode).send(response);
  }
});

// =============================================
// Health Check Endpoint
// =============================================
fastify.get('/health', async () => {
  return { status: 'ok', timestamp: new Date().toISOString() };
});

// =============================================
// Start Server
// =============================================
const start = async () => {
  try {
    await fastify.listen({ 
      port: CONFIG.PORT, 
      host: '0.0.0.0' 
    });
    fastify.log.info(`Server running on http://localhost:${CONFIG.PORT}`);
    fastify.log.info(`Swagger docs at http://localhost:${CONFIG.PORT}/documentation`);
  } catch (err) {
    fastify.log.error('Server startup error:', err);
    process.exit(1);
  }
};

start();