require('dotenv').config();
const fastify = require('fastify')({
  logger: true
});
const crypto = require('crypto');

// Swagger configuration
fastify.register(require('@fastify/swagger'), {
  exposeRoute: true,
  routePrefix: '/documentation',
  swagger: {
    info: {
      title: 'Salesforce Decryption Microservice',
      description: 'API for decrypting RSA-encrypted data from Salesforce using RSA/ECB/PKCS1Padding',
      version: '1.0.0'
    },
    host: 'localhost:3000',
    schemes: ['http'],
    consumes: ['application/json'],
    produces: ['application/json'],
  }
});

fastify.register(require('@fastify/swagger-ui'), {
  routePrefix: '/documentation',
  uiConfig: {
    docExpansion: 'full',
    deepLinking: false
  },
  staticCSP: true
});

// Validate private key on startup
const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY?.replace(/\\n/g, '\n');

if (!PRIVATE_KEY_PEM || !PRIVATE_KEY_PEM.includes('-----BEGIN PRIVATE KEY-----')) {
  fastify.log.error('Invalid PRIVATE_KEY environment variable. Must be a valid PEM-formatted private key.');
  process.exit(1);
}

// Decryption endpoint
fastify.post('/decrypt', {
  schema: {
    body: {
      type: 'object',
      required: ['encryptedKey', 'encryptedData'],
      properties: {
        requestId: { type: 'string' },
        service: { type: 'string' },
        encryptedKey: { 
          type: 'string', 
          description: 'RSA encrypted symmetric key (using RSA/ECB/PKCS1Padding)' 
        },
        encryptedData: { 
          type: 'string', 
          description: 'AES-256-CBC encrypted data payload' 
        },
        oaepHashingAlgorithm: { 
          type: 'string', 
          default: 'NONE', 
          description: 'Ignored (using PKCS1 padding)' 
        },
        iv: { 
          type: 'string', 
          default: '', 
          description: 'Initialization Vector for AES decryption (if empty, uses zero IV)' 
        },
        clientInfo: { type: 'string' },
        optionalParam: { type: 'string' }
      }
    },
    response: {
      200: {
        type: 'object',
        description: 'Successfully decrypted plain request data'
      },
      400: {
        type: 'object',
        properties: {
          error: { type: 'string' },
          message: { type: 'string' }
        }
      },
      500: {
        type: 'object',
        properties: {
          error: { type: 'string' },
          message: { type: 'string' }
        }
      }
    }
  }
}, async (request, reply) => {
  const { encryptedKey, encryptedData, iv } = request.body;

  try {
    // 1. Decrypt the AES key using RSA with PKCS1 padding
    const decryptedSymmetricKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY_PEM,
        padding: crypto.constants.RSA_PKCS1_PADDING
      },
      Buffer.from(encryptedKey, 'base64')
    );

    // 2. Prepare IV (use zero-filled buffer if not provided)
    const ivBuffer = iv 
      ? Buffer.from(iv, 'base64') 
      : Buffer.alloc(16); // 16 zero bytes for AES-256-CBC

    // 3. Decrypt the data using AES-256-CBC
    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      decryptedSymmetricKey,
      ivBuffer
    );

    let decryptedData = decipher.update(encryptedData, 'base64', 'utf8');
    decryptedData += decipher.final('utf8');

    // 4. Parse and return the decrypted JSON
    const plainRequest = JSON.parse(decryptedData);
    reply.send(plainRequest);

  } catch (error) {
    fastify.log.error('Decryption error:', error);
    
    if (error.code === 'ERR_OSSL_RSA_PRIVKEY_DECRYPT') {
      reply.status(400).send({ 
        error: 'RSA_DECRYPTION_FAILED', 
        message: 'Failed to decrypt symmetric key. Check private key or encrypted key format.' 
      });
    } else if (error.code === 'ERR_OSSL_EVP_BAD_DECRYPT') {
      reply.status(400).send({ 
        error: 'AES_DECRYPTION_FAILED', 
        message: 'Failed to decrypt data. Check symmetric key, IV, or encrypted data format.' 
      });
    } else if (error instanceof SyntaxError) {
      reply.status(400).send({ 
        error: 'INVALID_JSON', 
        message: 'Decrypted data is not valid JSON.' 
      });
    } else {
      reply.status(500).send({ 
        error: 'INTERNAL_ERROR', 
        message: 'An unexpected error occurred during decryption.' 
      });
    }
  }
});

// Start server
const start = async () => {
  try {
    const port = process.env.PORT || 3000;
    await fastify.listen({ port, host: '0.0.0.0' });
    fastify.log.info(`Server listening on port ${port}`);
    fastify.log.info(`Swagger UI available at http://localhost:${port}/documentation`);
  } catch (err) {
    fastify.log.error('Server startup error:', err);
    process.exit(1);
  }
};

start();