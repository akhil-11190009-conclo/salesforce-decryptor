// server.js

require('dotenv').config();

const fastify = require('fastify')({
  logger: true
});
const crypto = require('crypto');

fastify.register(require('@fastify/swagger'), {
  exposeRoute: true,
  routePrefix: '/documentation',
  swagger: {
    info: {
      title: 'Salesforce Decryption Microservice',
      description: 'API for decrypting RSA-encrypted data from Salesforce.',
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
  uiHooks: {
    onRequest: function (request, reply, next) { next() },
    preHandler: function (request, reply, next) { next() }
  },
  staticCSP: true,
  transformStaticCSP: (header) => header,
  transformSpecification: (swaggerObject, request, reply) => { return swaggerObject },
  transformSpecificationClone: true
});

const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY;

if (!PRIVATE_KEY_PEM || PRIVATE_KEY_PEM.trim().length < 100) {
  fastify.log.error('PRIVATE_KEY environment variable is missing or too short. Please set it securely.');
  process.exit(1);
}

fastify.post('/decrypt', {
  schema: {
    body: {
      type: 'object',
      required: ['encryptedKey', 'encryptedData', 'iv'],
      properties: {
        requestId: { type: 'string' },
        service: { type: 'string' },
        encryptedKey: { type: 'string', description: 'RSA encrypted symmetric key (e.g., AES key)' },
        encryptedData: { type: 'string', description: 'Symmetric encrypted data payload' },
        oaepHashingAlgorithm: { type: 'string', default: 'NONE', description: 'Hashing algorithm for OAEP padding (ignored if PKCS1)' },
        iv: { type: 'string', description: 'Initialization Vector for symmetric decryption' },
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
  const { encryptedKey, encryptedData, iv, oaepHashingAlgorithm } = request.body;

  try {
    // Step 1: Decrypt the symmetric key using the RSA private key
    // CHANGED: Using RSA_PKCS1_OAEP_PADDING instead of RSA_PKCS1_PADDING
    // If the original encryption used PKCS1_PADDING, this will fail.
    // The sender's encryption method MUST match this padding.
    const decryptedSymmetricKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY_PEM,
        // Use OAEP padding. You might need to specify hash (e.g., 'sha256')
        // if the sender used a specific hash with OAEP.
        // For 'NONE' in your sample, PKCS1_OAEP_PADDING is the secure replacement.
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256' // Common default for OAEP, or match sender's hash
      },
      Buffer.from(encryptedKey, 'base64')
    );

    // Step 2: Decrypt the main data payload using the decrypted symmetric key and IV
    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      decryptedSymmetricKey,
      Buffer.from(iv, 'base64')
    );

    let decryptedData = decipher.update(encryptedData, 'base64', 'utf8');
    decryptedData += decipher.final('utf8');

    const plainRequest = JSON.parse(decryptedData);

    reply.send(plainRequest);

  } catch (error) {
    fastify.log.error('Decryption error:', error.message);
    if (error.code === 'ERR_OSSL_RSA_PRIVKEY_DECRYPT' || error.message.includes('padding')) {
        reply.status(400).send({ error: 'DecryptionFailed', message: 'RSA private key decryption failed. Check key, padding (now OAEP), or encryptedKey format. Error: ' + error.message });
    } else if (error.code === 'ERR_OSSL_EVP_DECRYPT_NOT_INITIALIZED' || error.code === 'ERR_OSSL_EVP_DECRYPT_FINAL') {
        reply.status(400).send({ error: 'DecryptionFailed', message: 'Symmetric decryption failed. Check key, IV, or encryptedData format. Error: ' + error.message });
    } else if (error.name === 'SyntaxError') {
        reply.status(400).send({ error: 'InvalidJsonFormat', message: 'Decrypted data is not valid JSON. Error: ' + error.message });
    } else {
        reply.status(500).send({ error: 'InternalServerError', message: error.message });
    }
  }
});

const start = async () => {
  try {
    const port = process.env.PORT || 3000;
    await fastify.listen({ port: port, host: '0.0.0.0' });
    fastify.log.info(`Server listening on port ${fastify.server.address().port}`);
    fastify.log.info(`Swagger documentation available at http://localhost:${port}/documentation`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
