// server.js

// Load environment variables from .env file (for local development)
require('dotenv').config();

const fastify = require('fastify')({
  logger: true // Enable logging for requests
});
const crypto = require('crypto'); // Node.js built-in crypto module

// Register Fastify Swagger for API documentation (optional, but good practice)
fastify.register(require('@fastify/swagger'), {
  exposeRoute: true,
  routePrefix: '/documentation',
  swagger: {
    info: {
      title: 'Salesforce Decryption Microservice',
      description: 'API for decrypting RSA-encrypted data from Salesforce.',
      version: '1.0.0'
    },
    host: 'localhost:3000', // This will be overridden by Render's URL in production
    schemes: ['http'], // Use https in production (Render handles this)
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


// --- IMPORTANT: RSA PRIVATE KEY CONFIGURATION ---
// The private key is loaded from the PRIVATE_KEY environment variable.
// For local testing, this comes from the .env file.
// For Render deployment, this comes from Render's Config Vars.
// This constant MUST be defined at the top level of the module.
const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY;

// Basic validation for the private key
if (!PRIVATE_KEY_PEM || PRIVATE_KEY_PEM.trim().length < 100) {
  fastify.log.error('PRIVATE_KEY environment variable is missing or too short. Please set it securely in .env (local) or Render Config Vars (production).');
  process.exit(1); // Exit if key is not set for security
}

// Decryption endpoint
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
        type: 'object', // Assuming the decrypted data is a JSON object
        description: 'Successfully decrypted plain request data'
        // You might want to define the exact schema of your Plain Request here
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
    // Using RSA_PKCS1_PADDING for compatibility with older Node.js versions
    // and potentially the sender's encryption method.
    // This requires Node.js 18 or older on Render.
    const decryptedSymmetricKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY_PEM,
        padding: crypto.constants.RSA_PKCS1_PADDING, // Reverted to PKCS1 padding
      },
      Buffer.from(encryptedKey, 'base64')
    );

    // Step 2: Decrypt the main data payload using the decrypted symmetric key and IV
    // Assuming AES-256-CBC, which is a common and secure choice with an IV.
    // The encryptedData and IV are typically Base64 encoded.
    // IMPORTANT: If 'iv' is an empty string in the incoming request, this will likely fail.
    // A proper IV is required for AES-256-CBC.
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
    if (error.code === 'ERR_OSSL_RSA_PRIVKEY_DECRYPT' || error.message.includes('padding') || error.message.includes('data greater than mod len')) {
        reply.status(400).send({ error: 'DecryptionFailed', message: 'RSA private key decryption failed. Check key, padding (expected PKCS1), or encryptedKey format. Error: ' + error.message });
    } else if (error.code === 'ERR_OSSL_EVP_DECRYPT_NOT_INITIALIZED' || error.code === 'ERR_OSSL_EVP_DECRYPT_FINAL' || error.message.includes('bad decrypt') || error.message.includes('invalid iv')) {
        reply.status(400).send({ error: 'DecryptionFailed', message: 'Symmetric decryption failed. Check key, IV (must not be empty for CBC), or encryptedData format. Error: ' + error.message });
    } else if (error.name === 'SyntaxError') {
        reply.status(400).send({ error: 'InvalidJsonFormat', message: 'Decrypted data is not valid JSON. Error: ' + error.message });
    } else {
        reply.status(500).send({ error: 'InternalServerError', message: error.message });
    }
  }
});

// Start the server
const start = async () => {
  try {
    // Render assigns a PORT environment variable dynamically
    const port = process.env.PORT || 3000;
    await fastify.listen({ port: port, host: '0.0.0.0' }); // Listen on all interfaces
    fastify.log.info(`Server listening on port ${fastify.server.address().port}`);
    fastify.log.info(`Swagger documentation available at http://localhost:${port}/documentation`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
