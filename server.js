require('dotenv').config();
const fastify = require('fastify')({
  logger: {
    level: 'debug',
    // Only use pino-pretty for pretty printing in non-production environments
    ...(process.env.NODE_ENV !== 'production' && {
      transport: {
        target: 'pino-pretty'
      },
    }),
  }
});
const crypto = require('crypto');
const { spawn } = require('child_process');

const CONFIG = {
  PORT: process.env.PORT || 3000,
  PRIVATE_KEY: process.env.PRIVATE_KEY?.replace(/\\n/g, '\n'), // Private key string for Java
  AES_ALGORITHM: 'aes-256-cbc',
  IV_LENGTH: 16 // AES-256-CBC always uses a 16-byte IV
};

/**
 * Validates that the PRIVATE_KEY environment variable is present and in a basic PEM format.
 * This is a preliminary check as the full validation occurs in the Java process.
 * @param {string | undefined} key The private key string from environment variables.
 * @returns {string} The validated private key string.
 * @throws {Error} If the private key is missing or not in a basic PEM format.
 */
const validatePrivateKey = (key) => {
  if (!key) {
    throw new Error('PRIVATE_KEY environment variable is missing. It is required for RSA decryption.');
  }
  // Basic check for PEM header
  if (!key.includes('-----BEGIN PRIVATE KEY-----') && !key.includes('-----BEGIN RSA PRIVATE KEY-----')) {
    throw new Error('Invalid private key format. Must be PEM encoded (e.g., PKCS#1 or PKCS#8 format).');
  }
  return key;
};

/**
 * Handles decryption-related errors and returns an appropriate HTTP response object.
 * Provides more specific error messages based on the type of decryption failure.
 * @param {Error} error The error object from the try-catch block.
 * @param {object} fastify The Fastify instance for logging.
 * @returns {{statusCode: number, response: object}} An object containing the HTTP status code and response body.
 */
const handleDecryptionError = (error, fastify) => {
  fastify.log.error(error); // Log the full error for debugging

  // Error originating from the Java child process
  if (error.message.startsWith('Java decryption failed:')) {
    return {
      statusCode: 500, // Using 500 because it's a backend execution failure
      response: {
        error: 'JAVA_RSA_DECRYPTION_FAILED',
        message: 'The Java process failed to decrypt the symmetric key. Check Java logs for details.',
        details: error.message // This should contain the stderr from Java
      }
    };
  }

  // Error during Node.js AES decryption
  // ERR_OSSL_EVP_BAD_DECRYPT usually means incorrect key, IV, or corrupted ciphertext
  if (error.code === 'ERR_OSSL_EVP_BAD_DECRYPT') {
    return {
      statusCode: 400,
      response: {
        error: 'AES_DECRYPTION_FAILED',
        message: 'Failed to decrypt payload using AES-256-CBC. Check your encryptedData, decrypted symmetric key, and IV.',
        details: error.message
      }
    };
  }

  // Error during JSON parsing of the decrypted payload
  if (error instanceof SyntaxError && error.message.includes('JSON')) {
    return {
      statusCode: 400,
      response: {
        error: 'INVALID_DECRYPTED_PAYLOAD_FORMAT',
        message: 'The decrypted data is not a valid JSON string. Ensure the original payload was JSON.',
        details: error.message
      }
    };
  }

  // Catch-all for any other unexpected errors
  return {
    statusCode: 500,
    response: {
      error: 'INTERNAL_SERVER_ERROR',
      message: 'An unexpected error occurred during the decryption process.',
      details: error.message
    }
  };
};

// Validate private key at application startup
try {
  CONFIG.PRIVATE_KEY = validatePrivateKey(CONFIG.PRIVATE_KEY);
} catch (error) {
  fastify.log.error('Configuration error: ' + error.message);
  process.exit(1); // Exit if the private key is not correctly configured
}

// Register Swagger documentation plugins
fastify.register(require('@fastify/swagger'), {
  exposeRoute: true,
  routePrefix: '/documentation',
  swagger: {
    info: {
      title: 'Salesforce Decryption Microservice',
      description: 'Decrypts AES key (RSA/ECB/PKCS1Padding in Java) and payload (AES-256-CBC in Node.js)',
      version: '1.0.0'
    },
    // Dynamically set host for Render deployment if needed, otherwise localhost
    host: `localhost:${CONFIG.PORT}`,
    schemes: ['http'],
    consumes: ['application/json'],
    produces: ['application/json']
  }
});

fastify.register(require('@fastify/swagger-ui'), {
  routePrefix: '/documentation',
  uiConfig: {
    docExpansion: 'full'
  }
});

// Decryption endpoint
fastify.post('/decrypt', {
  schema: {
    body: {
      type: 'object',
      required: ['encryptedKey', 'encryptedData'],
      properties: {
        encryptedKey: {
          type: 'string',
          description: 'Base64-encoded RSA-encrypted AES key (PKCS1 padding), decrypted by Java.'
        },
        encryptedData: {
          type: 'string',
          description: 'Base64-encoded AES-256-CBC encrypted payload, decrypted by Node.js.'
        },
        iv: {
          type: 'string',
          default: '',
          description: 'Optional Base64-encoded initialization vector (16 bytes). If empty, a zero-filled IV is used.'
        }
      }
    },
    response: {
      200: {
        // Assuming the final decrypted payload is JSON
        type: 'object',
        description: 'Decrypted payload (assumed to be a JSON object).'
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
    // 1. Call Java process to decrypt the AES key using RSA/ECB/PKCS1Padding
    fastify.log.debug('Spawning Java process for RSA key decryption...');
    const javaProcess = spawn('java', ['rsa_decryptor']); // Assumes rsa_decryptor.class is compiled and in PATH/CWD

    let decryptedKeyBase64 = '';
    let javaStderr = '';

    // Capture Java stdout (decrypted key)
    javaProcess.stdout.on('data', (data) => {
      decryptedKeyBase64 += data.toString();
    });

    // Capture Java stderr (error messages)
    javaProcess.stderr.on('data', (data) => {
      javaStderr += data.toString();
    });

    // Send encryptedKey and PRIVATE_KEY to Java process via stdin
    javaProcess.stdin.write(encryptedKey + '\n');
    javaProcess.stdin.write(CONFIG.PRIVATE_KEY);
    javaProcess.stdin.end();

    // Wait for the Java process to complete
    const decryptedSymmetricKey = await new Promise((resolve, reject) => {
      javaProcess.on('close', (code) => {
        if (code !== 0) { // Java process exited with an error
          const errorMessage = `Java decryption failed: Exit code ${code}. Stderr: ${javaStderr || 'No stderr output.'}`;
          fastify.log.error(errorMessage);
          return reject(new Error(errorMessage));
        }
        if (!decryptedKeyBase64.trim()) { // Java returned no decrypted key
            const errorMessage = `Java decryption failed: No decrypted key returned. Stderr: ${javaStderr || 'No stderr output.'}`;
            fastify.log.error(errorMessage);
            return reject(new Error(errorMessage));
        }
        fastify.log.debug('Java RSA decryption successful.');
        // Resolve with the Base64 decoded buffer of the symmetric key
        resolve(Buffer.from(decryptedKeyBase64.trim(), 'base64'));
      });

      javaProcess.on('error', (err) => { // Handle errors spawning the process itself
        const errorMessage = `Failed to spawn Java process: ${err.message}`;
        fastify.log.error(errorMessage);
        reject(new Error(errorMessage));
      });
    });

    // 2. Prepare IV buffer for AES decryption
    // If IV is not provided, use a zero-filled buffer of CONFIG.IV_LENGTH (16 bytes for AES-256-CBC)
    const ivBuffer = iv ? Buffer.from(iv, 'base64') : Buffer.alloc(CONFIG.IV_LENGTH, 0);
    if (ivBuffer.length !== CONFIG.IV_LENGTH) {
        throw new Error(`Invalid IV length. Expected ${CONFIG.IV_LENGTH} bytes, got ${ivBuffer.length}.`);
    }

    // 3. Decrypt the payload using AES-256-CBC in Node.js
    fastify.log.debug('Starting AES payload decryption...');
    const decipher = crypto.createDecipheriv(
      CONFIG.AES_ALGORITHM,
      decryptedSymmetricKey,
      ivBuffer
    );

    let decryptedData = decipher.update(encryptedData, 'base64', 'utf8');
    decryptedData += decipher.final('utf8');
    fastify.log.debug('AES payload decryption successful.');

    // 4. Parse the decrypted data as JSON
    fastify.log.debug('Parsing decrypted data as JSON...');
    const result = JSON.parse(decryptedData);
    fastify.log.debug('JSON parsing successful.');

    reply.send(result);

  } catch (error) {
    // Centralized error handling
    const { statusCode, response } = handleDecryptionError(error, fastify);
    reply.status(statusCode).send(response);
  }
});

// Health check endpoint
fastify.get('/health', async (request, reply) => {
  reply.send({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start the Fastify server
const start = async () => {
  try {
    await fastify.listen({
      port: CONFIG.PORT,
      host: '0.0.0.0' // Listen on all network interfaces
    });
    fastify.log.info(`Server running on http://localhost:${CONFIG.PORT}`);
    fastify.log.info(`Swagger docs at http://localhost:${CONFIG.PORT}/documentation`);
  } catch (err) {
    fastify.log.error('Server startup error:', err);
    process.exit(1); // Exit process on startup failure
  }
};

start();