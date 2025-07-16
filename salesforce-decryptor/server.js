import Fastify from 'fastify';
import Swagger from '@fastify/swagger';
import SwaggerUI from '@fastify/swagger-ui';
import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config();

const fastify = Fastify({ logger: true });

// Swagger API Docs
fastify.register(Swagger, { 
  swagger: { 
    info: { title: 'Salesforce RSA Decryptor', version: '1.0.0' } 
  } 
});
fastify.register(SwaggerUI, { routePrefix: '/docs' });

// Health Check
fastify.get('/', async () => ({ status: 'OK' }));

// Decryption Endpoint
fastify.post('/decrypt', async (request, reply) => {
  try {
    const { encryptedKey, encryptedData } = request.body;
    const privateKey = process.env.PRIVATE_KEY.replace(/\\n/g, '\n');

    // RSA Decryption
    const symmetricKey = crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING },
      Buffer.from(encryptedKey, 'base64')
    );

    // AES-256-CBC Decryption
    const encryptedBuffer = Buffer.from(encryptedData, 'base64');
    const iv = encryptedBuffer.slice(0, 16);
    const ciphertext = encryptedBuffer.slice(16);
    
    const decipher = crypto.createDecipheriv('aes-256-cbc', symmetricKey, iv);
    let decrypted = decipher.update(ciphertext, null, 'utf8');
    decrypted += decipher.final('utf8');

    return { success: true, decryptedData: decrypted };
  } catch (error) {
    fastify.log.error(error);
    return reply.code(500).send({ success: false, error: error.message });
  }
});

// Start Server
const start = async () => {
  try {
    await fastify.listen({ port: process.env.PORT || 3000, host: '0.0.0.0' });
    console.log(`Server running on port ${fastify.server.address().port}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();