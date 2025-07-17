# Use a Node.js 18 base image
# This image already includes Node.js and npm
FROM node:18

# Install Java Development Kit (JDK)
# apt-get update refreshes the package list
# Use 'default-jdk' which is a more generic package name that should resolve
# to a compatible JDK version (e.g., OpenJDK 11, 17, or newer)
RUN apt-get update && apt-get install -y default-jdk

# Set the working directory inside the container
# All subsequent commands will be executed relative to this directory
WORKDIR /app

# Copy all files from the current local directory into the /app directory in the container
# This includes your server.js, rsa_decryptor.java, package.json, .env, etc.
COPY . .

# Install Node.js dependencies
# This command reads package.json and installs all listed dependencies into node_modules
RUN npm install

# Compile the Java decryption tool
# javac compiles rsa_decryptor.java into rsa_decryptor.class
# This compiled file is what your Node.js application will spawn
RUN javac rsa_decryptor.java

# Define the command to run when the container starts
# This starts your Node.js Fastify server
CMD ["node", "server.js"]