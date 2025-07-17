FROM node:18

# Install Java
RUN apt-get update && apt-get install -y openjdk-11-jdk

# App directory
WORKDIR /app

# Copy and install
COPY . .
RUN npm install

# Compile Java decryption tool
RUN javac rsa_decryptor.java

# Run app
CMD ["node", "server.js"]