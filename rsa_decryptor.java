import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException; // Import for specific key spec errors
import javax.crypto.Cipher;
import javax.crypto.BadPaddingException; // Import for decryption padding errors
import javax.crypto.IllegalBlockSizeException; // Import for decryption block size errors
import java.util.Base64;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException; // Import for I/O errors

public class rsa_decryptor {
    public static void main(String[] args) {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(System.in));

            // Read the Base64-encoded encrypted AES key from the first line of stdin
            String encryptedKeyBase64 = reader.readLine();
            if (encryptedKeyBase64 == null || encryptedKeyBase64.isEmpty()) {
                System.err.println("Error: Encrypted key (Base64) was not provided on stdin.");
                System.exit(1);
                return;
            }

            // Read the private key PEM string from subsequent lines of stdin
            // Node.js sends the full PEM including headers and footers
            StringBuilder privateKeyPem = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                privateKeyPem.append(line).append("\n"); // Preserve newlines as sent by Node.js
            }

            String fullPrivateKeyPem = privateKeyPem.toString().trim(); // Trim leading/trailing whitespace

            // Remove PEM headers, footers, and all whitespace (including newlines)
            // Note: This assumes PKCS#8 format which `PKCS8EncodedKeySpec` expects.
            // If your private key is PKCS#1, you might need to convert it to PKCS#8 or use different spec.
            String privateKeyBase64 = fullPrivateKeyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "") // Handle PKCS#1 header too, if it might come
                .replace("-----END RSA PRIVATE KEY-----", "")   // Handle PKCS#1 footer too
                .replaceAll("\\s+", ""); // Remove all whitespace (spaces, newlines, tabs)

            if (privateKeyBase64.isEmpty()) {
                System.err.println("Error: Private key was not provided or was empty after stripping PEM format.");
                System.exit(1);
                return;
            }

            // Decode the Base64 private key content into raw bytes
            byte[] keyBytes = Base64.getDecoder().decode(privateKeyBase64);

            // Create a PKCS8EncodedKeySpec to load the private key
            // This spec expects the key to be in PKCS#8 format (DER encoded).
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(spec);

            // Initialize the Cipher for RSA decryption with PKCS1 padding
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // Decode the Base64 encrypted key into raw bytes
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedKeyBase64);

            // Perform decryption
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            // Print the Base64-encoded decrypted symmetric key to stdout
            System.out.println(Base64.getEncoder().encodeToString(decryptedBytes));

        } catch (IOException e) {
            System.err.println("Error reading input: " + e.getMessage());
            System.exit(1);
        } catch (InvalidKeySpecException e) {
            System.err.println("Error: Invalid private key specification. Ensure it's a valid PKCS#8 RSA private key. Details: " + e.getMessage());
            // For debugging, consider e.printStackTrace(System.err);
            System.exit(1);
        } catch (BadPaddingException e) {
            System.err.println("Error: Bad padding during RSA decryption. This usually means the encrypted key is corrupted or encrypted with a different public key. Details: " + e.getMessage());
            System.exit(1);
        } catch (IllegalBlockSizeException e) {
            System.err.println("Error: Illegal block size during RSA decryption. This can happen if the encrypted data length is incorrect. Details: " + e.getMessage());
            System.exit(1);
        } catch (Exception e) { // Catch all other exceptions
            System.err.println("An unexpected error occurred during RSA decryption in Java: " + e.getMessage());
            e.printStackTrace(System.err); // Print stack trace for comprehensive debugging
            System.exit(1);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    System.err.println("Error closing reader: " + e.getMessage());
                }
            }
        }
    }
}