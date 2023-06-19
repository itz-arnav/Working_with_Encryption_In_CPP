#include <openssl/evp.h>
#include <openssl/aes.h>
#include <cstring>
#include <iostream>

int main() {
    unsigned char key[AES_BLOCK_SIZE];
    memset(key, 0x00, AES_BLOCK_SIZE);

    // "Message to be encrypted"
    unsigned char plaintext[] = "Hello, World!";

    // Print the original plaintext
    std::cout << "Original message: " << plaintext << std::endl;

    // Encrypted output buffer
    unsigned char enc_out[sizeof(plaintext)+AES_BLOCK_SIZE]; // Add space for potential padding
    unsigned char dec_out[sizeof(enc_out)];

    // Create and initialize the context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    // Initialize the encryption operation
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr);

    int len, ciphertext_len;

    // Provide the message to be encrypted, and obtain the encrypted output
    EVP_EncryptUpdate(ctx, enc_out, &len, plaintext, sizeof(plaintext)-1); // Subtract 1 to ignore null terminator

    // Finalize the encryption
    EVP_EncryptFinal_ex(ctx, enc_out + len, &ciphertext_len);
    ciphertext_len += len;

    // Print encrypted text
    std::cout << "Encrypted message: ";
    for (int i = 0; i < ciphertext_len; ++i) {
        printf("%02x", enc_out[i]);
    }
    std::cout << std::endl;

    // Initialize the decryption operation
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr);

    // Provide the message to be decrypted, and obtain the plaintext output
    EVP_DecryptUpdate(ctx, dec_out, &len, enc_out, ciphertext_len);

    // Finalize the decryption
    EVP_DecryptFinal_ex(ctx, dec_out + len, &len);

    // Manually add a null terminator to the decrypted output to make it a valid string
    dec_out[ciphertext_len] = '\0';

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Print decrypted text
    std::cout << "Decrypted message: " << dec_out << std::endl;

    return 0;
}
