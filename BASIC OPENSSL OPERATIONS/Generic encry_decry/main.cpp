#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <cstring>
#include <iomanip>

const unsigned int KEY_SIZE = 16; // AES key size in bytes
const unsigned int BLOCK_SIZE = 16; // AES block size in bytes

// Function to print data in hex
void print_hex(unsigned char* data, int len) {
    for (int i = 0; i < len; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    std::cout << std::endl;
}

int main() {
    // Generate a random key
    unsigned char key[KEY_SIZE];
    if (!RAND_bytes(key, sizeof(key))) {
        std::cerr << "Error generating key" << std::endl;
        return 1;
    }

    // Generate a random IV
    unsigned char iv[BLOCK_SIZE];
    if (!RAND_bytes(iv, sizeof(iv))) {
        std::cerr << "Error generating IV" << std::endl;
        return 1;
    }

    // Input data to encrypt
    unsigned char plaintext[] = "Hello, OpenSSL!";
    unsigned char ciphertext[sizeof(plaintext) + BLOCK_SIZE];
    unsigned char decryptedtext[sizeof(plaintext)];

    int decryptedtext_len = 0, ciphertext_len = 0;

    // Encrypt the plaintext
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, sizeof(plaintext))){
        std::cerr << "Error in encryption.\n";
        return 1;
    }

    int len;
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len)){
        std::cerr << "Error in final encryption.\n";
        return 1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Decrypt the ciphertext
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    if(1 != EVP_DecryptUpdate(ctx, decryptedtext, &decryptedtext_len, ciphertext, ciphertext_len)){
        std::cerr << "Error in decryption.\n";
        return 1;
    }

    if(1 != EVP_DecryptFinal_ex(ctx, decryptedtext + decryptedtext_len, &len)){
        std::cerr << "Error in final decryption.\n";
        return 1;
    }
    decryptedtext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Print out the original, encrypted, and decrypted texts
    std::cout << "Original text: " << plaintext << std::endl;
    std::cout << "Encrypted text in hex: ";
    print_hex(ciphertext, ciphertext_len);
    std::cout << "Decrypted text: " << decryptedtext << std::endl;

    return 0;
}
