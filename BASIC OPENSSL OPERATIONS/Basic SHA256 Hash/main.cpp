#include <openssl/evp.h>
#include <iostream>
#include <iomanip>

void print_hex(unsigned char* data, int len) {
    for (int i = 0; i < len; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    std::cout << std::endl;
}

int main() {
    // Input data
    unsigned char data[] = "Hello, OpenSSL!";

    // Buffer for the hash
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    // Create a hash context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // Initialize the hash context with SHA-256 algorithm
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    // Provide the message to the context
    EVP_DigestUpdate(ctx, data, sizeof(data));

    // Finalize the hash
    EVP_DigestFinal_ex(ctx, hash, &hash_len);

    // Print the hash
    std::cout << "SHA-256 hash of the input is: ";
    print_hex(hash, hash_len);

    // Clean up
    EVP_MD_CTX_free(ctx);

    return 0;
}
