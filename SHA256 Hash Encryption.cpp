#include <openssl/evp.h>
#include <iostream>
#include <string>

void printHash(unsigned char* md) {
    for (int i = 0; i < EVP_MAX_MD_SIZE; i++) {
        printf("%02x", md[i]);
    }
    std::cout << std::endl;
}

int main() {
    std::string input = "Hello, World!";
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    // Create a hash context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // Initialize the context for SHA-256
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        std::cout << "Error initializing digest context." << std::endl;
        return -1;
    }

    // Provide the message to be hashed
    if (EVP_DigestUpdate(ctx, input.c_str(), input.size()) != 1) {
        std::cout << "Error updating digest." << std::endl;
        return -1;
    }

    // Finalize the hash
    if (EVP_DigestFinal_ex(ctx, md, &md_len) != 1) {
        std::cout << "Error finalizing digest." << std::endl;
        return -1;
    }

    // Print the hash
    std::cout << "SHA-256 hash of '" << input << "': ";
    printHash(md);

    // Clean up
    EVP_MD_CTX_free(ctx);

    return 0;
}
