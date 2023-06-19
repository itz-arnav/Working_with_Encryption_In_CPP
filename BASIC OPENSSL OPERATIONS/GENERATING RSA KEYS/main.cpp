#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <iostream>
#include <fstream>

int main() {
    // Create a new RSA key pair
    BIGNUM* bne = BN_new();
    int ret = BN_set_word(bne, RSA_F4);
    RSA* rsa = RSA_new();

    if (ret != 1) {
        RSA_free(rsa);
        BN_free(bne);
        std::cerr << "Error during RSA key pair generation: BN_set_word failed." << std::endl;
        return 1;
    }

    ret = RSA_generate_key_ex(rsa, 2048, bne, NULL);
    if (ret != 1) {
        RSA_free(rsa);
        BN_free(bne);
        std::cerr << "Error during RSA key pair generation: RSA_generate_key_ex failed." << std::endl;
        return 1;
    }

    // Write keys to BIO objects
    BIO* pri = BIO_new(BIO_s_mem());
    BIO* pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, rsa, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, rsa);

    // Write keys from BIO objects to files
    size_t pri_len = BIO_pending(pri);
    size_t pub_len = BIO_pending(pub);

    char* pri_key = new char[pri_len + 1];
    char* pub_key = new char[pub_len + 1];

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    std::ofstream pri_file("privateKey.pem");
    std::ofstream pub_file("publicKey.pem");

    if(pri_file.is_open()) {
        pri_file << pri_key;
        pri_file.close();
    } else {
        std::cerr << "Unable to open private key file for writing\n";
        return 1;
    }

    if(pub_file.is_open()) {
        pub_file << pub_key;
        pub_file.close();
    } else {
        std::cerr << "Unable to open public key file for writing\n";
        return 1;
    }

    // Clean up
    delete[] pri_key;
    delete[] pub_key;

    BIO_free_all(pub);
    BIO_free_all(pri);
    RSA_free(rsa);
    BN_free(bne);

    std::cout << "Keys have been written to privateKey.pem and publicKey.pem\n";

    return 0;
}
