#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
using namespace std;

void handleErrors()
{
    cerr << "Error: " << ERR_error_string(ERR_get_error(), nullptr) << endl;
    abort();
}

RSA* generate_rsa_key_pair(int keyLength)
{
    RSA* rsaKey = RSA_new();
    if (!rsaKey)
    {
        handleErrors();
    }

    BIGNUM* bn = BN_new();
    if (!bn)
    {
        RSA_free(rsaKey);
        handleErrors();
    }

    int ret = BN_set_word(bn, RSA_F4);
    if (ret != 1)
    {
        RSA_free(rsaKey);
        BN_free(bn);
        handleErrors();
    }

    ret = RSA_generate_key_ex(rsaKey, keyLength, bn, nullptr);
    if (ret != 1)
    {
        RSA_free(rsaKey);
        BN_free(bn);
        handleErrors();
    }

    BN_free(bn);
    return rsaKey;
}

int rsaes_oaep_encrypt(const unsigned char* plaintext, int plaintext_len, RSA* rsaKey, unsigned char* ciphertext)
{
    int ciphertext_len = RSA_public_encrypt(plaintext_len, plaintext, ciphertext, rsaKey, RSA_PKCS1_OAEP_PADDING);
    if (ciphertext_len == -1)
    {
        handleErrors();
    }
    return ciphertext_len;
}

int rsaes_oaep_decrypt(const unsigned char* ciphertext, int ciphertext_len, RSA* rsaKey, unsigned char* decryptedtext)
{
    int decryptedtext_len = RSA_private_decrypt(ciphertext_len, ciphertext, decryptedtext, rsaKey, RSA_PKCS1_OAEP_PADDING);
    if (decryptedtext_len == -1)
    {
        handleErrors();
    }
    return decryptedtext_len;
}

void test_rsaes_oaep(const int keyLength, const char* plaintext) 
{
    // Generate RSA key pair
    RSA* rsaKey = generate_rsa_key_pair(keyLength);

    int plaintext_len = strlen(plaintext);

    unsigned char* ciphertext;
    ciphertext = (unsigned char*)malloc(RSA_size(rsaKey) * sizeof(unsigned char));

    unsigned char* decryptedtext;
    decryptedtext = (unsigned char*)malloc(RSA_size(rsaKey) * sizeof(unsigned char));

    // Encryption
    int ciphertext_len = rsaes_oaep_encrypt(reinterpret_cast<const unsigned char*>(plaintext), plaintext_len, rsaKey, ciphertext);

    // Decryption
    int decryptedtext_len = rsaes_oaep_decrypt(ciphertext, ciphertext_len, rsaKey, decryptedtext);

    cout << "Plaintext: " << plaintext << endl;
    cout << "Ciphertext: ";
    for (int i = 0; i < ciphertext_len; ++i)
    {
        printf("%02X", ciphertext[i]);
    }
    cout << endl;
    cout << "Decrypted text: " << decryptedtext << endl;

    RSA_free(rsaKey);
}

int main()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    const int keyLength = 2048;
    const char* plaintext = "Hello, RSAES-OAEP!";
    
    test_rsaes_oaep(keyLength, plaintext);

    ERR_free_strings();
    EVP_cleanup();

    return 0;
}
