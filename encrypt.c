#include "encrypt.h"
#include <assert.h>

//create rsa pubkey and privkey pair.
void create_rsa_key_pair(char** pubkey, char** privkey) {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bn, NULL);

    BIO *priv_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(priv_bio, rsa, NULL, NULL, 0, NULL, NULL);

    BIO *pub_bio = BIO_new(BIO_s_mem());
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, rsa);
    PEM_write_bio_PUBKEY(pub_bio, pkey);

    size_t priv_len = BIO_pending(priv_bio);
    size_t pub_len = BIO_pending(pub_bio);

    *privkey = malloc(priv_len + 1);
    *pubkey = malloc(pub_len + 1);

    BIO_read(priv_bio, *privkey, priv_len);
    BIO_read(pub_bio, *pubkey, pub_len);

    (*privkey)[priv_len] = '\0'; // null-terminated
    (*pubkey)[pub_len] = '\0'; // null- terminated

    RSA_free(rsa);
    BN_free(bn);
    EVP_PKEY_free(pkey); //
    BIO_free_all(priv_bio);
    BIO_free_all(pub_bio);
}



RSA* convert_to_rsa_pubkey(const char* key_str) {
    BIO *bio = BIO_new_mem_buf((void*)key_str, -1);
    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    ERR_print_errors_fp(stderr);
    BIO_free(bio);
    return rsa;
}

// Convert a plaintext private key to RSA structure
RSA* convert_to_rsa_privkey(const char* key_str) {
    BIO *bio = BIO_new_mem_buf((void*)key_str, -1);
    RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return rsa;
}

// Modified encryption function to accept plaintext public key
void print_pubkey_information(char* pubkey) {
    printf("\n-------------------Recipient's Pubkey ----------------------\n");
    printf("%s",pubkey);
    printf("\n-----------------------------------------------------------\n");
}

char* base64_encode(const unsigned char *input, int length) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    bmem = BIO_push(b64, bmem);

    BIO_write(bmem, input, length);
    BIO_flush(bmem);
    BIO_get_mem_ptr(bmem, &bptr);

    char *buff = (char *)malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length - 1);
    buff[bptr->length - 1] = 0;

    BIO_free_all(bmem);

    return buff;
}

// Base64 decoding
unsigned char* base64_decode(const char *input, int *length) {
    BIO *b64, *bmem;

    int input_length = strlen(input);
    unsigned char *buffer = (unsigned char *)malloc(input_length);
    memset(buffer, 0, input_length);

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(input, input_length);
    bmem = BIO_push(b64, bmem);

    *length = BIO_read(bmem, buffer, input_length);

    BIO_free_all(bmem);

    return buffer;
}

// rsa encrypt
char* rsa_encrypt(char* pub_key_str, char *message, size_t message_len) {

    RSA *rsa = convert_to_rsa_pubkey(pub_key_str);
    assert (rsa != NULL);

    unsigned char *encrypted = malloc(RSA_size(rsa));
    if (!encrypted) {
        RSA_free(rsa);
        return NULL;
    }

    int encrypted_len = RSA_public_encrypt(message_len, (unsigned char*)message, encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);
    if (encrypted_len == -1) {
        free(encrypted);
        return NULL;
    }

    char *base64_encrypted = base64_encode(encrypted, encrypted_len);
    free(encrypted);

    return base64_encrypted; // Caller is responsible for freeing this memory
}

// rsa decrypt
char* rsa_decrypt(char* priv_key_str, char *base64_encrypted, size_t base64_encrypted_len) {
    int encrypted_len;
    unsigned char *encrypted = base64_decode(base64_encrypted, &encrypted_len);
    if (!encrypted) return NULL;

    RSA *rsa = convert_to_rsa_privkey(priv_key_str);
    if (!rsa) {
        free(encrypted);
        return NULL;
    }

    unsigned char *decrypted = malloc(RSA_size(rsa));
    if (!decrypted) {
        RSA_free(rsa);
        free(encrypted);
        return NULL;
    }

    int decrypted_len = RSA_private_decrypt(encrypted_len, encrypted, decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);
    free(encrypted);

    if (decrypted_len == -1) {
        free(decrypted);
        return NULL;
    }

    char *result = malloc(decrypted_len + 1);
    if (result) {
        memcpy(result, decrypted, decrypted_len);
        result[decrypted_len] = '\0'; // Null-terminate the string
    }

    free(decrypted);

    return result; // Caller is responsible for freeing this memory
}




