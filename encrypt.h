#ifndef GPG_H
#define GPG_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <stdlib.h>
#include <string.h>

void create_rsa_key_pair(char** pubkey, char** privkey);
RSA* convert_to_rsa_pubkey(const char* key_str);
RSA* convert_to_rsa_privkey(const char* key_str);
char* rsa_encrypt(char* pub_key_str, char *message, size_t message_len);
char* rsa_decrypt(char* priv_key_str, char *encrypted, size_t encrypted_len);
void print_pubkey_information(char* pubkey);
#endif
