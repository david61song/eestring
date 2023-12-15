#ifndef TLS_H
#define TLS_H

#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

void configure_context(SSL_CTX *ctx);
SSL_CTX* create_context();
void show_certs(SSL* ssl);
SSL_CTX* init_CTX(void);
int verify_certificate_with_root(SSL *ssl, const char* rootcert);
#endif
