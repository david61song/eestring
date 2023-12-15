#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include "tls.h"

void configure_context(SSL_CTX *ctx){
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "servercert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "serverkey.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

SSL_CTX *create_context(){
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

/* Print Certificate Information*/
void show_certs(SSL* ssl){
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}

SSL_CTX* init_CTX(void) {
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */

    ctx = SSL_CTX_new(TLS_client_method()); /* Create new context using TLS method */

    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* Only allow TLS 1.3 */
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    return ctx;
}


int verify_certificate_with_root(SSL *ssl, const char* root_cert_file) {
    // Load the root certificate
    FILE *fp = fopen(root_cert_file, "r");
    if (!fp) return -1;
    X509 *root_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!root_cert) return -1;

    // Get the server certificate from the SSL connection
    X509 *server_cert = SSL_get_peer_certificate(ssl);
    if (!server_cert) {
        X509_free(root_cert);
        return -1;
    }

    // Create a new X509_STORE and add the root certificate
    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, root_cert);

    // Create and initialize X509_STORE_CTX
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, server_cert, NULL);

    // Perform the verification
    int result = X509_verify_cert(ctx);

    // Cleanup
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(server_cert);  // Remember to free the server certificate
    X509_free(root_cert);

    // Return the result
    return (result == 1) ? 1 : 0;
}
