#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "socket.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tls.h"
#include "client_method.h"
#include "packet.h"
#include "encrypt.h"

void *chat_receiver(void *arg);
void *chat_sender(void* arg);
int client_handler(packet* pkt, SSL* ssl);
void add_user_info(packet* pkt);

unsigned int my_uuid;

pthread_mutex_t cli_mutex = PTHREAD_MUTEX_INITIALIZER;
struct list pubkey_list;
bool pubkey_list_updated = false;

char* pubkey;
char* privkey;

int main(int argc, char** argv) {
    int sd;
    int opt;
    int bytes;
    int port = -1;
    char nickname[16];
    char* address = NULL;
    char* identity_path = NULL;
    pthread_t rev_tid;
    pthread_t sen_tid;
    SSL_CTX* ctx;
    SSL *ssl;
    char option;
    packet* pkt;


    /* option parsing*/
   while ((opt = getopt(argc, argv, "p:i:n:a:")) != -1) {
    switch (opt) {
        case 'p':
            port = atoi(optarg);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "Invalid port number. Please enter a number between 1 and 65535.\n");
                exit(1);
            }
            break;
        case 'a':
            address = optarg;
            break;
        case 'n':
            strcpy(nickname, optarg);
            break;
        default: /* '?' */
            fprintf(stderr, "Usage: %s [-p port] [-a server address] [-n nickname]\n", argv[0]);
            exit(1);
        }
    }

    /* Arguments Checking */
    if (port == -1 || address == NULL || strlen(nickname) == 0){
        printf("Invalid Arguments:\n");
        fprintf(stderr, "Usage: %s [-p port] [-a server address] [-n nickname]\n", argv[0]);
        exit(1);
    }

    create_rsa_key_pair(&pubkey, &privkey);

    printf("pubkey and private key generated. Your key information :\n");
    printf(" ==========      your RSA pubkey      ========== \n");
    printf("%s",pubkey);
    printf("\n============================================== \n");



    printf("--------------------------------------------\n");
    printf("Trys to connect EEstring server....: \n");
    printf("path to identity file : %s, your nickname : %s\n", identity_path, nickname);
    printf("--------------------------------------------\n");
    sd = open_connection(address, port);


    /*TLS connection Init*/
    SSL_library_init();
    ctx = init_CTX();
    ssl = SSL_new(ctx);             /* create new SSL connection state */
    SSL_set_fd(ssl, sd);            /* attach the socket descriptor */
    if (SSL_connect(ssl) != 1 ){   /* perform the connection */
        ERR_print_errors_fp(stderr);
    }

    if (!verify_certificate_with_root(ssl, "rootcert.pem")){
        printf("Failed to Validate Server! Exiting...\n");
        printf("This is not Valid EEstring Server!\n");
        exit(1);
    }

    //Server Hello packet

    printf("Server Handshake Complete.\n");
    /* pubkey list init */
    list_init(&pubkey_list);



    my_uuid = say_hello(ssl, nickname, pubkey);

    if(my_uuid == 0){
        printf("Failed to Access Server! Exiting...\n");
        exit(1);
    }

    first_message(my_uuid);
    pthread_create(&rev_tid, NULL, chat_receiver, ssl);
    pthread_create(&sen_tid, NULL, chat_sender, ssl);


    //waits to main thread returns..

    pthread_join(rev_tid, NULL);
    pthread_join(sen_tid, NULL);


    // Clean up
    SSL_free(ssl);
    close(sd);
    SSL_CTX_free(ctx);
    return 0;
}


/* Only handles DELIVER_MESSAGE packet */
void* chat_receiver(void* arg) {
    SSL *ssl = (SSL *)arg;
    while (1) {
        packet *pkt;
        if (ssl_receive(ssl, &pkt) > 0) {
            client_handler(pkt, ssl);
            free_packet(pkt);
        } else {
            break;
        }
    }
    return NULL;
}

void* chat_sender(void* arg) {
    SSL *ssl = (SSL *)arg;
    char input[1024];
    char command;
    unsigned int uuid;
    char message[1024];
    packet* request;

    first_message(my_uuid); // Display the initial message

    while (1) {
        printf(">>>>>>");
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("Error reading input. Try again.\n");
            continue;
        }

        // Parse the command from the input
        if (sscanf(input, "%c", &command) < 1) {
            printf("Invalid input. Type '-h' for help.\n");
            continue;
        }

        switch (command) {
            case 'p': // Print user list
                request = request_user_list();
                ssl_send(ssl, request);
                free_packet(request);
                break;
            case 'u': // User info
                if (sscanf(input, "u %u", &uuid) == 1){
                    request = request_user_info(uuid);
                    ssl_send(ssl, request);
                    free_packet(request);
                }
                else{
                    printf("Invalid usage of -u command.\n");
                }
                break;
            case 's': // Send message
                if (sscanf(input, "s %u %[^\n]", &uuid, message) == 2) {
                    assert (&pubkey_list != NULL);
                    packet* pkt = request_send_message(ssl, uuid, message, my_uuid, &pubkey_list);
                    if (pkt == NULL)
                        break;
                    ssl_send(ssl, pkt);
                    free_packet(pkt);
                }
                else {
                    printf("Invalid usage of -s command.\n");
                }
                break;
            case 'x': // Exit
                printf("Exiting EEstring.\n");
                exit(0);
                break;
            case 'h': // Help message
                first_message(my_uuid);
                break;
            default:
                printf("Unknown command. Type '-h' for help.\n");
                break;
        }
    }
    return NULL;
}
/* receiver thread uses it */
int client_handler(packet* pkt, SSL* ssl) {
    packet* new;
    switch (pkt->type) {
        case DELIVER_MESSAGE:
                printf("\n===========================\n");
                printf("Message from user [uuid : %u]:",pkt -> sender_uuid);
                printf("Decrypted Message: %s \n",rsa_decrypt(privkey, pkt -> message, strlen(pkt -> message)));
                printf("\n===========================\n");
            break;
        case ANSWER_USER_LIST:
            show_user_list(pkt -> message);
            break;
        case ANSWER_USER_INFO:
            printf("\nUser %u pubkey information : \n",pkt -> receiver_uuid);
            print_pubkey_information(pkt -> pubkey);
            pthread_mutex_lock(&cli_mutex);
            add_user_info(pkt);
            pubkey_list_updated = true;
            pthread_mutex_unlock(&cli_mutex);
            break;
        case CHECK_CONNECT:
            new = init_packet();
            new -> type = CHECK_CONNECT;
            ssl_send(ssl, new);
            break;
        case SERVER_MSG:
            pthread_mutex_lock(&cli_mutex);
            pubkey_list_updated = true;
            pthread_mutex_unlock(&cli_mutex);
            printf("Message from server: %s\n", pkt -> message);
            break;
        default:
            printf("\nReceived an unhandled packet type.\n");
    }
    return 1;
}

void add_user_info(packet* pkt) {

    // Check if the user's public key already exists in the list
    struct list_elem *e;
    for (e = list_begin(&pubkey_list); e != list_end(&pubkey_list); e = list_next(e)) {
        struct user_pubkeys *up = list_entry(e, struct user_pubkeys, elem);
        if (up -> uuid == pkt -> receiver_uuid) {
            // UUID found, update public key if different and return
            if (strcmp(up->pubkey, pkt->pubkey) != 0) {
                free(up->pubkey);
                up -> pubkey = strdup(pkt->pubkey);
            }
            return;
        }
    }

    // UUID not found, add new user public key to the list
    struct user_pubkeys *new_up = malloc(sizeof(struct user_pubkeys));
    new_up->uuid = pkt->receiver_uuid;
    new_up->pubkey = strdup(pkt->pubkey);
    list_push_back(&pubkey_list, &new_up->elem);
}
