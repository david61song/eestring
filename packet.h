#ifndef PACKET_H
#define PACKET_H

#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "list.h"
#include <string.h>

#define MAX_MSG_SIZE 1024
#define MAX_PUBKEY_SIZE 4096

extern pthread_mutex_t user_mutex;

typedef enum _packet_type{
    USER_HELLO,                 // user hello message
    SERVER_HELLO,               // server hello message, returns user uuid.
    SERVER_MSG,                 // server to user message.
    REQUEST_USER_LIST,          // request current user list
    REQUEST_USER_INFO,          // request certain uuid user
    ANSWER_USER_LIST,           // answer of user list
    ANSWER_USER_INFO,           // answer of user info
    REQUEST_SEND_MESSAGE,       // request to send certain message.
    DELIVER_MESSAGE,             // message delivered by server.
    CHECK_CONNECT               // check connectivity
}packet_type;

typedef struct _packet{
    //received time
    time_t timestamp;
    // packet type
    packet_type type;
    // size of message
    unsigned int message_size;
    char* message;
    // public key (gpg pubkey)
    unsigned int pubkey_size;
    char* pubkey;
    // user uuid
    unsigned int sender_uuid;
    unsigned int receiver_uuid;
}packet;


int ssl_receive(SSL *ssl, packet **pkt);
int ssl_send(SSL *ssl, packet *pkt);
packet* byte_to_packet(char *byte_array, unsigned int size);
char* packet_to_byte(packet *pkt, unsigned int *size);
packet* init_packet();
int free_packet(packet* pkt);

#endif

