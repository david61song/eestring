#include "packet.h"

char* packet_to_byte(packet *pkt, unsigned int *size) {
    unsigned int total_size;
    total_size = 0;
    total_size += sizeof(pkt -> timestamp);
    total_size += sizeof(pkt -> type);
    total_size += sizeof(pkt -> message_size);
    total_size += pkt -> message_size;
    total_size += sizeof(pkt -> pubkey_size);
    total_size += pkt -> pubkey_size;
    total_size += sizeof(pkt -> sender_uuid);
    total_size += sizeof(pkt -> receiver_uuid);

    char *buffer = malloc(total_size);
    char *ptr = buffer;

    memcpy(ptr, &(pkt -> timestamp), sizeof(pkt -> timestamp));
    ptr += sizeof(pkt->timestamp);

    memcpy(ptr, &(pkt -> type), sizeof(pkt -> type));
    ptr += sizeof(pkt -> type);

    memcpy(ptr, &(pkt -> message_size), sizeof(pkt -> message_size));
    ptr += sizeof(pkt -> message_size);

    memcpy(ptr, pkt -> message, pkt -> message_size);
    ptr += pkt -> message_size;

    memcpy(ptr, &(pkt -> pubkey_size), sizeof(pkt -> pubkey_size));
    ptr += sizeof(pkt -> pubkey_size);

    memcpy(ptr, pkt -> pubkey, pkt -> pubkey_size);
    ptr += pkt -> pubkey_size;

    memcpy(ptr, &(pkt -> sender_uuid), sizeof(pkt -> sender_uuid));
    ptr += sizeof(pkt -> sender_uuid);

    memcpy(ptr, &(pkt -> receiver_uuid), sizeof(pkt -> receiver_uuid));
    ptr += sizeof(pkt -> receiver_uuid);

    *size = total_size;
    return buffer;
}

packet* byte_to_packet(char *byte_array, unsigned int size) {
    packet *pkt = malloc(sizeof(packet));
    char *ptr = byte_array;

    memcpy(&(pkt -> timestamp), ptr, sizeof(pkt -> timestamp));
    ptr += sizeof(pkt -> timestamp);

    memcpy(&(pkt -> type), ptr, sizeof(pkt -> type));
    ptr += sizeof(pkt -> type);

    memcpy(&(pkt -> message_size), ptr, sizeof(pkt -> message_size));
    ptr += sizeof(pkt -> message_size);

    pkt -> message = malloc(pkt -> message_size);
    memcpy(pkt -> message, ptr, pkt -> message_size);
    ptr += pkt -> message_size;

    memcpy(&(pkt -> pubkey_size), ptr, sizeof(pkt -> pubkey_size));
    ptr += sizeof(pkt -> pubkey_size);

    pkt -> pubkey = malloc(pkt -> pubkey_size);
    memcpy(pkt -> pubkey, ptr, pkt -> pubkey_size);
    ptr += pkt -> pubkey_size;

    memcpy(&(pkt -> sender_uuid), ptr, sizeof(pkt -> sender_uuid));
    ptr += sizeof(pkt -> sender_uuid);

    memcpy(&(pkt -> receiver_uuid), ptr, sizeof(pkt -> receiver_uuid));

    return pkt;
}

int ssl_send(SSL *ssl, packet *pkt) {
    unsigned int size;
    char *byte_array = packet_to_byte(pkt, &size);

    int sent = SSL_write(ssl, byte_array, size);
    free(byte_array);
    return sent;
}

int ssl_receive(SSL *ssl, packet **pkt) {
    unsigned int buffer_size = 4096 * 2;
    char buffer[buffer_size];
    int received = SSL_read(ssl, buffer, buffer_size);

    if (received <= 0) {
        int err = SSL_get_error(ssl, received);
        switch (err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                // Non-fatal, retryable error
                break;
            case SSL_ERROR_ZERO_RETURN:
                fprintf(stderr, "SSL connection has been closed gracefully.\n");
                break;
            default:
                fprintf(stderr, "SSL read error %d! Connection Broken. Terminating Thread...\n", err);
                fprintf(stderr, "Error message :\n");
                ERR_print_errors_fp(stdout);  // prints ssl error to stderr
                break;
        }
        return -1;
    }

    *pkt = byte_to_packet(buffer, received);

    return received;
}


packet* init_packet(){
    packet* new_packet = malloc(sizeof(packet));
    new_packet -> type = USER_HELLO;
    new_packet -> message_size = 0;
    new_packet -> message = NULL;
    new_packet -> pubkey_size = 0;
    new_packet -> pubkey = NULL;
    new_packet -> sender_uuid = 0;
    new_packet -> receiver_uuid = 0;

    return new_packet;
}



// Free'ing packet data.
int free_packet(packet* pkt) {
    if (pkt -> message != NULL) {
        free(pkt -> message);
    }

    if (pkt -> pubkey != NULL) {
        free(pkt -> pubkey);
    }

    free(pkt);
    return 1;
}

