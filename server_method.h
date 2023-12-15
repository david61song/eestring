#ifndef SERVER_METHOD_H
#define SERVER_METHOD_H

#include "list.h"
#include <time.h>
#include "packet.h"

typedef struct _userinfo{
    unsigned uuid;
    time_t show;
    char nickname[16];
    unsigned int pubkey_size;
    char* pubkey;
    SSL* ssl;
    struct list_elem elem;
}userinfo;




void check_connection(struct list* user_list);
packet* answer_user_list(struct list* user_list);
packet* answer_user_info(userinfo* user);
userinfo* search_user_by_uuid(struct list* user_list, unsigned uuid);
userinfo* new_user(packet* hello_packet, SSL* ssl);
char* get_user_pubkey(userinfo* user);
extern pthread_mutex_t user_mutex;
void remove_user_by_uuid(struct list* user_list, unsigned int uuid);
unsigned int pick_uuid_by_packet(userinfo* user);
packet* message_relay(packet* pkt);
packet* not_found(packet* pkt);
packet* server_hello(userinfo* new_user);
int is_ssl_alive(SSL* ssl);

#endif
