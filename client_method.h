#ifndef USER_METHOD_H
#define USER_METHOD_H

#include <openssl/ssl.h>
#include "packet.h"
#include "encrypt.h"
#include <assert.h>
#include <unistd.h>


struct user_pubkeys{
    char* pubkey;
    unsigned int uuid;
    struct list_elem elem;
}user_pubkeys;

extern pthread_mutex_t cli_mutex;
extern struct list pubkey_list;
extern bool pubkey_list_updated;


void show_user_list(char* message);
unsigned int say_hello(SSL* ssl, char* username,char* pubkey);
void first_message(unsigned int uuid);
packet* request_send_message(SSL* ssl, unsigned int receiver_uuid, char* message, unsigned int sender_uuid,struct list* pubkey_list);
packet* request_user_list();
packet* request_user_info(unsigned int target_uuid);
char* return_user_pubkey(struct list* pubkey_list, unsigned int uuid);
#endif
