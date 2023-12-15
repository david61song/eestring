#include "packet.h"
#include "server_method.h"
#include <openssl/ssl.h>
#include <string.h>
#include <assert.h>

userinfo* new_user(packet* hello_pkt, SSL* ssl){
    userinfo* new = malloc(sizeof(userinfo));

    new -> show = time(NULL);
    strcpy(new -> nickname, hello_pkt -> message);
    new -> pubkey_size = hello_pkt -> pubkey_size;
    new -> pubkey = malloc(sizeof(char) * (new -> pubkey_size));
    strcpy(new -> pubkey, hello_pkt -> pubkey);
    srand(new->show);
    new -> uuid = (unsigned int) rand() % 100000; // random uuid
    new -> ssl = ssl;

    return new;
}

void remove_user_by_uuid(struct list* user_list, unsigned int uuid) {
    struct list_elem* e;

    for (e = list_begin(user_list); e != list_end(user_list); e = list_next(e)) {
        userinfo* u = list_entry(e, userinfo, elem);
        if (u -> uuid == uuid) {
            list_remove(e);
            /* Not certain if u is dynamically allocated?
            free(u -> pubkey);
            free(u);
            */
            break;
        }
    }
}


packet* answer_user_list(struct list* user_list) {
    // Lock the user list to ensure thread safety.
    pthread_mutex_lock(&user_mutex);

    // Start with an empty string for the user list.
    char* user_list_str = malloc(MAX_MSG_SIZE);
    memset(user_list_str, 0, MAX_MSG_SIZE);
    size_t current_size = 0;

    // Iterate over the user list.
    for (struct list_elem* e = list_begin(user_list); e != list_end(user_list); e = list_next(e)) {
        userinfo* user = list_entry(e, userinfo, elem);

        // Prepare the user info string.
        char user_info[100];
        snprintf(user_info, sizeof(user_info), "UUID: %u, Nickname: %s\n", user -> uuid, user -> nickname);

        // Check if we can add this user info to our string.
        size_t needed_size = strlen(user_info);
        if (current_size + needed_size < MAX_MSG_SIZE) {
            strcat(user_list_str, user_info);
            current_size += needed_size;
        } else {
            // If we're out of space, break the loop.
            break;
        }
    }

    // Unlock the user list.
    pthread_mutex_unlock(&user_mutex);

    // Create a packet to send.
    packet* response_packet = init_packet();
    response_packet->type = ANSWER_USER_LIST;
    response_packet->message_size = strlen(user_list_str);
    response_packet->message = user_list_str;

    return response_packet;
}


userinfo* search_user_by_uuid(struct list* user_list, unsigned uuid){
    struct list_elem* e;
    userinfo* u = NULL;


    for (e = list_begin(user_list); e != list_end(user_list); e = list_next(e)) {
        u = list_entry(e, userinfo, elem);
        if (u -> uuid == uuid) {
            return u;
        }
    }
    return NULL;
}




// travelsal user list and find certain uuid user's pubkey
char* get_user_pubkey(userinfo* user){
   char* pubkey_to_return;
   int size;

   size = strlen(user -> pubkey);
   pubkey_to_return = malloc(sizeof(char) * size);
   strcpy(pubkey_to_return, user -> pubkey);

   return pubkey_to_return;
}


packet* answer_user_info(userinfo* user){
    packet* result = init_packet();
    char* pubkey = get_user_pubkey(user);

    if(pubkey == NULL)
        return NULL;

    assert (pubkey != NULL);

    result -> timestamp = time(NULL);
    result -> type = ANSWER_USER_INFO;
    result -> message_size = 0;
    result -> message = NULL;
    result -> pubkey_size = strlen(pubkey);
    result -> pubkey = pubkey;
    result -> sender_uuid = 0;
    result -> receiver_uuid = user -> uuid;

    return result;
}

packet* message_relay(packet* pkt){
    packet* result = init_packet();

    result -> timestamp = time(NULL);
    result -> type = DELIVER_MESSAGE;
    result -> message_size = pkt -> message_size;
    result -> message = malloc(sizeof(char) * result -> message_size + 1);
    strcpy(result -> message, pkt -> message);
    result -> pubkey = pkt -> pubkey;
    result -> sender_uuid = pkt -> sender_uuid;
    result -> receiver_uuid = pkt -> receiver_uuid;

    printf("===================================================\n");
    printf("User %u send message to User %u\n",pkt -> sender_uuid, pkt -> receiver_uuid);
    printf("%s\n", pkt -> message);
    printf("===================================================\n");

    return result;
}

packet* not_found(packet* pkt){
    packet* result = init_packet();
    result -> timestamp = time(NULL);
    result -> type = SERVER_MSG;
    result -> message_size = strlen("Requested User not found!\n");
    result -> message = malloc(sizeof(char) * result -> message_size + 1);
    strcpy(result -> message, "Requested User not found!\n");
    result -> sender_uuid = 0;
    result -> receiver_uuid = pkt -> sender_uuid;

    return result;
}


packet* server_hello(userinfo* new_user){
    packet* result = init_packet();

    result -> timestamp = time(NULL);
    result -> type = SERVER_HELLO;
    result -> message_size = 0;
    result -> message = NULL;
    result -> sender_uuid = 0;
    result -> receiver_uuid = new_user -> uuid;

    return result;
}
