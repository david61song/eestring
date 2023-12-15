#include "client_method.h"


extern pthread_mutex_t cli_mutex;
extern struct list pubkey_list;
extern bool pubkey_list_updated;

void first_message(unsigned int uuid){
    system("clear");
    printf(
        "------------------------------------------------------------ \n"
        "------------------- Welcome to EEstring  ------------------- \n"
        "-----      Secure E2EE Message Exchange Server         ----- \n"
        "------------------------------------------------------------ \n"
        "Your UUID : <%u>\n"
        "Your Options:\n"
        "p :prints current active user lists in server\n"
        "u [uuid]: prints user information (PGP pubkey)\n"
        "s [uuid] [message]: send encrypted message to user\n"
        "x : exit EEstring \n"
        "h : prints this message \n"
        "Examples: s [uuid] Hello, World!\n"
        "------------------------------------------------------------ \n"
    ,uuid);
}


void show_user_list(char* message) {
    if (message == NULL) {
        printf("No user information available.\n");
        return;
    }

    printf("\n--------------------------------------\n");
    printf("Current Users:\n");
    printf("--------------------------------------\n");

    // each user's info is separated by a newline character.
    const char* delimiter = "\n";
    char* token = strtok(message, delimiter);

    while (token != NULL) {
        printf("%s\n", token);  // Print each user's info.
        token = strtok(NULL, delimiter);  // Get the next user's info.
    }

    printf("--------------------------------------\n");
}

// Send Packet whose type is "USER_HELLO".
unsigned int say_hello(SSL* ssl, char* username, char* pubkey) {
    // Initialize a new packet
    packet* hello_packet = malloc(sizeof(packet));
    packet* re = init_packet();
    int result = 0;
    int result_receive;
    int result_send;

    if (hello_packet == NULL) {
        // Handle memory allocation failure
        return 0;
    }

    // Set the packet type to USER_HELLO
    // This code make memory leaks. Modify Later.

    hello_packet -> type = USER_HELLO;
    hello_packet -> timestamp = time(NULL);                                                 // Current time as timestamp
    hello_packet -> message_size = strlen(username);                                        // No message in this packet
    hello_packet -> message = malloc(sizeof(char) * (hello_packet -> message_size + 1));    // malloc
    strcpy(hello_packet -> message, username);                                              // set username
    hello_packet -> pubkey_size = strlen(pubkey);
    hello_packet -> pubkey = malloc(sizeof(char) * hello_packet -> pubkey_size + 1);
    strcpy(hello_packet -> pubkey, pubkey);                                                  // pubkey
    hello_packet -> sender_uuid = 0;                                                          // UUID init to 0

    result_send = ssl_send(ssl, hello_packet);
    result_receive = ssl_receive(ssl, &re);
    if (result_send != -1 && result_send != -1){
        return (re -> receiver_uuid);
    }
    else return 0;

}


packet* request_send_message(SSL* ssl, unsigned int receiver_uuid, char* message, unsigned int sender_uuid, struct list* pubkey_list){

    char* pubkey;
    char* message_encrypted = NULL;
    packet* new_packet = init_packet();
    packet* query = request_user_info(receiver_uuid);

    ssl_send(ssl, query);

    pthread_mutex_lock(&cli_mutex);
    while (!pubkey_list_updated) {
        pthread_mutex_unlock(&cli_mutex);
        usleep(100000);
        pthread_mutex_lock(&cli_mutex);
    }
    pthread_mutex_unlock(&cli_mutex);

    pubkey = return_user_pubkey(pubkey_list, receiver_uuid);
    pubkey_list_updated = false;

    if (pubkey == NULL)
        return NULL;


    assert (message != NULL);
    message_encrypted = rsa_encrypt(pubkey, message, strlen(message));

    new_packet -> timestamp = time(NULL);
    new_packet -> type = REQUEST_SEND_MESSAGE;
    new_packet -> message_size = strlen(message_encrypted) + 1;
    new_packet -> message = malloc(sizeof(char) * new_packet -> message_size);
    strcpy(new_packet -> message, message_encrypted);

    new_packet -> pubkey = NULL;
    new_packet -> pubkey_size = 0;
    new_packet -> sender_uuid = sender_uuid;
    new_packet -> receiver_uuid = receiver_uuid;

    return new_packet;
}

packet* request_user_list(){
    packet* new_packet = init_packet();

    new_packet -> timestamp = time(NULL);
    new_packet -> type = REQUEST_USER_LIST;
    new_packet -> message_size = 0;
    new_packet -> message = NULL;

    new_packet -> pubkey = NULL;
    new_packet -> pubkey_size = 0;
    new_packet -> sender_uuid = 0;
    new_packet -> receiver_uuid = 0; //receiver is server
    return new_packet;
}

packet* request_user_info(unsigned int uuid){
    packet* new_packet = init_packet();

    new_packet -> timestamp = time(NULL);
    new_packet -> type = REQUEST_USER_INFO;
    new_packet -> message_size = 0;
    new_packet -> message = NULL;

    new_packet -> pubkey = NULL;
    new_packet -> pubkey_size = 0;
    new_packet -> sender_uuid = 0; //my uuid
    new_packet -> receiver_uuid = uuid; // we find receiver_uuid user
    return new_packet;
}

char* return_user_pubkey(struct list* pubkey_list, unsigned int certain_uuid){

    assert (pubkey_list != NULL);

    struct list_elem *e;
    for (e = list_begin(pubkey_list); e != list_end(pubkey_list); e = list_next(e)) {

        struct user_pubkeys *up = list_entry(e, struct user_pubkeys, elem);
        if (up -> uuid == certain_uuid) {
            return up -> pubkey;
        }
    }
    // UUID not found in the list, returns NULL
    return NULL;
}
