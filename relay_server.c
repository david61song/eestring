#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "socket.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "tls.h"
#include "server_method.h"

void* routine(void* arg);
int server_handler(SSL* ssl,packet* pkt);

struct list user_list;
pthread_mutex_t user_mutex = PTHREAD_MUTEX_INITIALIZER;


int main(int argc, char** argv) {
    int port = -1;
    char* server_address = NULL;
    SSL_CTX *ctx;
    int sd;
    SSL* ssl;
    int opt;
    unsigned int uuid;
    int sock_in;
    struct sockaddr_in cli_addr;
    socklen_t clilen = sizeof(cli_addr);
    int result;
    pthread_t tid;


   /* option parsing*/
   while ((opt = getopt(argc, argv, "p:a:")) != -1) {
    switch (opt) {
        case 'p':
            port = atoi(optarg);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "Invalid port number. Please enter a number between 1 and 65535.\n");
                exit(1);
            }
            break;
        case 'a':
            server_address = optarg;
            break;
        default: /* '?' */
            fprintf(stderr, "Usage: %s [-p port] [-a server address]\n", argv[0]);
            exit(1);
        }
    }

    /* Arguments Checking */
    if (port == -1 || server_address == NULL){
        printf("Invalid Arguments:\n");
        fprintf(stderr, "Usage: %s [-p port] [-a server address]\n", argv[0]);
        exit(1);
    }

    sock_in = create_socket_server(port, server_address);
    ctx = create_context();
    configure_context(ctx);

    /* user list init*/

    list_init(&user_list);

    while (1){
        /* accepting client connection*/
        sd = accept(sock_in, (struct sockaddr *)&cli_addr, &clilen);

        /* Do handshaking*/
        ssl = SSL_new(ctx);      /* create new SSL connection state */
        SSL_set_fd(ssl, sd);     /* bind SSL connection and socket*/

        if (pthread_create(&tid, NULL, routine, ssl) != 0) {
            perror("pthread_create");
        }
    }

    close(sock_in);
    return 0;
}

void* routine(void* arg) {
    SSL* ssl = (SSL* )arg;
    int result = 1;
    char* buffer;
    int received;

    pthread_detach(pthread_self());

    if (SSL_accept(ssl) <= 0){
        ERR_print_errors_fp(stderr);
        printf("Cannot Make SSL Handshake!\n");
        return NULL;
    }

    while(1)
    {
        packet* pkt;
        /*Server waits packet from user..*/
        received = ssl_receive(ssl, &pkt);

        if (received == -1){
            pthread_mutex_lock(&user_mutex);
            check_connection(&user_list);
            pthread_mutex_unlock(&user_mutex);
            return NULL;
        }
        server_handler(ssl, pkt);

    }

    return NULL;
}

/* check connection on all user in current user_list.*/
void check_connection(struct list* user_list) {
    struct list_elem *e;
    for (e = list_begin(user_list); e != list_end(user_list); e = list_next(e)) {
        userinfo* user = list_entry(e, userinfo, elem);
            if (!is_ssl_alive(user -> ssl)) {
                list_remove(&user->elem);
                //needs to be free'd
                break;
        }
    }
}

/* check ssl alive*/
int is_ssl_alive(SSL *ssl) {
    if (ssl == NULL) {
        return 0;
    }
    packet* check_pkt = init_packet();
    check_pkt -> type = CHECK_CONNECT;
    if (ssl_send(ssl, check_pkt) <= 0) { //connection failed
        free_packet(check_pkt);
        return 0;
    }
    free_packet(check_pkt);
    return 0;  // timed out
}


int server_handler(SSL* ssl, packet* pkt){

    packet* new_packet;
    userinfo* certain_user;
    /* User says Hello to Server*/

    if (pkt -> type == USER_HELLO){
        pthread_mutex_lock(&user_mutex);
        certain_user = new_user(pkt, ssl);
        list_push_front(&user_list, &(certain_user -> elem));
        pthread_mutex_unlock(&user_mutex);
        new_packet = server_hello(certain_user);
        ssl_send(ssl, new_packet);
        free_packet(new_packet);
        return 1;
    }

    /* Traversal user list and make strings in message pkt*/
    else if (pkt->type == REQUEST_USER_LIST){
        new_packet = answer_user_list(&user_list);
        ssl_send(ssl, new_packet);
	    free_packet(new_packet);
        return 1;
    }

    /* Search user by nickname, and returns in message pkt */
    else if (pkt -> type == REQUEST_USER_INFO){
	    pthread_mutex_lock(&user_mutex);
        certain_user = search_user_by_uuid(&user_list, pkt -> receiver_uuid);
        if (certain_user == NULL) // we failed to find certain user.
            new_packet = not_found(pkt);
        else
            new_packet = answer_user_info(certain_user);
	    pthread_mutex_unlock(&user_mutex);
	    ssl_send(ssl, new_packet);
        free_packet(new_packet);
        return 1;
    }

    else if (pkt->type == REQUEST_SEND_MESSAGE){
        pthread_mutex_lock(&user_mutex);
        certain_user = search_user_by_uuid(&user_list, pkt -> receiver_uuid);
        if (certain_user == NULL) // we failed to find certain user.
            new_packet = not_found(pkt);
        else
	        new_packet = message_relay(pkt);
	    pthread_mutex_unlock(&user_mutex);
        ssl_send(certain_user -> ssl, new_packet);
        free_packet(new_packet);
        return 1;
    }

    else{

        return 0;

    }

}


