#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "socket.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>

int create_socket_server(int port, char* address){
    // initiate socket and binding and listening
    int sd;
    struct sockaddr_in sock_in;

    memset((char *)&sock_in, '\0', sizeof(sock_in));
    sock_in.sin_family = AF_INET;
    sock_in.sin_port = htons(port);
    sock_in.sin_addr.s_addr = inet_addr(address);

    // socket generate
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("creating socket failed:");
        exit(1);
    }
    if (bind(sd, (struct sockaddr *)&sock_in, sizeof(sock_in)) == -1) {
        perror("socket binding failed:");
        exit(1);
    }
    if (listen(sd, 5) < 0){
        perror("listening to socket failed:");
        exit(1);
    }
    return sd;
}

int open_connection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in serv_addr;
    if ((host = gethostbyname(hostname)) == NULL){
        perror(hostname);
        printf("Failed to Connect EEstring Server.\n");
        printf("Exiting...\n");
        exit(1);
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&serv_addr, sizeof(serv_addr));


    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = *(long*)(host -> h_addr_list[0]);


    if(connect(sd, (struct sockaddr*)&(serv_addr), sizeof(serv_addr)) != 0){
        close(sd);
        perror(hostname);
        printf("Exiting...\n");
        exit(1);
    }
    return sd;
}
