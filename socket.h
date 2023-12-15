#ifndef SOCKET_H
#define SOCKET_H

#include <sys/socket.h>

int create_socket_server(int port, char* address);
int open_connection(const char* hostname, int port);
#endif
