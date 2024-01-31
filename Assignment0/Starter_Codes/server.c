#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>

#define QUEUE_LENGTH 10
#define RECV_BUFFER_SIZE 2048

/* TODO: server()
 * Open socket and wait for client to connect
 * Print received message to stdout
 * Return 0 on success, non-zero on failure
*/
int server(char *server_port) {
  // First we need to store this server's TCP/IP info 
  struct addrinfo hints, *serverinfo, *p;
  struct sockaddr_storage client_addr;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
  hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
  hints.ai_flags = AI_PASSIVE;      // Use host IP

  int err = getaddrinfo(NULL, server_port, &hints, &serverinfo);
  if (err != 0) {
    fprintf(stderr, "Error getting addr info");
    return EXIT_FAILURE;
  }

  // loop through all the results and bind to the first we can
  int yes = 1;
  int sock_fd;
  for(p = serverinfo; p != NULL; p = p->ai_next) {
    if ((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("Error opening socket");
      continue;
    }

    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
      perror("Error setting socket options");
      return EXIT_FAILURE;
    }

    if (bind(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sock_fd);
      perror("Error binding socket");
      continue;
    }
    break;
  }
  freeaddrinfo(serverinfo);
  if (p == NULL)  {
    fprintf(stderr, "server: failed to bind\n");
    return EXIT_FAILURE;
  }

  if (listen(sock_fd, QUEUE_LENGTH) == -1) {
    perror("Could not listen");
    return EXIT_FAILURE;
  }

  // Clients can connect whenever, we'll be listening
  char rx_buffer[RECV_BUFFER_SIZE];
  while (1) {
    // We must accept connections
    socklen_t sin_size = sizeof client_addr;
    int client_fd = accept(sock_fd, (struct sockaddr *)&client_addr, &sin_size);
    if (client_fd == -1) {
        perror("accept");
        continue;
    }

    // TODO: is this necessary?
    // char s[INET6_ADDRSTRLEN];
    // inet_ntop(client_addr.ss_family, get_in_addr((struct sockaddr *)&client_addr), s, sizeof s);

    // Connection successful, so we can read off data
    int bytes_rx = recv(client_fd, rx_buffer, RECV_BUFFER_SIZE-1, 0);
    if (bytes_rx == -1) {
      perror("Error reading message");
      continue;
    } else if (bytes_rx == 0) {
      printf("Client closed connection");
    }

    fwrite(rx_buffer, sizeof rx_buffer[0], bytes_rx, stdout);
    err = close(client_fd);
    if (err == -1) {
      perror("Error closing client connection");
      continue;
    }
  }
}

/*
 * main():
 * Parse command-line arguments and call server function
*/
int main(int argc, char **argv) {
  char *server_port;

  if (argc != 2) {
    fprintf(stderr, "Usage: ./server-c [server port]\n");
    exit(EXIT_FAILURE);
  }

  server_port = argv[1];
  return server(server_port);
}
