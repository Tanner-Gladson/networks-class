#include "proxy_parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>
#include <netinet/tcp.h>

#define LISTEN_QUEUE_LEN 10
#define MAX_NUMBER_FORKS 100
#define MAX_BUFFER_SIZE 2048

// Local function prototypes
int start_proxy(char *proxy_port);
int handle_connection(int client_fd);
int _attempt_handle_connection(int client_fd, struct ParsedRequest* request);
int read_http_request(int client_fd, struct ParsedRequest* request);
int forward_http_request(struct ParsedRequest* request, char* response_buffer, int buffer_len);
int open_proxy_listening_socket(char *proxy_port);
int open_server_socket(char *server_ip, char *server_port);
int send_text(int client_fd, char *data, int length);


int main(int argc, char *argv[])
{
  char *proxy_port;

  if (argc != 2)
  {
    fprintf(stderr, "Usage: ./proxy <port>\n");
    exit(EXIT_FAILURE);
  }

  proxy_port = argv[1];
  return start_proxy(proxy_port);
}


int start_proxy(char *proxy_port)
{
  int sock_fd = open_proxy_listening_socket(proxy_port);
  if (listen(sock_fd, LISTEN_QUEUE_LEN) == -1)
  {
    perror("Could not listen");
    return -1;
  }

  #ifdef DEBUG
    printf("Bound to socket. Waiting for connections...\n");
  #endif


  // Clients can connect whenever, we'll be listening
  struct sockaddr_storage client_addr;
  socklen_t sin_size = sizeof client_addr;
  int num_active_forks = 0;

  // TODO: do I need to add a signal handler?
  while (1)
  {
    // Reap zombies
    while (waitpid(-1, NULL, WNOHANG) > 0) {
      num_active_forks--;
    }

    // Limit number of forks, block until one dies
    while (num_active_forks >= MAX_NUMBER_FORKS) {
      waitpid(-1, NULL, 0);
      num_active_forks--;
    }
    
    // We must accept connections
    int client_fd = accept(sock_fd, (struct sockaddr *) &client_addr, &sin_size);
    if (client_fd == -1)
    {
      perror("Could not accept client conenction");
      continue;
    }

    #ifdef DEBUG // Debug with a single process, much easier
      printf("Accepted message, forking a child\n");
      handle_connection(client_fd);
    #else
      // TODO: limit number of forks
      if (!fork())
      { 
        // entire child process
        close(sock_fd);
        handle_connection(client_fd, &client_addr);
        close(client_fd);
        exit(0);
      }
      num_active_forks++;
    #endif
    close(client_fd);
  }
  
  // Reap zombies, blocking
  while (num_active_forks > 0) {
    waitpid(-1, NULL, 0);
    num_active_forks--;
  }
  return 0;
}


int handle_connection(int client_fd)
{
  struct ParsedRequest* request_buffer = ParsedRequest_create();
  int status = _attempt_handle_connection(client_fd, request_buffer);

  // Clean up the connection
  ParsedRequest_destroy(request_buffer);
  if (close(client_fd) == -1)
  {
    perror("Error closing client connection\n");
  }
  return status;
}


int _attempt_handle_connection(int client_fd, struct ParsedRequest* request) {
  /* Get client's requests */
  int err = read_http_request(client_fd, request);
  if (err == -501) {
    #ifdef DEBUG
      printf("Failed to parse request, sending 501 error code\n");
    #endif
    send(client_fd, "HTTP/1.0 501 Not Implemented\r\n\r\n", 35, 0);
    return -1;
  } else if (err == -400) {
    #ifdef DEBUG
      printf("Failed to parse request, sending 400 error code\n");
    #endif
    send(client_fd, "HTTP/1.0 400 Bad Request\r\n\r\n", 26, 0);
    return -1;
  }

  /* Forward request to server */
  char response[MAX_BUFFER_SIZE];
  int response_len = forward_http_request(request, response, sizeof response);
  if (err == -400) {
    send(client_fd, "HTTP/1.0 400 Bad Request\r\n\r\n", 26, 0);
    return -1;
  } else if (response_len == -1) {
    return -1;
  }

  /* Send server's response back to the client */
  return send_text(client_fd, response, response_len);
}


int read_http_request(int client_fd, struct ParsedRequest* request) {
  char rx_buffer[MAX_BUFFER_SIZE];
  int bytes_rx = recv(client_fd, rx_buffer, sizeof rx_buffer, 0);

  #ifdef DEBUG
    rx_buffer[bytes_rx] = '\0';
    printf("Request: \n\n%s\nAttempting to parse...\n", rx_buffer);
  #endif

  int err = ParsedRequest_parse(request, rx_buffer, sizeof rx_buffer);
  if (err < 0) {
    return -400;
  }
  if (strcmp(request->method, "GET") != 0) {
    return -501;
  }
  return 0;
}


int forward_http_request(struct ParsedRequest* request, char* response_buffer, int buffer_len) {
  // If hostname does not have a port, use 80
  char port[6];
  if (request->port == NULL) {
    strcpy(port, "80");
  } else {
    strcpy(port, request->port);
  }

  #ifdef DEBUG
    printf("Connecting to server %s on port %s\n", port, request->host);
  #endif
  int server_fd = open_server_socket(request->host, port);
  if (server_fd == -1) {
    return -1;
  }

  // Form the HTTP request for the server (we want to close the connection after retrieval)
  if (ParsedHeader_set(request, "Connection", "close") == -1) {
    #ifdef DEBUG
      printf("Failed to set 'Connection: close' header\n");
    #endif
    return -1;
  }

  int request_len = ParsedRequest_totalLen(request);
  char *request_buffer = (char *) malloc(request_len+1);
  if (ParsedRequest_unparse(request, request_buffer, request_len) == -1) {
    #ifdef DEBUG
      printf("Failed to unparse request, returning 400 error code\n");
    #endif
    free(request_buffer);
    return -400;
  }

  // Debug request
  #ifdef DEBUG
    request_buffer[request_len]='\0';
    printf("Request: \n\n%s\n", request_buffer);
  #endif

  // Send request to server
  send_text(server_fd, request_buffer, request_len);
  free(request_buffer);

  // Receive response from server
  int bytes_rx = recv(server_fd, response_buffer, buffer_len, 0);

  #ifdef DEBUG
    response_buffer[bytes_rx] = '\0';
    printf("Response: \n\n%s\n", request_buffer);
  #endif

  if (close(server_fd) == -1) {
    perror("Error closing server connection\n");
  }
  return bytes_rx;
}


int open_proxy_listening_socket(char *proxy_port) {
   // First we need to store this server's TCP/IP info
  struct addrinfo hints;
  struct addrinfo *serverinfo;
  struct addrinfo *p;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
  hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
  hints.ai_flags = AI_PASSIVE;     // Use host IP

  int err = getaddrinfo(NULL, proxy_port, &hints, &serverinfo);
  if (err != 0)
  {
    fprintf(stderr, "Error getting addr info");
    return -1;
  }

  // Bind our socket to the port
  int yes = 1;
  int sock_fd;
  for (p = serverinfo; p != NULL; p = p->ai_next)
  {
    if ((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
    {
      perror("Error opening socket");
      continue;
    }

    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
    {
      perror("Error setting socket options");
      return -1;
    }

    if (bind(sock_fd, p->ai_addr, p->ai_addrlen) == -1)
    {
      close(sock_fd);
      perror("Error binding socket");
      continue;
    }
    break;
  }
  freeaddrinfo(serverinfo);
  if (p == NULL)
  {
    fprintf(stderr, "server: failed to bind\n");
    return -1;
  }
  return sock_fd;
}


int open_server_socket(char *server_ip, char *server_port) {
  struct addrinfo hints, *serverinfo, *p;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  int status = getaddrinfo(server_ip, server_port, &hints, &serverinfo);
  if (status != 0)
  {
    fprintf(stderr, "Error getting address info. Error code: %d\n", status);
    return -1;
  }

  int sock_fd;
  for (p = serverinfo; p != NULL; p = p->ai_next)
  {
    if ((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
    {
      perror("client: socket");
      continue;
    }

    if (connect(sock_fd, p->ai_addr, p->ai_addrlen) == -1)
    {
      close(sock_fd);
      perror("client: connect");
      continue;
    }
    break;
  }

  if (p == NULL)
  {
    fprintf(stderr, "client: failed to connect\n");
    return -1;
  }
  return sock_fd;
}


int send_text(int client_fd, char *data, int length) {
  int bytes_remaining = length;
  while (bytes_remaining > 0)
  {
    int bytes_sent = send(client_fd, data + (length - bytes_remaining), bytes_remaining, 0);
    if (bytes_sent == -1)
    {
      perror("Error sending message");
      return -1;
    }
    bytes_remaining -= bytes_sent;
  }
  return 0;
}




  