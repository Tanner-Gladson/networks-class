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
#define DEFAULT_BUFFER_SIZE 2048

// Local function prototypes
int start_proxy(char *proxy_port);
int handle_connection(int client_fd);
int _attempt_handle_connection(int client_fd, struct ParsedRequest* request);
int parse_client_http_request(int client_fd, struct ParsedRequest* request);
int forward_http_request(struct ParsedRequest* request, char** response);
int open_proxy_listening_socket(char *proxy_port);
int open_server_socket(char *server_ip, char *server_port);
int send_text(int client_fd, char *data, int length);
int count_carriage_returns(const char* str, int length);
int recv_http_request(int socket_fd, char** buffer_pointer);


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

  #ifdef DEBUG_FLAG
    printf("Bound to socket. Waiting for connections...\n");
  #endif

  // Clients can connect whenever, we'll be listening
  struct sockaddr_storage client_addr;
  socklen_t sin_size = sizeof client_addr;
  int num_active_forks = 0;

  // TODO: do I need to add a signal handler for clean exit?
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
    if (client_fd == -1) {
      perror("Could not accept client conenction");
      continue;
    }
    if (!fork()) { 
      // entire child process
      close(sock_fd);
      handle_connection(client_fd);
      close(client_fd);
      exit(0);
    }
    num_active_forks++;
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
  int err = parse_client_http_request(client_fd, request);
  if (err == -501) {
    #ifdef DEBUG_FLAG
      printf("Failed to parse request, sending 501 error code\n");
    #endif
    send(client_fd, "HTTP/1.0 501 Not Implemented\r\n\r\n", 35, 0);
    return -1;
  } else if (err == -400) {
    #ifdef DEBUG_FLAG
      printf("Failed to parse request, sending 400 error code\n");
    #endif
    send(client_fd, "HTTP/1.0 400 Bad Request\r\n\r\n", 26, 0);
    return -1;
  }

  /* Forward request to server and receive response */
  char* response = NULL;
  int response_len = forward_http_request(request, &response);
  if (err == -400) {
    send(client_fd, "HTTP/1.0 400 Bad Request\r\n\r\n", 26, 0);
    return -1;
  } else if (response_len == -1) {
    return -1;
  }

  #ifdef DEBUG_FLAG
    printf("\nGot response of length %d\n", response_len);
    printf("Sending response back to client\n");
  #endif

  /* Send server's response back to the client */
  int success = send_text(client_fd, response, response_len);
  free(response);
  return success;
}


int parse_client_http_request(int client_fd, struct ParsedRequest* request) {

  /* Get the client's request */
  char* client_request = NULL;
  int request_size = recv_http_request(client_fd, &client_request);
  if (request_size == -1) {
    return -400;
  }

  #ifdef DEBUG_FLAG
    client_request[request_size] = '\0';
    printf("Client request: \n\n%s\n", client_request);
  #endif

  /* Parse the client's request */
  int err = ParsedRequest_parse(request, client_request, request_size);
  free(client_request);

  if (err < 0) {
    return -400;
  }
  if (strcmp(request->method, "GET") != 0) {
    return -501;
  }
  return 0;
}


int forward_http_request(struct ParsedRequest* request, char** response) {
  /* Recieve a dynamically allocated request, return a dynamically allocated response on success */
  
  /* Open a connection with the server */
  char port[6];
  if (request->port == NULL) {
    strcpy(port, "80"); // Defaul of 80
  } else {
    strcpy(port, request->port);
  }
  #ifdef DEBUG_FLAG
    printf("Connecting to server %s on port %s\n", port, request->host);
  #endif
  int server_fd = open_server_socket(request->host, port);
  if (server_fd == -1) {
    return -1;
  }

  /* Format the HTTP request for the server (we want to close the connection after retrieval) */
  if (ParsedHeader_set(request, "Connection", "close") == -1) {
    #ifdef DEBUG_FLAG
      printf("Failed to set 'Connection: close' header\n");
    #endif
    return -1;
  }
  if (ParsedHeader_set(request, "Host", request->host) == -1) {
    #ifdef DEBUG_FLAG
      printf("Failed to set 'Host: <host>' header\n");
    #endif
    return -1;
  }

  // Add the "GET <relativeURL> HTTP/1.0 \r\n"
  int buffer_len = ParsedRequest_totalLen(request); // Use buffer with copious space
  char *request_buffer = (char *)malloc(buffer_len + DEFAULT_BUFFER_SIZE);
  strcpy(request_buffer, request->method);
  strcat(request_buffer, " ");
  strcat(request_buffer, request->path);
  strcat(request_buffer, " ");
  strcat(request_buffer, "HTTP/1.0");
  strcat(request_buffer, "\r\n");
  int request_len = strlen(request_buffer);

  // Add the headers, followed by "\r\n"
  char * start = request_buffer + strlen(request_buffer);
  if(ParsedRequest_unparse_headers(request, start, buffer_len - strlen(request_buffer)) == -1) {
    #ifdef DEBUG_FLAG
      printf("Failed to unparse headers, returning 400 error code\n");
    #endif
    return -400;
  }
  request_len += ParsedHeader_headersLen(request);

  #ifdef DEBUG_FLAG
    int n_returns = count_carriage_returns(request_buffer, buffer_len);
    if (count_carriage_returns(request_buffer, buffer_len) != 2) {
      printf("Unparsed request has %d carriage returns\n", n_returns);
    }
  #endif

  #ifdef DEBUG_FLAG
    request_buffer[request_len]='\0';
    printf("Request sent to server: \n\n%s\n", request_buffer);
  #endif

  /* Send request to server */
  int status = send_text(server_fd, request_buffer, request_len);
  free(request_buffer);
  if (status == -1) {
    #ifdef DEBUG_FLAG
      printf("Failed to send request to server\n");
    #endif
    return -1;
  }

  /* Recieve response from the server */
  int response_size = recv_http_request(server_fd, response);
  if (response_size == -1) {
    #ifdef DEBUG_FLAG
      printf("Failed to receive response from server\n");
    #endif
    return -1;
  }

  /* We're good to return everything */
  #ifdef DEBUG_FLAG
    (*response)[response_size] = '\0';
    printf("Response: \n\n%s\n", *response);
  #endif

  if (close(server_fd) == -1) {
    perror("Error closing server connection\n");
  }
  return response_size;
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
    #ifdef DEBUG_FLAG
      fprintf(stderr, "Error getting address info. Error code: %d\n", err);
    #endif
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
    fprintf(stderr, "Proxy listening socket: failed to bind\n");
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

/* Reads an HTTP request from a socket. Buffer will have dyn allocated data on success */
int recv_http_request(int socket_fd, char** buffer_pointer) {
  int total_bytes_read = 0;
  int num_carriage_returns = 0;

  while (1) {
    *buffer_pointer = (char *) realloc(*buffer_pointer, (total_bytes_read + DEFAULT_BUFFER_SIZE + 1) * sizeof(char));
    int bytes_read = recv(socket_fd, *buffer_pointer + total_bytes_read, DEFAULT_BUFFER_SIZE, 0);
    
    if (bytes_read == -1) {
      #ifdef DEBUG_FLAG
        perror("Error receiving message");
      #endif
      free(*buffer_pointer);
      return -1;
    }
    if (bytes_read == 0) {
      free(*buffer_pointer);
      #ifdef DEBUG_FLAG
        perror("Connection closed by remote");
      #endif
      return -1;
    }

    // We can stop after seeing end of first line and headers. Count only in the newly read portion
    num_carriage_returns += count_carriage_returns(*buffer_pointer + total_bytes_read, bytes_read);
    total_bytes_read += bytes_read;
    if (num_carriage_returns >= 2) {
      break;
    }
  }
  return total_bytes_read;
}


int count_carriage_returns(const char* str, int length) {
  int count = 0;
  for (int i = 0; i < length - 1; i++) {
    if (str[i] == '\r' && str[i+1] == '\n') {
      count++;
    }
  }
  return count;
}
