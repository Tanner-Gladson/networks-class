#include "proxy_parse.h"
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
#include <netinet/tcp.h>

#define LISTEN_QUEUE_LEN 10
#define MAX_NUMBER_FORKS 100
#define MAX_BUFFER_SIZE 2048

int proxy(char *proxy_port);
int handle_connection();
void read_http_request();
void forward_http_request();
void return_http_request();

int main(int argc, char *argv[])
{
  char *proxy_port;

  if (argc != 2)
  {
    fprintf(stderr, "Usage: ./proxy <port>\n");
    exit(EXIT_FAILURE);
  }

  proxy_port = argv[1];
  return proxy(proxy_port);
}

/* TODO: proxy()
 * Establish a socket connection to listen for incoming connections.
 * Accept each client request in a new process.
 * Parse header of request and get requested URL.
 * Get data from requested remote server.
 * Send data to the client
 * Return 0 on success, non-zero on failure
 */
int proxy(char *proxy_port)
{
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
    return EXIT_FAILURE;
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
      return EXIT_FAILURE;
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
    return EXIT_FAILURE;
  }

  if (listen(sock_fd, LISTEN_QUEUE_LEN) == -1)
  {
    perror("Could not listen");
    return EXIT_FAILURE;
  }
  printf("Bound to socket. Waiting for connections...\n");

  // Clients can connect whenever, we'll be listening
  struct sockaddr_storage client_addr;
  socklen_t sin_size = sizeof client_addr;
  while (1)
  {
    // We must accept connections
    int client_fd = accept(sock_fd, (struct sockaddr *) &client_addr, &sin_size);
    if (client_fd == -1)
    {
      perror("Could not accept client conenction");
      continue;
    }

    printf("Accepted message, forking a child\n");
    if (!fork())
    { 
      // entire child process
      close(sock_fd);
      handle_connection(client_fd, &client_addr);
      close(client_fd);
      exit(0);
    }
    close(client_fd);
  }
  
  // TODO: do I need to wait on all child processes?
  return EXIT_SUCCESS;
}

int handle_connection(int client_fd, struct sockaddr_storage* client_addr)
{
  // Grab the client's IP and print (just for fun)
  char s[INET6_ADDRSTRLEN];
  inet_ntop(
    client_addr->ss_family, 
    get_in_addr((struct sockaddr *) client_addr), 
    s, 
    sizeof s
  );
  printf("server: got connection from %s\n", s);

  // Need to parse/reformat and validate the client's HTTP requests
  struct ParsedRequest* request = ParsedRequest_create();
  void read_http_request(client_fd, request);

  // Now, we need to forward that request
  char response[MAX_BUFFER_SIZE];
  void forward_http_request();

  // The returned HTTP is directly sent to the client
  void return_http_request(client_fd, response);

  // Clean up the connection
  ParsedRequest_destroy(request);
  int err = close(client_fd);
  if (err == -1)
  {
    perror("Error closing client connection\n");
    return;
  }
}


void read_http_request(int client_fd, struct ParsedRequest* request) {
  // Read in from raw text and parse into HTTP
  char rx_buffer[MAX_BUFFER_SIZE];
  int bytes_rx = recv(client_fd, rx_buffer, sizeof rx_buffer, 0);
  
  if (ParsedRequest_parse(request, rx_buffer, sizeof rx_buffer) < 0) {
      printf("parse failed\n");
      return -1; // TODO: Bad request
  }

  // We only need to support GET requests
  if (strcmp(request->method, "GET") != 0) {
    return -1; // TODO: Not implimented
  }

  // TODO: check that GET request is formatted correctly (do I really need this?)


  // TODO: return data necessary for forwarding (which is what?)


  // EXAMPLE: unparsing back into HTTP, accounts for modifications to ParsedRequest
  int request_len = ParsedRequest_totalLen(req);
  char *return_buffer = (char *) malloc(request_len+1);
  if (ParsedRequest_unparse(request, return_buffer, request_len) < 0) {
    printf("unparse failed\n");
    return -1;
  }
  return_buffer[request_len]='\0';
  free(return_buffer);

  // EXAMPLE: getting header information. Why would I need?
  struct ParsedHeader *r = ParsedHeader_get(request, "If-Modified-Since");
  printf("Modified value: %s\n", r->value);

}


void forward_http_request() {
  // TODO: establish connection with server
  // TODO: send HTTP request to server
  // TODO: close connection with server?
  // TODO: return the HTTP response
}


void return_http_request(int client_fd) {
  // TODO: write HTTP response to the client's fd
}




  