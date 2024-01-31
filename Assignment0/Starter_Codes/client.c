#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define SEND_BUFFER_SIZE 2048

void *get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/* TODO: client()
 * Open socket and send message from stdin.
 * Return 0 on success, non-zero on failure
 */
int client(char *server_ip, char *server_port)
{
  // Must "gracefully handle all errors returned by socket API". If the
  // function might set errno, call perror(). If the function does not set
  // errno, you can just print an error to std::err. "make sure to flush
  // stdout using fflush(stdout)"

  // Attempt to open a socket
  struct addrinfo hints, *serverinfo, *p;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  int status = getaddrinfo(server_ip, server_port, &hints, &serverinfo);
  if (status != 0)
  {
    fprintf(stderr, "Error getting address info. Error code: %d\n", status);
    return 1;
  }

  // loop through all the results and connect to the first we can
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
    return 2;
  }

  char s[INET6_ADDRSTRLEN];
  inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
  printf("client: connecting to %s\n", s);
  freeaddrinfo(serverinfo); // all done with this structure

  // Read a message from stdin
  char msg[SEND_BUFFER_SIZE];
  int msg_len = read(STDIN_FILENO, msg, SEND_BUFFER_SIZE);
  if (msg_len == -1)
  {
    perror("Error reading message");
    return EXIT_FAILURE;
  }
  printf("Read %d bytes from stdin\n", msg_len);

  // Send the message. Sometimes we can't do it all at once
  int bytes_remaining = msg_len;
  while (bytes_remaining > 0)
  {
    int start_char = msg_len - bytes_remaining;

    int bytes_sent = send(sock_fd, msg, start_char, 0);
    if (bytes_sent == -1)
    {
      perror("Error sending message");
      return EXIT_FAILURE;
    }
    printf("Sent %d bytes to server\n", bytes_sent);
    exit(1);
    bytes_remaining -= bytes_sent;
  }

  close(sock_fd);
  freeaddrinfo(serverinfo); // free the linked-list
  fflush(stdout);
  return 0;
}

/*
 * main()
 * Parse command-line arguments and call client function
 */
int main(int argc, char **argv)
{
  char *server_ip;
  char *server_port;

  if (argc != 3)
  {
    fprintf(stderr, "Usage: ./client-c [server IP] [server port] < [message]\n");
    exit(EXIT_FAILURE);
  }

  server_ip = argv[1];
  server_port = argv[2];
  return client(server_ip, server_port);
}
