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

#define SEND_BUFFER_SIZE 2048


/* TODO: client()
 * Open socket and send message from stdin.
 * Return 0 on success, non-zero on failure
*/
int client(char *server_ip, char *server_port) {
  // Must "gracefully handle all errors returned by socket API". If the
  // function might set errno, call perror(). If the function does not set
  // errno, you can just print an error to std::err. "make sure to flush
  // stdout using fflush(stdout)"

  // Attempt to open a socket
  struct addrinfo hints, *serverinfo, *p;

  memset(&hints, 0, sizeof hints); 
  hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
  hints.ai_socktype = SOCK_STREAM; // TCP stream sockets

  // Prepare addrinfo so we can send data to server
  int err = getaddrinfo(server_ip, server_port, &hints, &serverinfo);
  if (err != 0) {
    fprintf(stderr, "Error getting addr info");
    return EXIT_FAILURE;
  }

  // Remark that the socket is IP agnostic?
  int sock_fd = socket(serverinfo->ai_family, serverinfo->ai_socktype, serverinfo->ai_protocol);
  if (sock_fd == -1) {
    perror("Error opening socket fd");
    return EXIT_FAILURE;
  }

  // Do we need to pass addrlen so that it can handle both IPv4 and IPv6?
  err = connect(sock_fd, serverinfo->ai_addr, serverinfo->ai_addrlen);
  if (err == -1) {
    perror("Error connecting to server");
    return EXIT_FAILURE;
  }

  // Read a message from stdin
  char msg[SEND_BUFFER_SIZE];
  int msg_len = read(STDIN_FILENO, msg, SEND_BUFFER_SIZE);
  if (msg_len == -1) {
    perror("Error reading message");
    return EXIT_FAILURE;
  }
  
  // Send the message. Sometimes we can't do it all at once
  int bytes_remaining = msg_len;
  while (bytes_remaining > 0) {
    int start_char = msg_len - bytes_remaining;
    
    int bytes_sent = send(sock_fd, msg, start_char, 0);
    if (bytes_sent == -1) {
      perror("Error sending message");
      return EXIT_FAILURE;
    }

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
int main(int argc, char **argv) {
  char *server_ip;
  char *server_port;

  if (argc != 3) {
    fprintf(stderr, "Usage: ./client-c [server IP] [server port] < [message]\n");
    exit(EXIT_FAILURE);
  }

  server_ip = argv[1];
  server_port = argv[2];
  return client(server_ip, server_port);
}
