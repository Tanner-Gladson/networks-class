CC=gcc
CFLAGS= -Wall

# Normal mode
all: proxy

proxy: proxy.c
	$(CC) $(CFLAGS) -o proxy_parse.o -c proxy_parse.c
	$(CC) $(CFLAGS) -o proxy.o -c proxy.c
	$(CC) $(CFLAGS) -o proxy proxy_parse.o proxy.o

clean:
	rm -f proxy *.o

# Debug mode
debug: CFLAGS += -g -DDEBUG_FLAG
debug: proxy

.PHONY: debug
