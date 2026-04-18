CC     = gcc
CFLAGS = -Wall -Wextra -g
LIBS   = -lssl -lcrypto -lpthread

vpnd: vpnd.c
	$(CC) $(CFLAGS) -o vpnd vpnd.c $(LIBS)

clean:
	rm -f vpnd
