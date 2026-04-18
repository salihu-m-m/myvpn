CC     = gcc
CFLAGS = -Wall -Wextra -g
LIBS   = -lssl -lcrypto -lpthread

all: vpn_server vpn_client

vpn_server: vpn_server.c
	$(CC) $(CFLAGS) -o vpn_server vpn_server.c $(LIBS)

vpn_client: vpn_client.c
	$(CC) $(CFLAGS) -o vpn_client vpn_client.c $(LIBS)

clean:
	rm -f vpn_server vpn_client
