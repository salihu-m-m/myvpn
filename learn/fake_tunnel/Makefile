CC     = gcc
CFLAGS = -Wall -Wextra -g
LIBS   = -lssl -lcrypto

all: forwarder fake_client

forwarder: forwarder.c
	$(CC) $(CFLAGS) -o forwarder forwarder.c $(LIBS)

fake_client: fake_client.c
	$(CC) $(CFLAGS) -o fake_client fake_client.c $(LIBS)

clean:
	rm -f forwarder fake_client
