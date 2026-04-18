CC     = gcc
CFLAGS = -Wall -Wextra -g
LIBS   = -lssl -lcrypto -lpthread

vpnc: vpnc.c
	$(CC) $(CFLAGS) -o vpnc vpnc.c $(LIBS)

clean:
	rm -f vpnc