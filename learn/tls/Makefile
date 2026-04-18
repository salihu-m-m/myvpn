CC     = gcc
CFLAGS = -Wall -Wextra -g
# -lssl links the OpenSSL SSL library
# -lcrypto links the OpenSSL crypto library (SSL depends on it)
LIBS   = -lssl -lcrypto

all: tls_server tls_client

tls_server: tls_server.c
	$(CC) $(CFLAGS) -o tls_server tls_server.c $(LIBS)

tls_client: tls_client.c
	$(CC) $(CFLAGS) -o tls_client tls_client.c $(LIBS)

clean:
	rm -f tls_server tls_client
