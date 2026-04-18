#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>   // SSL_CTX, SSL, SSL_accept etc.
#include <openssl/err.h>   // ERR_print_errors_fp()

#define PORT        9000
#define BUFFER_SIZE 1024

#define CA_CERT     "../../pki/ca/ca.crt"
#define CLI_CERT    "../../pki/clients/mubby/mubby.crt"
#define CLI_KEY     "../../pki/clients/mubby/mubby.key"

int main () {
 SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { ERR_print_errors_fp(stderr); exit(1); }
     
    if (SSL_CTX_use_certificate_file(ctx, CLI_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, CLI_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); exit(1);
    
    }
    SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
     int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    if (connect(sock_fd, (struct sockaddr*)&server_addr,
                sizeof(server_addr)) == -1) {
        perror("connect"); exit(1);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock_fd);

     if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr); exit(1);
    }

    printf("[+] TLS connected — cipher: %s\n", SSL_get_cipher(ssl));

      char buffer[BUFFER_SIZE];
    int  bytes;

    while (1) {
        printf("Enter message (or 'quit'): ");
        fgets(buffer, BUFFER_SIZE, stdin);
        if (strncmp(buffer, "quit", 4) == 0) break;

        SSL_write(ssl, buffer, strlen(buffer));

        bytes = SSL_read(ssl, buffer, BUFFER_SIZE);
        buffer[bytes] = '\0';
        printf("[<] Echo: %s", buffer);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock_fd);
    SSL_CTX_free(ctx);
    printf("[*] Disconnected\n");
    return 0;
}



