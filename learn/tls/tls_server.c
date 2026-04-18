#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>   // SSL_CTX, SSL, SSL_accept etc.
#include <openssl/err.h>   // ERR_print_errors_fp()

#define PORT        9000
#define BUFFER_SIZE 1024

/* Cert paths — relative to where you run the binary from */
#define CA_CERT     "../../pki/ca/ca.crt"
#define SRV_CERT    "../../pki/server/server.crt"
#define SRV_KEY     "../../pki/server/server.key"

int main() {

    /* ── 1. Create SSL context ─────────────────────────────────
       TLS_server_method() = use TLS, server mode, auto version
       SSL_CTX holds config shared across all connections       */
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { ERR_print_errors_fp(stderr); exit(1); }

    /* ── 2. Load server certificate ────────────────────────────
       This is what the server presents to connecting clients   */
    if (SSL_CTX_use_certificate_file(ctx, SRV_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); exit(1);
    }

    /* ── 3. Load server private key ────────────────────────────
       Must match the certificate loaded above                  */
    if (SSL_CTX_use_PrivateKey_file(ctx, SRV_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); exit(1);
    }

    /* ── 4. Load CA cert + require client cert (mutual TLS) ────
       SSL_VERIFY_PEER       = verify the client's certificate
       SSL_VERIFY_FAIL_IF_NO_PEER_CERT = reject if no cert sent */
    SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL);
    SSL_CTX_set_verify(ctx,
        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    /* ── 5. TCP socket setup (identical to Phase 2) ────────────
    ──────────────────────────────────────────────────────── */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(PORT);

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 1);

    printf("[*] TLS server listening on port %d\n", PORT);

    /* ── 6. Accept TCP connection (same as Phase 2) ────────────
    ──────────────────────────────────────────────────────── */
    socklen_t addrlen = sizeof(addr);
    int client_fd = accept(server_fd,
                           (struct sockaddr*)&addr, &addrlen);

    /* ── 7. Create SSL object and attach to socket ─────────────
       SSL_new()     = new SSL connection object from context
       SSL_set_fd()  = bind this SSL object to the TCP socket   */
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    /* ── 8. TLS handshake ──────────────────────────────────────
       SSL_accept() runs the full TLS handshake:
       - sends server.crt to client
       - requests and verifies client cert (alice.crt)
       - negotiates cipher + session keys
       Returns 1 on success, <= 0 on failure                    */
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl); close(client_fd); exit(1);
    }

    printf("[+] TLS handshake complete — connection encrypted\n");
    printf("[+] Cipher: %s\n", SSL_get_cipher(ssl));

    /* ── 9. Encrypted echo loop ────────────────────────────────
       SSL_read / SSL_write replace read / write — same logic   */
    char buffer[BUFFER_SIZE];
    int bytes;
    while ((bytes = SSL_read(ssl, buffer, BUFFER_SIZE)) > 0) {
        buffer[bytes] = '\0';
        printf("[>] Received: %s", buffer);
        SSL_write(ssl, buffer, bytes);
    }

    printf("[-] Client disconnected\n");

    /* ── 10. Clean shutdown ────────────────────────────────────
       SSL_shutdown() sends TLS close_notify alert
       SSL_free()     releases the SSL object
       SSL_CTX_free() releases the context                      */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}










