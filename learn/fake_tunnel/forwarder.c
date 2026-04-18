#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT        9000
#define MAX_PACKET  4096
#define CA_CERT     "../../pki/ca/ca.crt"
#define SRV_CERT    "../../pki/server/server.crt"
#define SRV_KEY     "../../pki/server/server.key"

/* ── Framing functions (same as Step 3) ──────────────────── */
int send_packet(SSL *ssl, const uint8_t *data, uint32_t len) {
    uint32_t net_len = htonl(len);
    if (SSL_write(ssl, &net_len, sizeof(net_len)) <= 0) return -1;
    if (SSL_write(ssl, data, len) <= 0) return -1;
    return 0;
}

int recv_packet(SSL *ssl, uint8_t *buf, uint32_t max_len) {
    uint32_t net_len;
    if (SSL_read(ssl, &net_len, sizeof(net_len)) <= 0) return -1;
    uint32_t len = ntohl(net_len);
    if (len == 0 || len > max_len) return -1;
    if (SSL_read(ssl, buf, len) <= 0) return -1;
    return len;
}

int main() {

    /* ── TLS setup (identical to Phase 3 server) ───────────── */
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate_file(ctx, SRV_CERT, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, SRV_KEY, SSL_FILETYPE_PEM);
    SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 1);

    printf("[*] Forwarder listening on port %d\n", PORT);

    socklen_t addrlen = sizeof(addr);
    int client_fd = accept(server_fd, (struct sockaddr*)&addr, &addrlen);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr); exit(1);
    }
    printf("[+] TLS handshake complete\n");

    /* ── Packet forwarding loop ────────────────────────────────
       recv_packet() reads a complete framed packet
       Print its contents, then echo it back with send_packet()
    ──────────────────────────────────────────────────────── */
    uint8_t buf[MAX_PACKET];
    int pkt_len;

    while ((pkt_len = recv_packet(ssl, buf, MAX_PACKET)) > 0) {
        buf[pkt_len] = '\0';
        printf("[>] Packet received (%d bytes): %s\n", pkt_len, buf);

        /* Echo the packet back */
        send_packet(ssl, buf, pkt_len);
    }

    printf("[-] Client disconnected\n");
    SSL_shutdown(ssl); SSL_free(ssl);
    close(client_fd); close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}