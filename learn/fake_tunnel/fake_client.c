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
#define CLI_CERT    "../../pki/clients/mubby/mubby.crt"
#define CLI_KEY     "../../pki/clients/mubby/mubby.key"

/* ── Framing functions (same as forwarder) ───────────────── */
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


void build_fake_packet(uint8_t *buf, uint32_t *len,
                         const char *src, const char *dst,
                         const char *payload) {
    uint32_t src_ip, dst_ip;
    inet_pton(AF_INET, src, &src_ip);
    inet_pton(AF_INET, dst, &dst_ip);

    memcpy(buf,     &src_ip, 4);   
    memcpy(buf + 4, &dst_ip, 4);   
    memcpy(buf + 8, payload, strlen(payload)); 
    *len = 8 + strlen(payload);
}

int main() {

    
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_use_certificate_file(ctx, CLI_CERT, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, CLI_KEY, SSL_FILETYPE_PEM);
    SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &srv.sin_addr);
    connect(sock_fd, (struct sockaddr*)&srv, sizeof(srv));

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock_fd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr); exit(1);
    }
    printf("[+] TLS connected — sending fake packets\n");

    uint8_t  pkt[MAX_PACKET];
    uint8_t  echo[MAX_PACKET];
    uint32_t pkt_len;

    const char *payloads[] = {
        "ping request  seq=1",
        "ping request  seq=2",
        "ping request  seq=3",
    };

    for (int i = 0; i < 3; i++) {

        
        build_fake_packet(pkt, &pkt_len,
            "10.0.0.2",     
            "10.0.0.1",    
            payloads[i]);

        printf("[>] Sending packet %d (%u bytes)\n", i+1, pkt_len);
        send_packet(ssl, pkt, pkt_len);

        
        int echo_len = recv_packet(ssl, echo, MAX_PACKET);
        printf("[<] Echo received (%d bytes)\n", echo_len);
    }

    SSL_shutdown(ssl); SSL_free(ssl);
    close(sock_fd); SSL_CTX_free(ctx);
    printf("[*] Done\n");
    return 0;
}