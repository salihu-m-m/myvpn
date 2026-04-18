#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT       9000
#define MAX_PACKET 4096
#define CA_CERT    "../../pki/ca/ca.crt"
#define CLI_CERT   "../../pki/clients/mubby/mubby.crt"
#define CLI_KEY    "../../pki/clients/mubby/mubby.key"
#define TUN_IP     "10.8.0.2/24"   // client tunnel address
#define SERVER_IP  "127.0.0.1"     // where vpn_server is running

/* tun_open(), send_packet(), recv_packet() — identical to server */
int tun_open(char *dev) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open tun"); return -1; }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (*dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(fd, TUNSETIFF, (void*)&ifr) < 0) {
        perror("ioctl"); return -1;
    }
    strncpy(dev, ifr.ifr_name, IFNAMSIZ);
    printf("[*] TUN device: %s\n", dev);
    return fd;
}

int send_packet(SSL *ssl, const uint8_t *data, uint32_t len) {
    uint32_t net_len = htonl(len);
    if (SSL_write(ssl, &net_len, sizeof(net_len)) <= 0) return -1;
    if (SSL_write(ssl, data, len) <= 0) return -1;
    return 0;
}
int recv_packet(SSL *ssl, uint8_t *buf, uint32_t max) {
    uint32_t net_len;
    if (SSL_read(ssl, &net_len, sizeof(net_len)) <= 0) return -1;
    uint32_t len = ntohl(net_len);
    if (len == 0 || len > max) return -1;
    if (SSL_read(ssl, buf, len) <= 0) return -1;
    return len;
}

typedef struct { SSL *ssl; int tun_fd; } tunnel_ctx;

void* tls_to_tun(void *arg) {
    tunnel_ctx *ctx = (tunnel_ctx*)arg;
    uint8_t buf[MAX_PACKET];
    int len;
    while ((len = recv_packet(ctx->ssl, buf, MAX_PACKET)) > 0) {
        printf("[>] TLS→TUN %d bytes\n", len);
        write(ctx->tun_fd, buf, len);
    }
    return NULL;
}

void* tun_to_tls(void *arg) {
    tunnel_ctx *ctx = (tunnel_ctx*)arg;
    uint8_t buf[MAX_PACKET];
    int len;
    while ((len = read(ctx->tun_fd, buf, MAX_PACKET)) > 0) {
        printf("[<] TUN→TLS %d bytes\n", len);
        send_packet(ctx->ssl, buf, len);
    }
    return NULL;
}

int main() {
    /* ── TLS setup (identical to Phase 4 client) ───────────── */
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_use_certificate_file(ssl_ctx, CLI_CERT, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ssl_ctx, CLI_KEY, SSL_FILETYPE_PEM);
    SSL_CTX_load_verify_locations(ssl_ctx, CA_CERT, NULL);
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &srv.sin_addr);
    if (connect(sock_fd, (struct sockaddr*)&srv, sizeof(srv)) == -1) {
        perror("connect"); exit(1);
    }

    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sock_fd);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr); exit(1);
    }
    printf("[+] TLS connected to VPN server\n");

    /* ── Open TUN device ────────────────────────────────────── */
    char tun_name[IFNAMSIZ] = "tun1";   // tun1 so it doesn't clash with server
    int  tun_fd = tun_open(tun_name);
    if (tun_fd < 0) exit(1);

    char cmd[128];
    snprintf(cmd, sizeof(cmd),
             "ip addr add %s dev %s && ip link set %s up",
             TUN_IP, tun_name, tun_name);
    system(cmd);
    printf("[*] TUN IP set: %s\n", TUN_IP);

    /* ── Start two threads ──────────────────────────────────── */
    tunnel_ctx ctx = { .ssl = ssl, .tun_fd = tun_fd };
    pthread_t t1, t2;
    pthread_create(&t1, NULL, tls_to_tun, &ctx);
    pthread_create(&t2, NULL, tun_to_tls, &ctx);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    SSL_shutdown(ssl); SSL_free(ssl);
    close(sock_fd); SSL_CTX_free(ssl_ctx);
    return 0;
}