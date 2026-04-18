#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>        // threads
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
#define SRV_CERT   "../../pki/server/server.crt"
#define SRV_KEY    "../../pki/server/server.key"
#define TUN_IP     "10.8.0.1/24"   // server tunnel address

/* ── tun_open() — same as Step 2 ────────────────────────── */
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

/* ── Framing functions — identical to Phase 4 ────────────── */
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

/* ── Thread context — passed to both threads ─────────────── */
typedef struct {
    SSL *ssl;
    int  tun_fd;
} tunnel_ctx;

/* ── Thread 1: TLS → TUN ───────────────────────────────────
   Receives encrypted packets from client, injects into kernel */
void* tls_to_tun(void *arg) {
    tunnel_ctx *ctx = (tunnel_ctx*)arg;
    uint8_t buf[MAX_PACKET];
    int len;
    while ((len = recv_packet(ctx->ssl, buf, MAX_PACKET)) > 0) {
        printf("[>] TLS→TUN %d bytes\n", len);
        write(ctx->tun_fd, buf, len);   // inject into kernel
    }
    return NULL;
}

/* ── Thread 2: TUN → TLS ───────────────────────────────────
   Reads outgoing packets from kernel, sends to client        */
void* tun_to_tls(void *arg) {
    tunnel_ctx *ctx = (tunnel_ctx*)arg;
    uint8_t buf[MAX_PACKET];
    int len;
    while ((len = read(ctx->tun_fd, buf, MAX_PACKET)) > 0) {
        printf("[<] TUN→TLS %d bytes\n", len);
        send_packet(ctx->ssl, buf, len); // send to client
    }
    return NULL;
}

int main() {
    /* ── TLS setup (identical to Phase 4) ──────────────────── */
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate_file(ssl_ctx, SRV_CERT, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ssl_ctx, SRV_KEY, SSL_FILETYPE_PEM);
    SSL_CTX_load_verify_locations(ssl_ctx, CA_CERT, NULL);
    SSL_CTX_set_verify(ssl_ctx,
        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

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
    printf("[*] VPN server listening on port %d\n", PORT);

    socklen_t addrlen = sizeof(addr);
    int client_fd = accept(server_fd,
                           (struct sockaddr*)&addr, &addrlen);
    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, client_fd);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr); exit(1);
    }
    printf("[+] Client connected and authenticated\n");

    /* ── Open TUN device ────────────────────────────────────── */
    char tun_name[IFNAMSIZ] = "tun0";
    int  tun_fd = tun_open(tun_name);
    if (tun_fd < 0) exit(1);

    /* ── Assign IP to TUN interface ─────────────────────────── */
    char cmd[128];
    snprintf(cmd, sizeof(cmd),
             "ip addr add %s dev %s && ip link set %s up",
             TUN_IP, tun_name, tun_name);
    system(cmd);
    printf("[*] TUN IP set: %s\n", TUN_IP);

    /* ── Start two threads — one per traffic direction ──────── */
    tunnel_ctx ctx = { .ssl = ssl, .tun_fd = tun_fd };
    pthread_t t1, t2;
    pthread_create(&t1, NULL, tls_to_tun, &ctx);
    pthread_create(&t2, NULL, tun_to_tls, &ctx);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    SSL_shutdown(ssl); SSL_free(ssl);
    close(client_fd); close(server_fd);
    SSL_CTX_free(ssl_ctx);
    return 0;
}