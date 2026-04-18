#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>      // va_list for log_msg
#include <time.h>         // timestamps
#include <signal.h>
#include <pthread.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_PACKET 4096
#define LOG_FILE   "/tmp/vpnd.log"

/* ── Config struct ─────────────────────────────────────────── */
typedef struct {
    int  port;
    char ca_cert[256];
    char srv_cert[256];
    char srv_key[256];
    char tun_ip[32];
    char tun_name[IFNAMSIZ];
} vpn_config;

/* ── Global shutdown flag ──────────────────────────────────── */
volatile sig_atomic_t running = 1;

/* ── Logging ───────────────────────────────────────────────── */
void log_msg(const char *fmt, ...) {
    time_t now = time(NULL);
    char   ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));

    va_list args;
    va_start(args, fmt);
    fprintf(stdout, "[%s] ", ts);
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");
    va_end(args);
    fflush(stdout);
}

/* ── Signal handlers ───────────────────────────────────────── */
void handle_shutdown(int sig) { (void)sig; running = 0; }
void handle_sigchld(int sig)  {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

/* ── TUN device open ───────────────────────────────────────── */
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
    return fd;
}

/* ── Framing (identical to Phase 4/5) ──────────────────────── */
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

/* ── Tunnel threads (identical to Phase 5) ─────────────────── */
typedef struct { SSL *ssl; int tun_fd; } tunnel_ctx;

void* tls_to_tun(void *arg) {
    tunnel_ctx *ctx = (tunnel_ctx*)arg;
    uint8_t buf[MAX_PACKET]; int len;
    while ((len = recv_packet(ctx->ssl, buf, MAX_PACKET)) > 0)
        write(ctx->tun_fd, buf, len);
    return NULL;
}
void* tun_to_tls(void *arg) {
    tunnel_ctx *ctx = (tunnel_ctx*)arg;
    uint8_t buf[MAX_PACKET]; int len;
    while ((len = read(ctx->tun_fd, buf, MAX_PACKET)) > 0)
        send_packet(ctx->ssl, buf, len);
    return NULL;
}

/* ── Handle one client — runs in child process ─────────────── */
void handle_client(int client_fd, SSL_CTX *ssl_ctx,
                    vpn_config *cfg, int client_num) {
    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl); close(client_fd); return;
    }
    log_msg("Client %d authenticated — cipher: %s",
            client_num, SSL_get_cipher(ssl));

    /* Each client gets its own TUN device */
    char tun_name[IFNAMSIZ];
    snprintf(tun_name, IFNAMSIZ, "tun%d", client_num);
    int tun_fd = tun_open(tun_name);
    if (tun_fd < 0) { SSL_free(ssl); close(client_fd); return; }

    char cmd[128], tun_ip[32];
    snprintf(tun_ip, sizeof(tun_ip), "10.8.0.%d/24", client_num + 1);
    snprintf(cmd, sizeof(cmd),
             "ip addr add %s dev %s && ip link set %s up",
             tun_ip, tun_name, tun_name);
    system(cmd);
    log_msg("TUN %s up with IP %s", tun_name, tun_ip);

    tunnel_ctx ctx = { .ssl = ssl, .tun_fd = tun_fd };
    pthread_t t1, t2;
    pthread_create(&t1, NULL, tls_to_tun, &ctx);
    pthread_create(&t2, NULL, tun_to_tls, &ctx);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    log_msg("Client %d disconnected", client_num);
    SSL_shutdown(ssl); SSL_free(ssl);
    close(client_fd); close(tun_fd);
}

/* ── Load config from file ─────────────────────────────────── */
void load_config(vpn_config *cfg, const char *path) {
    /* Defaults */
    cfg->port = 9000;
    strcpy(cfg->ca_cert,  "../../pki/ca/ca.crt");
    strcpy(cfg->srv_cert, "../../pki/server/server.crt");
    strcpy(cfg->srv_key,  "../../pki/server/server.key");
    strcpy(cfg->tun_ip,   "10.8.0.1/24");
    strcpy(cfg->tun_name, "tun0");

    FILE *f = fopen(path, "r");
    if (!f) { log_msg("No config at %s — using defaults", path); return; }

    char line[256], key[64], val[192];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (sscanf(line, "%63s = %191s", key, val) != 2) continue;
        if      (strcmp(key, "port")     == 0) cfg->port = atoi(val);
        else if (strcmp(key, "ca_cert")  == 0) strcpy(cfg->ca_cert,  val);
        else if (strcmp(key, "srv_cert") == 0) strcpy(cfg->srv_cert, val);
        else if (strcmp(key, "srv_key")  == 0) strcpy(cfg->srv_key,  val);
        else if (strcmp(key, "tun_ip")   == 0) strcpy(cfg->tun_ip,   val);
    }
    fclose(f);
    log_msg("Config loaded from %s", path);
}

int main(int argc, char *argv[]) {

    /* ── Load config ────────────────────────────────────────── */
    vpn_config cfg;
    const char *cfgpath = (argc > 1) ? argv[1] : "../../config/server.conf";
    load_config(&cfg, cfgpath);

    /* ── Register signal handlers ───────────────────────────── */
    signal(SIGINT,  handle_shutdown);
    signal(SIGTERM, handle_shutdown);
    signal(SIGCHLD, handle_sigchld);
    signal(SIGPIPE, SIG_IGN);

    /* ── TLS context ────────────────────────────────────────── */
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate_file(ssl_ctx, cfg.srv_cert, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ssl_ctx, cfg.srv_key, SSL_FILETYPE_PEM);
    SSL_CTX_load_verify_locations(ssl_ctx, cfg.ca_cert, NULL);
    SSL_CTX_set_verify(ssl_ctx,
        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    /* ── TCP socket ─────────────────────────────────────────── */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(cfg.port);
    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 10);   // backlog 10 — support up to 10 queued
    log_msg("vpnd listening on port %d", cfg.port);

    /* ── Main accept loop ───────────────────────────────────── */
    int client_count = 0;
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);

    while (running) {
        int client_fd = accept(server_fd,
                               (struct sockaddr*)&client_addr, &addrlen);
        if (client_fd < 0) continue;

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        log_msg("Connection from %s", ip);

        client_count++;
        pid_t pid = fork();

        if (pid == 0) {
            close(server_fd);
            handle_client(client_fd, ssl_ctx, &cfg, client_count);
            exit(0);
        } else {
            close(client_fd);
            log_msg("Spawned handler PID %d for client %d",
                    pid, client_count);
        }
    }

    /* ── Graceful shutdown ──────────────────────────────────── */
    log_msg("Shutting down vpnd...");
    close(server_fd);
    SSL_CTX_free(ssl_ctx);
    log_msg("vpnd stopped");
    return 0;
}
