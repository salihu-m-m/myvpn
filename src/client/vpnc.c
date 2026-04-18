#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_PACKET 4096

typedef struct {
    int  port;
    char server_ip[64];
    char ca_cert[256];
    char cli_cert[256];
    char cli_key[256];
    char tun_ip[32];
    char tun_name[IFNAMSIZ];
} client_config;

volatile sig_atomic_t running = 1;
void handle_shutdown(int sig) { (void)sig; running = 0; }

void log_msg(const char *fmt, ...) {
    time_t now = time(NULL);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    va_list args;
    va_start(args, fmt);
    fprintf(stdout, "[%s] ", ts);
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");
    va_end(args);
    fflush(stdout);
}

/* tun_open, send_packet, recv_packet — identical to Phase 5 */
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
int send_packet(SSL *ssl, const uint8_t *d, uint32_t l) {
    uint32_t n = htonl(l);
    if (SSL_write(ssl,&n,sizeof(n))<=0) return -1;
    if (SSL_write(ssl,d,l)<=0) return -1;
    return 0;
}
int recv_packet(SSL *ssl, uint8_t *b, uint32_t m) {
    uint32_t n;
    if (SSL_read(ssl,&n,sizeof(n))<=0) return -1;
    uint32_t l=ntohl(n);
    if (l==0||l>m) return -1;
    if (SSL_read(ssl,b,l)<=0) return -1;
    return l;
}

typedef struct { SSL *ssl; int tun_fd; } tunnel_ctx;
void* tls_to_tun(void *a) {
    tunnel_ctx *c=(tunnel_ctx*)a; uint8_t b[MAX_PACKET]; int l;
    while((l=recv_packet(c->ssl,b,MAX_PACKET))>0) write(c->tun_fd,b,l);
    return NULL;
}
void* tun_to_tls(void *a) {
    tunnel_ctx *c=(tunnel_ctx*)a; uint8_t b[MAX_PACKET]; int l;
    while((l=read(c->tun_fd,b,MAX_PACKET))>0) send_packet(c->ssl,b,l);
    return NULL;
}

void load_config(client_config *cfg, const char *path) {
    cfg->port = 9000;
    strcpy(cfg->server_ip, "127.0.0.1");
    strcpy(cfg->ca_cert,   "../../pki/ca/ca.crt");
    strcpy(cfg->cli_cert,  "../../pki/clients/mubby/mubby.crt");
    strcpy(cfg->cli_key,   "../../pki/clients/mubby/mubby.key");
    strcpy(cfg->tun_ip,    "10.8.0.2/24");
    strcpy(cfg->tun_name,  "tun1");

    FILE *f = fopen(path, "r");
    if (!f) { log_msg("No config at %s — using defaults", path); return; }
    char line[256], key[64], val[192];
    while (fgets(line, sizeof(line), f)) {
        if (line[0]=='#'||line[0]=='\n') continue;
        if (sscanf(line,"%63s = %191s",key,val)!=2) continue;
        if      (!strcmp(key,"port"))      cfg->port=atoi(val);
        else if (!strcmp(key,"server_ip")) strcpy(cfg->server_ip,val);
        else if (!strcmp(key,"ca_cert"))   strcpy(cfg->ca_cert,val);
        else if (!strcmp(key,"cli_cert"))  strcpy(cfg->cli_cert,val);
        else if (!strcmp(key,"cli_key"))   strcpy(cfg->cli_key,val);
        else if (!strcmp(key,"tun_ip"))    strcpy(cfg->tun_ip,val);
        else if (!strcmp(key,"server"))    strcpy(cfg->server_ip,val);
    }
    fclose(f);
}

int main(int argc, char *argv[]) {
    client_config cfg;
    const char *cfgpath = (argc > 1) ? argv[1] : "../../config/client.conf";
    load_config(&cfg, cfgpath);

    signal(SIGINT,  handle_shutdown);
    signal(SIGTERM, handle_shutdown);
    signal(SIGPIPE, SIG_IGN);

    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_use_certificate_file(ssl_ctx, cfg.cli_cert, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ssl_ctx, cfg.cli_key, SSL_FILETYPE_PEM);
    SSL_CTX_load_verify_locations(ssl_ctx, cfg.ca_cert, NULL);
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(cfg.port);
    inet_pton(AF_INET, cfg.server_ip, &srv.sin_addr);
    if (connect(sock_fd,(struct sockaddr*)&srv,sizeof(srv))==-1) {
        perror("connect"); exit(1);
    }

    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sock_fd);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr); exit(1);
    }
    log_msg("Connected to %s:%d — cipher: %s",
            cfg.server_ip, cfg.port, SSL_get_cipher(ssl));

    char tun_name[IFNAMSIZ];
    strncpy(tun_name, cfg.tun_name, IFNAMSIZ);
    int tun_fd = tun_open(tun_name);
    if (tun_fd < 0) exit(1);

    char cmd[128];
    snprintf(cmd, sizeof(cmd),
             "ip addr add %s dev %s && ip link set %s up",
             cfg.tun_ip, tun_name, tun_name);
    system(cmd);
    log_msg("TUN %s up with IP %s", tun_name, cfg.tun_ip);

    tunnel_ctx ctx = { .ssl = ssl, .tun_fd = tun_fd };
    pthread_t t1, t2;
    pthread_create(&t1, NULL, tls_to_tun, &ctx);
    pthread_create(&t2, NULL, tun_to_tls, &ctx);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    log_msg("Disconnected — shutting down");
    SSL_shutdown(ssl); SSL_free(ssl);
    close(sock_fd); SSL_CTX_free(ssl_ctx);
    return 0;
}
