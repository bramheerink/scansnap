/*
 * scansnap - ScanSnap iX500 WiFi scanner driver for Linux
 *
 * Single-file C17 implementation, no external dependencies.
 * Speaks the VENS protocol over UDP/TCP to Fujitsu ScanSnap scanners.
 *
 * Usage: scansnap [options]
 *   -s IP       scanner IP (auto-discovers if omitted)
 *   -k KEY      pairing key (WiFi module serial)
 *   -o FILE     output filename (default: scan_YYYYMMDD_HHMM.pdf)
 *   -j          output as separate JPEG files instead of PDF
 *   -1          single-sided (discard back pages)
 *   -d          debug output
 *   -h          help
 *   --getkey    capture pairing key from ScanSnap Home
 *   --getkey-ip IP
 *               advertise this host IP in fake scanner mode
 *   --getkey-name NAME
 *               fake scanner device name (default: iX500-A0PB023744)
 *   --getkey-model MODEL
 *               fake scanner model string (default: ScanSnap iX500)
 *   --getkey-mac MAC
 *               fake scanner MAC (default: 00:80:92:58:c1:5c)
 *   --getkey-tail HEX
 *               8-byte hex tail for UDP device info response
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <poll.h>
#include <unistd.h>

#define MAX_PAGES    256
#define RECV_BUF     65536
#define MAX_PAYLOAD  (16 * 1024 * 1024)

static bool g_debug = false;
static volatile sig_atomic_t g_interrupted = 0;
static uint32_t g_scanner_ip = 0;
static uint8_t  g_mac[6] = {0};
static const char *g_pairing_key = NULL;
static char g_key_buf[64];

struct page { uint8_t *data; size_t len; };

/* ── Config ──────────────────────────────────────────────────────────── */

static void config_path(char *buf, size_t len) {
    const char *xdg = getenv("XDG_CONFIG_HOME");
    if (xdg && xdg[0])
        snprintf(buf, len, "%s/scansnap/key", xdg);
    else
        snprintf(buf, len, "%s/.config/scansnap/key", getenv("HOME"));
}

static const char *load_key(void) {
    char path[512];
    config_path(path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    if (!fgets(g_key_buf, sizeof(g_key_buf), f)) { fclose(f); return NULL; }
    fclose(f);
    /* strip newline */
    size_t len = strlen(g_key_buf);
    while (len > 0 && (g_key_buf[len-1] == '\n' || g_key_buf[len-1] == '\r'))
        g_key_buf[--len] = '\0';
    return len > 0 ? g_key_buf : NULL;
}

static int save_key(const char *key) {
    char path[512];
    config_path(path, sizeof(path));

    /* mkdir -p the directory */
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", path);
    for (char *p = dir + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(dir, 0755);
            *p = '/';
        }
    }

    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return -1; }
    fprintf(f, "%s\n", key);
    fclose(f);
    chmod(path, 0600);
    return 0;
}

/* ── Helpers ──────────────────────────────────────────────────────────── */

static int hex_decode(const char *hex, uint8_t *out, size_t max) {
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > max) return -1;
    for (size_t i = 0; i < len; i += 2) {
        unsigned int byte;
        if (sscanf(hex + i, "%2x", &byte) != 1) return -1;
        out[i / 2] = (uint8_t)byte;
    }
    return (int)(len / 2);
}

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (v >> 24) & 0xff; p[1] = (v >> 16) & 0xff;
    p[2] = (v >>  8) & 0xff; p[3] =  v        & 0xff;
}

static uint32_t get_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static void set_timeout(int fd, int seconds) {
    struct timeval tv = { .tv_sec = seconds };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int read_exact(int fd, uint8_t *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = read(fd, buf + done, n - done);
        if (r <= 0) return -1;
        done += (size_t)r;
    }
    return 0;
}

static int write_all(int fd, const uint8_t *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t w = write(fd, buf + done, n - done);
        if (w <= 0) return -1;
        done += (size_t)w;
    }
    return 0;
}

static int vens_pkt(const uint8_t mac[6], const uint8_t *cmd, size_t cmd_len,
                    uint8_t *out, size_t max) {
    size_t total = 16 + 16 + cmd_len;
    if (total > max) return -1;
    memset(out, 0, total);
    put_be32(out, (uint32_t)total);
    memcpy(out + 4, "VENS", 4);
    put_be32(out + 8, 1);
    memcpy(out + 16, mac, 6);
    memcpy(out + 32, cmd, cmd_len);
    return (int)total;
}

static int vens_pkt_hex(const uint8_t mac[6], const char *cmd_hex,
                        uint8_t *out, size_t max) {
    uint8_t cmd[256];
    int cmd_len = hex_decode(cmd_hex, cmd, sizeof(cmd));
    if (cmd_len < 0) return -1;
    return vens_pkt(mac, cmd, (size_t)cmd_len, out, max);
}

static int recv_vens(int fd, uint8_t *buf, size_t max, int timeout_sec) {
    set_timeout(fd, timeout_sec);
    uint8_t hdr[16];
    if (read_exact(fd, hdr, 16) < 0) return -1;
    uint32_t pkt_len = get_be32(hdr);
    if (pkt_len < 16 || pkt_len > MAX_PAYLOAD || pkt_len > max) return -1;
    memcpy(buf, hdr, 16);
    if (pkt_len > 16 && read_exact(fd, buf + 16, pkt_len - 16) < 0) return -1;
    return (int)pkt_len;
}

static int send_cmd(int fd, const uint8_t mac[6], const char *cmd_hex,
                    uint8_t *resp, size_t resp_max) {
    uint8_t pkt[512];
    int pkt_len = vens_pkt_hex(mac, cmd_hex, pkt, sizeof(pkt));
    if (pkt_len < 0 || write_all(fd, pkt, (size_t)pkt_len) < 0) return -1;
    return recv_vens(fd, resp, resp_max, 5);
}

static int bind_udp(uint16_t port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    return fd;
}

static int connect_tcp_ms(uint32_t ip, uint16_t port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* Non-blocking connect + poll for reliable timeout */
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = ip };
    int r = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (r < 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (r < 0) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        if (poll(&pfd, 1, timeout_ms) <= 0) { close(fd); return -1; }
        int err = 0;
        socklen_t elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err != 0) { close(fd); return -1; }
    }

    /* Back to blocking with recv/send timeouts */
    fcntl(fd, F_SETFL, flags);
    struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return fd;
}

static int connect_tcp(uint32_t ip, uint16_t port, int timeout_sec) {
    return connect_tcp_ms(ip, port, timeout_sec * 1000);
}

static ssize_t find_bytes(const uint8_t *hay, size_t hay_len,
                          const uint8_t *needle, size_t needle_len) {
    if (hay_len < needle_len) return -1;
    for (size_t i = 0; i <= hay_len - needle_len; i++)
        if (memcmp(hay + i, needle, needle_len) == 0) return (ssize_t)i;
    return -1;
}

static ssize_t rfind_bytes(const uint8_t *hay, size_t hay_len,
                           const uint8_t *needle, size_t needle_len) {
    if (hay_len < needle_len) return -1;
    for (ssize_t i = (ssize_t)(hay_len - needle_len); i >= 0; i--)
        if (memcmp(hay + i, needle, needle_len) == 0) return i;
    return -1;
}

/* ── Discovery ────────────────────────────────────────────────────────── */

struct discover_ctx {
    uint32_t base_ip;
    uint8_t  host;
    uint32_t *result;
    pthread_mutex_t *mutex;
};

static void *discover_worker(void *arg) {
    struct discover_ctx *ctx = arg;

    pthread_mutex_lock(ctx->mutex);
    bool found = *ctx->result != 0;
    pthread_mutex_unlock(ctx->mutex);
    if (found) { free(ctx); return NULL; }

    uint32_t ip = ctx->base_ip | htonl((uint32_t)ctx->host);
    int fd1 = connect_tcp_ms(ip, 53218, 500);
    if (fd1 >= 0) {
        close(fd1);
        int fd2 = connect_tcp_ms(ip, 53219, 500);
        if (fd2 >= 0) {
            close(fd2);
            pthread_mutex_lock(ctx->mutex);
            if (*ctx->result == 0) *ctx->result = ip;
            pthread_mutex_unlock(ctx->mutex);
        }
    }
    free(ctx);
    return NULL;
}

static uint32_t discover(void) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 0;
    struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(1) };
    inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);
    connect(sock, (struct sockaddr *)&dst, sizeof(dst));
    struct sockaddr_in local;
    socklen_t slen = sizeof(local);
    getsockname(sock, (struct sockaddr *)&local, &slen);
    close(sock);

    uint32_t local_ip = ntohl(local.sin_addr.s_addr);
    uint32_t base_ip = htonl(local_ip & 0xffffff00);

    fprintf(stderr, "Searching for scanner...");
    if (g_debug)
        fprintf(stderr, " (%d.%d.%d.0/24)",
                (local_ip >> 24) & 0xff, (local_ip >> 16) & 0xff,
                (local_ip >> 8) & 0xff);

    uint32_t result = 0;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    for (int batch = 1; batch < 255; batch += 64) {
        int end = batch + 64;
        if (end > 255) end = 255;
        int n = end - batch;
        pthread_t threads[64];
        bool started[64] = {false};

        for (int i = 0; i < n; i++) {
            struct discover_ctx *ctx = calloc(1, sizeof(*ctx));
            if (!ctx) continue;
            ctx->base_ip = base_ip;
            ctx->host = (uint8_t)(batch + i);
            ctx->result = &result;
            ctx->mutex = &mutex;
            started[i] = (pthread_create(&threads[i], NULL, discover_worker, ctx) == 0);
            if (!started[i]) free(ctx);
        }

        for (int i = 0; i < n; i++)
            if (started[i]) pthread_join(threads[i], NULL);

        if (result != 0) break;
    }

    if (result != 0) {
        struct in_addr a = { .s_addr = result };
        fprintf(stderr, " found at %s\n", inet_ntoa(a));
    } else {
        fprintf(stderr, "\nNo scanner found\n");
    }

    pthread_mutex_destroy(&mutex);
    return result;
}

/* ── Network detection ────────────────────────────────────────────────── */

static int detect_network(uint32_t scanner_ip, uint8_t mac[6], uint32_t *local_ip) {
    /* Get local IP via UDP connect trick */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(1), .sin_addr.s_addr = scanner_ip };
    connect(sock, (struct sockaddr *)&dst, sizeof(dst));
    struct sockaddr_in local;
    socklen_t slen = sizeof(local);
    getsockname(sock, (struct sockaddr *)&local, &slen);
    close(sock);
    *local_ip = local.sin_addr.s_addr;

    /* Get interface name via `ip route get` */
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &scanner_ip, ip_str, sizeof(ip_str));

    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execlp("ip", "ip", "route", "get", ip_str, (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);
    char line[256];
    ssize_t n = read(pipefd[0], line, sizeof(line) - 1);
    close(pipefd[0]);
    waitpid(pid, NULL, 0);
    if (n <= 0) return -1;
    line[n] = '\0';

    char *dev = strstr(line, "dev ");
    if (!dev) return -1;
    char iface[32];
    if (sscanf(dev + 4, "%31s", iface) != 1) return -1;

    /* Read MAC from sysfs */
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%.31s/address", iface);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    char mac_str[32];
    if (!fgets(mac_str, sizeof(mac_str), fp)) { fclose(fp); return -1; }
    fclose(fp);

    unsigned int m[6];
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];
    return 0;
}

/* ── Protocol steps ───────────────────────────────────────────────────── */

static void send_d6_release(uint32_t scanner_ip, const uint8_t mac[6]) {
    if (g_debug) fprintf(stderr, "Sending D6 session release...\n");
    int s = connect_tcp(scanner_ip, 53218, 5);
    if (s < 0) return;
    uint8_t hello[16];
    if (read_exact(s, hello, 16) < 0) { close(s); return; }
    uint8_t pkt[512];
    int pkt_len = vens_pkt_hex(mac,
        "00000006000000000000000000000000d6000000000000000000000000000000",
        pkt, sizeof(pkt));
    write_all(s, pkt, (size_t)pkt_len);
    uint8_t resp[1024];
    recv_vens(s, resp, sizeof(resp), 3);
    shutdown(s, SHUT_WR);
    set_timeout(s, 2);
    uint8_t discard[1024];
    read(s, discard, sizeof(discard));
    close(s);
}

static int do_register(uint32_t scanner_ip, uint32_t local_ip, const uint8_t mac[6]) {
    if (g_debug) fprintf(stderr, "UDP registration...\n");
    int fd = bind_udp(55264);
    if (fd < 0) return -1;
    set_timeout(fd, 3);

    uint8_t ip_bytes[4];
    memcpy(ip_bytes, &local_ip, 4);
    struct sockaddr_in dest = { .sin_family = AF_INET, .sin_port = htons(52217), .sin_addr.s_addr = scanner_ip };

    const uint8_t magics[3][4] = { {'V','E','N','S'}, {'s','s','N','R'}, {'V','2','s','s'} };
    const uint16_t flags[3] = { 0x0010, 0x0100, 0x1000 };

    for (int round = 0; round < 4; round++) {
        for (int m = 0; m < 3; m++) {
            uint8_t pkt[32] = {0};
            memcpy(pkt, magics[m], 4);
            if (m == 2) put_be32(pkt + 4, 1);
            memcpy(pkt + 8, ip_bytes, 4);
            memcpy(pkt + 12, mac, 6);
            pkt[22] = 0xd7; pkt[23] = 0xe0;
            pkt[24] = (flags[m] >> 8) & 0xff;
            pkt[25] = flags[m] & 0xff;
            sendto(fd, pkt, 32, 0, (struct sockaddr *)&dest, sizeof(dest));
        }
    }

    uint8_t buf[256];
    ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
    if (g_debug) {
        if (n > 0) fprintf(stderr, "  registration OK (%zd bytes)\n", n);
        else fprintf(stderr, "  no registration response\n");
    }
    close(fd);
    usleep(500000);
    return 0;
}

static int try_handshake(uint32_t scanner_ip, uint32_t local_ip, const uint8_t mac[6]) {
    int fd = connect_tcp(scanner_ip, 53219, 5);
    if (fd < 0) {
        if (g_debug) perror("  connect 53219");
        return -999;
    }
    uint8_t hello[16];
    if (read_exact(fd, hello, 16) < 0) {
        if (g_debug) perror("  read hello");
        close(fd);
        return -999;
    }

    uint8_t pkt[128];
    hex_decode(
        "0000008056454e530000001100000000"
        "026c251c14ce00000000000000000000"
        "00061e000000000000000001c0a80199"
        "0000d7e131373431333631383031373800000000000000000000000000000000"
        "00000000000000000000000000000000"
        "0000000007ea030a15001a0036c7c7e4"
        "7a800000ffff9d900000000000000000",
        pkt, sizeof(pkt));
    memcpy(pkt + 16, mac, 6);
    memcpy(pkt + 44, &local_ip, 4);
    if (g_pairing_key) {
        memset(pkt + 52, 0, 16);
        size_t klen = strlen(g_pairing_key);
        if (klen > 16) klen = 16;
        memcpy(pkt + 52, g_pairing_key, klen);
    }

    if (write_all(fd, pkt, 128) < 0) {
        if (g_debug) perror("  write handshake");
        close(fd);
        return -999;
    }
    uint8_t resp[256];
    ssize_t n = read(fd, resp, sizeof(resp));
    if (n < 0 && g_debug) perror("  read handshake response");
    if (n >= 0 && n < 12 && g_debug)
        fprintf(stderr, "  short handshake response: %zd bytes\n", n);
    int32_t err = (n >= 12) ? (int32_t)get_be32(resp + 8) : -999;
    if (g_debug) fprintf(stderr, "  handshake result: %d\n", err);
    shutdown(fd, SHUT_RDWR);
    close(fd);
    return err;
}

static int do_handshake_conn1(uint32_t scanner_ip, uint32_t local_ip, const uint8_t mac[6]) {
    if (g_debug) fprintf(stderr, "TCP:53219 handshake...\n");
    int32_t err = try_handshake(scanner_ip, local_ip, mac);
    if (err == -4) {
        fprintf(stderr, "Stale session, releasing...\n");
        send_d6_release(scanner_ip, mac);
        sleep(1);
        do_register(scanner_ip, local_ip, mac);
        err = try_handshake(scanner_ip, local_ip, mac);
    }
    if (err != 0) {
        if (err == -999)
            fprintf(stderr, "Error: TCP handshake to scanner failed (error %d)\n", err);
        else
            fprintf(stderr, "Error: scanner rejected registration (error %d)\n", err);
        return -1;
    }
    return 0;
}

struct handshake_arg { uint32_t scanner_ip; uint8_t mac[6]; int n; };

static void *handshake_thread(void *arg) {
    struct handshake_arg *a = arg;
    uint32_t cmd = (a->n == 2) ? 0x13 : 0x30;
    int fd = connect_tcp(a->scanner_ip, 53219, 5);
    if (fd < 0) { free(a); return NULL; }
    uint8_t hello[16];
    if (read_exact(fd, hello, 16) < 0) { close(fd); free(a); return NULL; }
    uint8_t pkt[32] = {0};
    put_be32(pkt, 32);
    memcpy(pkt + 4, "VENS", 4);
    put_be32(pkt + 8, cmd);
    memcpy(pkt + 16, a->mac, 6);
    write_all(fd, pkt, 32);
    uint8_t resp[256];
    read(fd, resp, sizeof(resp));
    shutdown(fd, SHUT_RDWR);
    close(fd);
    free(a);
    return NULL;
}

static pthread_t start_handshake(uint32_t scanner_ip, const uint8_t mac[6], int n, bool *ok) {
    pthread_t t = 0;
    struct handshake_arg *a = calloc(1, sizeof(*a));
    if (!a) { *ok = false; return t; }
    a->scanner_ip = scanner_ip;
    memcpy(a->mac, mac, 6);
    a->n = n;
    *ok = (pthread_create(&t, NULL, handshake_thread, a) == 0);
    if (!*ok) free(a);
    return t;
}

static int do_init_session(uint32_t scanner_ip, const uint8_t mac[6]) {
    if (g_debug) fprintf(stderr, "TCP:53218 init session...\n");
    int fd = connect_tcp(scanner_ip, 53218, 10);
    if (fd < 0) return -1;
    uint8_t hello[16];
    if (read_exact(fd, hello, 16) < 0) { close(fd); return -1; }

    bool t2_ok = false;
    pthread_t t2 = (pthread_t){0};
    t2 = start_handshake(scanner_ip, mac, 2, &t2_ok);

    static const char *cmds[] = {
        "0000000600000060000000000000000012000000600000000000000000000000",
        "0000000a0000000c0000000000000000e70001000000000c0000000000000000",
        "0000000a000000200000000000000000c2000000000000002000000000000000",
        "00000008000000040000000000000000e6000100000000040000000000000000",
        "00000008000000000000000400000000e6000000000400000000000000000000101e0000",
        "00000006000000080000000800000000d50000000808000000000000000000000000000000000000",
        "00000006000000000000000000000000d6000000000000000000000000000000",
    };
    static const char *labels[] = { "06+12", "E7", "C2", "E6a", "E6b", "D5", "D6" };

    bool t3_ok = false;
    pthread_t t3 = (pthread_t){0};
    for (int i = 0; i < 7; i++) {
        if (g_interrupted) { close(fd); return -1; }
        uint8_t pkt[512];
        int pkt_len = vens_pkt_hex(mac, cmds[i], pkt, sizeof(pkt));
        if (pkt_len < 0 || write_all(fd, pkt, (size_t)pkt_len) < 0) { close(fd); return -1; }
        uint8_t resp[1024];
        int resp_len = recv_vens(fd, resp, sizeof(resp), 5);
        if (resp_len < 0) { close(fd); return -1; }
        if (g_debug) fprintf(stderr, "  %s: %dB\n", labels[i], resp_len);
        if (i == 0) t3 = start_handshake(scanner_ip, mac, 3, &t3_ok);
    }

    shutdown(fd, SHUT_RDWR);
    close(fd);
    if (t2_ok) pthread_join(t2, NULL);
    if (t3_ok) pthread_join(t3, NULL);
    return 0;
}

static int do_re_register(uint32_t scanner_ip, uint32_t local_ip, const uint8_t mac[6]) {
    int fd = bind_udp(55264);
    if (fd < 0) return -1;
    set_timeout(fd, 2);

    uint8_t ip_bytes[4];
    memcpy(ip_bytes, &local_ip, 4);
    struct sockaddr_in dest = { .sin_family = AF_INET, .sin_port = htons(52217), .sin_addr.s_addr = scanner_ip };

    for (int i = 0; i < 3; i++) {
        uint8_t pkt[32] = {0};
        memcpy(pkt, "VENS", 4);
        put_be32(pkt + 4, 1);
        memcpy(pkt + 8, ip_bytes, 4);
        memcpy(pkt + 12, mac, 6);
        pkt[22] = 0xd7; pkt[23] = 0xe0;
        pkt[24] = 0x10; pkt[25] = 0x00;
        sendto(fd, pkt, 32, 0, (struct sockaddr *)&dest, sizeof(dest));
        uint8_t buf[256];
        recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
        usleep(500000);
    }
    close(fd);
    return 0;
}

/* ── Scan ─────────────────────────────────────────────────────────────── */

static void build_scan_start(uint8_t page, uint8_t *cmd) {
    hex_decode("0000000c00300000000000000000000028000002000030000000000000000000", cmd, 32);
    if (page % 2 == 1) cmd[21] = 0x80;
    cmd[26] = page;
}

static void build_done_query(uint8_t page, uint8_t *cmd) {
    hex_decode("0000000c00000020000000000000000028008000008000002000000000000000", cmd, 32);
    cmd[26] = page;
}

static int recv_jpeg(int fd, uint8_t *prepend, size_t prepend_len,
                     uint8_t **out, size_t *out_len,
                     uint8_t **leftover, size_t *leftover_len) {
    size_t cap = prepend_len + RECV_BUF;
    uint8_t *buf = calloc(1, cap);
    if (!buf) return -1;
    size_t len = 0;
    if (prepend_len > 0) { memcpy(buf, prepend, prepend_len); len = prepend_len; }

    set_timeout(fd, 30);
    uint8_t tmp[RECV_BUF];
    static const uint8_t ffd8[2] = {0xFF, 0xD8};
    static const uint8_t ffd9[2] = {0xFF, 0xD9};

    for (;;) {
        ssize_t eoi = rfind_bytes(buf, len, ffd9, 2);
        if (eoi >= 0) {
            ssize_t soi = find_bytes(buf, len, ffd8, 2);
            if (soi < 0) { free(buf); return -1; }
            size_t jpeg_len = (size_t)(eoi + 2 - soi);
            *out = calloc(1, jpeg_len);
            if (!*out) { free(buf); return -1; }
            memcpy(*out, buf + soi, jpeg_len);
            *out_len = jpeg_len;
            size_t left = len - (size_t)(eoi + 2);
            if (left > 0) {
                *leftover = calloc(1, left);
                if (!*leftover) { free(*out); free(buf); return -1; }
                memcpy(*leftover, buf + eoi + 2, left);
                *leftover_len = left;
            } else {
                *leftover = NULL;
                *leftover_len = 0;
            }
            free(buf);
            return 0;
        }

        if (g_interrupted) { free(buf); return -1; }
        ssize_t n = read(fd, tmp, sizeof(tmp));
        if (n <= 0) { free(buf); return -1; }
        if (len + (size_t)n > cap) {
            cap = (len + (size_t)n) * 2;
            if (cap > MAX_PAYLOAD) { free(buf); return -1; }
            uint8_t *newbuf = realloc(buf, cap);
            if (!newbuf) { free(buf); return -1; }
            buf = newbuf;
        }
        memcpy(buf + len, tmp, (size_t)n);
        len += (size_t)n;
    }
}

static void do_cleanup(int fd, uint32_t scanner_ip, const uint8_t mac[6]) {
    shutdown(fd, SHUT_WR);
    set_timeout(fd, 2);
    uint8_t discard[1024];
    read(fd, discard, sizeof(discard));
    close(fd);
    sleep(1);
    send_d6_release(scanner_ip, mac);
}

static int do_scan(uint32_t scanner_ip, const uint8_t mac[6],
                   struct page *pages, int *page_count) {
    fprintf(stderr, "Scanning...\n");
    int fd = connect_tcp(scanner_ip, 53218, 10);
    if (fd < 0) return -1;
    uint8_t hello[16];
    if (read_exact(fd, hello, 16) < 0) { close(fd); return -1; }

    static const char *setup[] = {
        "0000000a000000200000000000000000c2000000000000002000000000000000",
        "00000006000000080000000800000000d50000000808000000000000000000000000000000000000",
        "00000006000000000000000000000000d8000000000000000000000000000000",
        "0000000a000000000000002000000000e9000000000000200000000000000000012c012c000028d0000044dc0500000000000000000000000000000000000000",
        "00000006000000000000005000000000d400000050000000000000000000000000030101d000c1808080908080000000000000000000000000000000000000300010012c012c05810000000028d0000044dc040000000000000000000000000000000000000000000000000000000000",
        "0000000a000000200000000000000000c2000000000000002000000000000000",
        "0000000600000012000000000000000003000000120000000000000000000000",
        "00000006000000000000000000000000e0000000000000000000000000000000",
    };

    uint8_t resp[1024];
    for (int i = 0; i < 8; i++) {
        if (g_interrupted) { close(fd); return -1; }
        if (send_cmd(fd, mac, setup[i], resp, sizeof(resp)) < 0) { close(fd); return -1; }
    }

    uint8_t scan_cmd[32], pkt[512];
    build_scan_start(0, scan_cmd);
    int pkt_len = vens_pkt(mac, scan_cmd, 32, pkt, sizeof(pkt));
    if (write_all(fd, pkt, (size_t)pkt_len) < 0) { close(fd); return -1; }

    /* Check for paper */
    set_timeout(fd, 15);
    uint8_t initial[4096];
    ssize_t n = read(fd, initial, sizeof(initial));
    if (n <= 0) {
        do_cleanup(fd, scanner_ip, mac);
        fprintf(stderr, "Error: no document in scanner\n");
        return -1;
    }

    static const uint8_t ffd8[2] = {0xFF, 0xD8};
    if (n >= 16 && find_bytes(initial, (size_t)n, ffd8, 2) < 0) {
        int32_t ec = (n >= 12) ? (int32_t)get_be32(initial + 8) : -999;
        do_cleanup(fd, scanner_ip, mac);
        fprintf(stderr, "Error: scanner error %d — is there paper in the feeder?\n", ec);
        return -1;
    }

    *page_count = 0;
    uint8_t pg = 0;
    uint8_t *prepend = calloc(1, (size_t)n);
    if (!prepend) { do_cleanup(fd, scanner_ip, mac); return -1; }
    memcpy(prepend, initial, (size_t)n);
    size_t prepend_len = (size_t)n;

    for (;;) {
        if (g_interrupted) { free(prepend); break; }

        uint8_t *jpeg = NULL;
        size_t jpeg_len = 0;
        uint8_t *leftover = NULL;
        size_t leftover_len = 0;

        if (recv_jpeg(fd, prepend, prepend_len, &jpeg, &jpeg_len, &leftover, &leftover_len) < 0) {
            free(prepend);
            break;
        }
        free(prepend);

        if (g_debug) {
            int sheet = pg / 2 + 1;
            if (pg % 2 == 0) {
                if (pg > 0) fprintf(stderr, "\n");
                fprintf(stderr, "  page %d  front %zu KB", sheet, jpeg_len / 1024);
            } else {
                fprintf(stderr, ", back %zu KB", jpeg_len / 1024);
            }
        }

        if (*page_count >= MAX_PAGES) { free(jpeg); free(leftover); break; }
        pages[*page_count].data = jpeg;
        pages[*page_count].len = jpeg_len;
        (*page_count)++;

        prepend = leftover;
        prepend_len = leftover_len;

        if (pg % 2 == 1) {
            /* Back side done — check for more sheets */
            if (!g_debug) fprintf(stderr, " sheet %d", pg / 2 + 1);
            if (send_cmd(fd, mac, "0000000600000012000000000000000003000000120000000000000000000000", resp, sizeof(resp)) < 0) break;
            uint8_t dq[32];
            build_done_query(pg, dq);
            pkt_len = vens_pkt(mac, dq, 32, pkt, sizeof(pkt));
            if (write_all(fd, pkt, (size_t)pkt_len) < 0) break;
            if (recv_vens(fd, resp, sizeof(resp), 5) < 0) break;
            if (send_cmd(fd, mac, "0000000a000000200000000000000000c2000000000000002000000000000000", resp, sizeof(resp)) < 0) break;
            if (send_cmd(fd, mac, "00000006000000000000000000000000e0000000000000000000000000000000", resp, sizeof(resp)) < 0) break;
            int rlen = send_cmd(fd, mac, "0000000600000012000000000000000003000000120000000000000000000000", resp, sizeof(resp));
            if (rlen < 0) break;
            if (rlen >= 12) {
                bool done = false;
                for (int i = rlen - 12; i < rlen; i++)
                    if (resp[i] != 0) { done = true; break; }
                if (done) break;
            }
        } else {
            /* Front side done — request back */
            if (send_cmd(fd, mac, "0000000600000012000000000000000003000000120000000000000000000000", resp, sizeof(resp)) < 0) break;
        }

        pg++;
        build_scan_start(pg, scan_cmd);
        pkt_len = vens_pkt(mac, scan_cmd, 32, pkt, sizeof(pkt));
        if (write_all(fd, pkt, (size_t)pkt_len) < 0) break;

        set_timeout(fd, pg % 2 == 0 ? 15 : 10);
        uint8_t ack[4096];
        ssize_t an = read(fd, ack, sizeof(ack));
        if (an <= 0) break;
        prepend = calloc(1, (size_t)an);
        if (!prepend) break;
        memcpy(prepend, ack, (size_t)an);
        prepend_len = (size_t)an;
    }

    fprintf(stderr, "\n");
    do_cleanup(fd, scanner_ip, mac);
    g_scanner_ip = 0;
    return 0;
}

/* ── PDF output ───────────────────────────────────────────────────────── */

static int jpeg_dimensions(const uint8_t *data, size_t len, int *width, int *height) {
    size_t i = 0;
    while (i + 1 < len) {
        if (data[i] != 0xFF) { i++; continue; }
        uint8_t marker = data[i + 1];
        i += 2;
        if (marker == 0xD8) continue;
        if (marker == 0xC0 || marker == 0xC2) {
            if (i + 7 > len) return -1;
            *height = ((int)data[i + 3] << 8) | data[i + 4];
            *width  = ((int)data[i + 5] << 8) | data[i + 6];
            return 0;
        }
        if (marker == 0xD9) return -1;
        if (i + 2 > len) return -1;
        int seg_len = ((int)data[i] << 8) | data[i + 1];
        if (seg_len < 2) return -1;
        i += (size_t)seg_len;
    }
    return -1;
}

static int save_pdf(const struct page *pages, int count, const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    int n_obj = 2 + count * 3;
    long *off = calloc((size_t)(n_obj + 1), sizeof(long));
    if (!off) { fclose(f); return -1; }

    fprintf(f, "%%PDF-1.4\n");
    off[1] = ftell(f);
    fprintf(f, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    off[2] = ftell(f);
    fprintf(f, "2 0 obj\n<< /Type /Pages /Kids [");
    for (int i = 0; i < count; i++) fprintf(f, "%d 0 R ", 3 + i * 3);
    fprintf(f, "] /Count %d >>\nendobj\n", count);

    for (int i = 0; i < count; i++) {
        int pg = 3 + i * 3, ct = pg + 1, im = pg + 2;
        int w = 2480, h = 3507;
        jpeg_dimensions(pages[i].data, pages[i].len, &w, &h);
        double wpt = (double)w / 300.0 * 72.0, hpt = (double)h / 300.0 * 72.0;
        char content[128];
        int clen = snprintf(content, sizeof(content), "q %.2f 0 0 %.2f 0 0 cm /Im0 Do Q", wpt, hpt);

        off[pg] = ftell(f);
        fprintf(f, "%d 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] "
                "/Contents %d 0 R /Resources << /XObject << /Im0 %d 0 R >> >> >>\nendobj\n",
                pg, wpt, hpt, ct, im);
        off[ct] = ftell(f);
        fprintf(f, "%d 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\n", ct, clen, content);
        off[im] = ftell(f);
        fprintf(f, "%d 0 obj\n<< /Type /XObject /Subtype /Image /Width %d /Height %d "
                "/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode "
                "/Length %zu >>\nstream\n", im, w, h, pages[i].len);
        if (fwrite(pages[i].data, 1, pages[i].len, f) != pages[i].len) { free(off); fclose(f); return -1; }
        fprintf(f, "\nendstream\nendobj\n");
    }

    long xref = ftell(f);
    fprintf(f, "xref\n0 %d\n0000000000 65535 f \n", n_obj + 1);
    for (int i = 1; i <= n_obj; i++) fprintf(f, "%010ld 00000 n \n", off[i]);
    fprintf(f, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%ld\n%%%%EOF\n", n_obj + 1, xref);

    free(off);
    fclose(f);
    chmod(path, 0600);
    return 0;
}

/* ── Main ─────────────────────────────────────────────────────────────── */

static void on_signal(int sig) { (void)sig; g_interrupted = 1; }

static void cleanup_on_exit(void) {
    if (g_scanner_ip != 0)
        send_d6_release(g_scanner_ip, g_mac);
}

/* ── Get pairing key (fake scanner mode) ─────────────────────────────── */

static void copy_padded_ascii(uint8_t *dst, size_t dst_len, const char *src) {
    memset(dst, 0, dst_len);
    if (!src) return;
    size_t n = strlen(src);
    if (n > dst_len) n = dst_len;
    memcpy(dst, src, n);
}

static int parse_hex_exact(const char *hex, uint8_t *out, size_t len) {
    if (!hex) return -1;
    size_t hex_len = strlen(hex);
    if (hex_len != len * 2) return -1;
    return hex_decode(hex, out, len) == (int)len ? 0 : -1;
}

static int do_getkey(const char *advertise_ip, const char *device_name,
                     const char *model_name, const char *fake_mac_str,
                     const char *info_tail_hex) {
    /* Broadcast discovery on UDP:53220 so ScanSnap Home finds us */
    int bcast_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (bcast_fd < 0) { perror("socket"); return -1; }
    int opt = 1;
    setsockopt(bcast_fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
    setsockopt(bcast_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Get or override our local IP */
    struct sockaddr_in plocal = { .sin_family = AF_INET };
    if (advertise_ip && advertise_ip[0]) {
        if (inet_pton(AF_INET, advertise_ip, &plocal.sin_addr) != 1) {
            fprintf(stderr, "Error: invalid --getkey-ip address: %s\n", advertise_ip);
            close(bcast_fd);
            return -1;
        }
    } else {
        int probe = socket(AF_INET, SOCK_DGRAM, 0);
        if (probe < 0) { close(bcast_fd); return -1; }
        struct sockaddr_in pdst = { .sin_family = AF_INET, .sin_port = htons(1) };
        inet_pton(AF_INET, "8.8.8.8", &pdst.sin_addr);
        connect(probe, (struct sockaddr *)&pdst, sizeof(pdst));
        socklen_t pslen = sizeof(plocal);
        getsockname(probe, (struct sockaddr *)&plocal, &pslen);
        close(probe);
    }
    uint8_t *ip = (uint8_t *)&plocal.sin_addr.s_addr;
    uint8_t fake_mac[6] = {0x00, 0x80, 0x92, 0x58, 0xc1, 0x5c};
    uint8_t info_tail[8] = {0x36, 0xc7, 0xc7, 0xe4, 0x7a, 0x80, 0x00, 0x00};
    if (fake_mac_str && fake_mac_str[0]) {
        unsigned int m[6];
        if (sscanf(fake_mac_str, "%x:%x:%x:%x:%x:%x",
                   &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) {
            fprintf(stderr, "Error: invalid --getkey-mac address: %s\n", fake_mac_str);
            close(bcast_fd);
            return -1;
        }
        for (int i = 0; i < 6; i++) fake_mac[i] = (uint8_t)m[i];
    }
    if (info_tail_hex && info_tail_hex[0]) {
        if (parse_hex_exact(info_tail_hex, info_tail, sizeof(info_tail)) < 0) {
            fprintf(stderr, "Error: invalid --getkey-tail value: %s\n", info_tail_hex);
            close(bcast_fd);
            return -1;
        }
    }
    if (g_debug) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &plocal.sin_addr, ip_str, sizeof(ip_str));
        fprintf(stderr, "Fake scanner advertising IP %s\n", ip_str);
        fprintf(stderr, "Fake scanner name '%s'\n",
                device_name ? device_name : "iX500-A0PB023744");
        fprintf(stderr, "Fake scanner model '%s'\n",
                model_name ? model_name : "ScanSnap iX500");
        fprintf(stderr, "Fake scanner MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                fake_mac[0], fake_mac[1], fake_mac[2],
                fake_mac[3], fake_mac[4], fake_mac[5]);
        fprintf(stderr, "Fake scanner UDP info tail %02x%02x%02x%02x%02x%02x%02x%02x\n",
                info_tail[0], info_tail[1], info_tail[2], info_tail[3],
                info_tail[4], info_tail[5], info_tail[6], info_tail[7]);
        fprintf(stderr, "Listening on UDP 52217, TCP 53219, TCP 53218\n");
        fprintf(stderr, "Broadcasting discovery on UDP 53220\n");
    }

    /* Listen on UDP:52217 for registration */
    int reg_fd = bind_udp(52217);
    if (reg_fd < 0) { close(bcast_fd); return -1; }
    set_timeout(reg_fd, 1);

    /* Listen on TCP:53219 for handshake */
    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd < 0) { close(bcast_fd); close(reg_fd); return -1; }
    setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in bind_addr = { .sin_family = AF_INET, .sin_port = htons(53219) };
    if (bind(tcp_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind 53219");
        close(bcast_fd); close(reg_fd); close(tcp_fd);
        return -1;
    }
    listen(tcp_fd, 5);

    /* Listen on TCP:53218 (scan port, just accept and close) */
    int scan_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (scan_fd < 0) {
        scan_fd = -1;
    } else {
        setsockopt(scan_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in scan_addr = { .sin_family = AF_INET, .sin_port = htons(53218) };
        if (bind(scan_fd, (struct sockaddr *)&scan_addr, sizeof(scan_addr)) < 0) {
            perror("bind 53218");
            close(scan_fd);
            scan_fd = -1;
        } else {
            listen(scan_fd, 5);
        }
    }

    /* Build discovery broadcast packet (48 bytes).
     * Real scanner packets place 0x01 at byte 16 and the IP at byte 20. */
    uint8_t disc[48] = {0};
    put_be32(disc, 48);
    memcpy(disc + 4, "VENS", 4);
    put_be32(disc + 8, 0x21);
    disc[16] = 1;
    memcpy(disc + 20, ip, 4);
    memcpy(disc + 24, fake_mac, 6);

    /* Real scanner registration response (132 bytes) */
    uint8_t reg_resp[132];
    hex_decode(
        "56454e530000000000060030ffffffff"
        "c0a8018c0000cfe20000cfe300809258"
        "c15c00000080000169583530302d4130"
        "50423032333734340000000000000000"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "00000000000000005363616e536e6170"
        "20695835303020200000000036c7c7e4"
        "7a800000",
        reg_resp, sizeof(reg_resp));
    memcpy(reg_resp + 16, ip, 4);  /* our IP */
    memcpy(reg_resp + 28, fake_mac, 6);
    copy_padded_ascii(reg_resp + 40, 16,
                      device_name ? device_name : "iX500-A0PB023744");
    copy_padded_ascii(reg_resp + 104, 16,
                      model_name ? model_name : "ScanSnap iX500  ");
    memcpy(reg_resp + 124, info_tail, sizeof(info_tail));

    struct sockaddr_in bcast_dst = {
        .sin_family = AF_INET, .sin_port = htons(53220),
        .sin_addr.s_addr = INADDR_BROADCAST
    };

    fprintf(stderr, "Waiting for ScanSnap Home to send pairing key...\n");
    fprintf(stderr, "(Make sure the real scanner is off or disconnected)\n");

    int nfds = 2;
    struct pollfd fds[3];
    fds[0].fd = reg_fd;   fds[0].events = POLLIN;
    fds[1].fd = tcp_fd;   fds[1].events = POLLIN;
    if (scan_fd >= 0) {
        fds[2].fd = scan_fd;  fds[2].events = POLLIN;
        nfds = 3;
    }

    bool found = false;
    time_t last_bcast = 0;

    while (!found && !g_interrupted) {
        /* Broadcast every 2 seconds */
        time_t now = time(NULL);
        if (now - last_bcast >= 2) {
            ssize_t sent = sendto(bcast_fd, disc, 48, 0,
                                  (struct sockaddr *)&bcast_dst, sizeof(bcast_dst));
            if (g_debug && sent < 0) perror("broadcast 53220");
            last_bcast = now;
        }

        int ready = poll(fds, (nfds_t)nfds, 1000);
        if (ready <= 0) continue;

        /* UDP registration */
        if (fds[0].revents & POLLIN) {
            uint8_t buf[256];
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            ssize_t n = recvfrom(reg_fd, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&from, &flen);
            if (n > 0) {
                if (g_debug)
                    fprintf(stderr, "UDP registration from %s (%zd bytes)\n",
                            inet_ntoa(from.sin_addr), n);
                sendto(reg_fd, reg_resp, 132, 0,
                       (struct sockaddr *)&from, flen);
            }
        }

        /* TCP:53219 handshake */
        if (fds[1].revents & POLLIN) {
            struct sockaddr_in client;
            socklen_t clen = sizeof(client);
            int conn = accept(tcp_fd, (struct sockaddr *)&client, &clen);
            if (conn < 0) continue;
            if (g_debug)
                fprintf(stderr, "TCP 53219 from %s\n", inet_ntoa(client.sin_addr));
            set_timeout(conn, 5);

            /* Send 16-byte hello */
            uint8_t hello[16] = {0};
            put_be32(hello, 16);
            memcpy(hello + 4, "VENS", 4);
            write_all(conn, hello, 16);

            uint8_t pkt[512];
            ssize_t n = read(conn, pkt, sizeof(pkt));
            if (n >= 70) {
                uint32_t pkt_len = get_be32(pkt);
                uint32_t cmd = get_be32(pkt + 8);

                if (pkt_len == 128 && cmd == 0x11) {
                    /* Extract key from offset 52, null-terminated */
                    char key[17] = {0};
                    memcpy(key, pkt + 52, 16);

                    printf("%s\n", key);
                    if (save_key(key) == 0)
                        fprintf(stderr, "Key saved\n");
                    found = true;

                    /* Send success response */
                    uint8_t resp[20] = {0};
                    put_be32(resp, 20);
                    memcpy(resp + 4, "VENS", 4);
                    write_all(conn, resp, 20);
                } else if (cmd == 0x13) {
                    if (g_debug) fprintf(stderr, "Handshake command 0x13\n");
                    uint8_t resp[112] = {0};
                    put_be32(resp, 112);
                    memcpy(resp + 4, "VENS", 4);
                    copy_padded_ascii(resp + 16, 16,
                                      device_name ? device_name : "iX500-A0PB023744");
                    write_all(conn, resp, 112);
                } else if (cmd == 0x30) {
                    if (g_debug) fprintf(stderr, "Handshake command 0x30\n");
                    uint8_t resp[32] = {0};
                    put_be32(resp, 32);
                    memcpy(resp + 4, "VENS", 4);
                    write_all(conn, resp, 32);
                }
            }
            close(conn);
        }

        /* TCP:53218 - just accept and send hello */
        if (fds[2].revents & POLLIN) {
            int conn = accept(scan_fd, NULL, NULL);
            if (conn >= 0) {
                if (g_debug) fprintf(stderr, "TCP 53218 probe accepted\n");
                uint8_t hello[16] = {0};
                put_be32(hello, 16);
                memcpy(hello + 4, "VENS", 4);
                write_all(conn, hello, 16);
                close(conn);
            }
        }
    }

    close(bcast_fd);
    close(reg_fd);
    close(tcp_fd);
    if (scan_fd >= 0) close(scan_fd);
    return found ? 0 : -1;
}

static void usage(void) {
    fprintf(stderr,
        "Usage: scansnap [options]\n"
        "  -s IP    scanner IP (auto-discovers if omitted)\n"
        "  -k KEY   pairing key (WiFi module serial)\n"
        "  -o FILE  output filename (default: scan_YYYYMMDD_HHMM.pdf)\n"
        "  -j       output as separate JPEG files\n"
        "  -1       single-sided (discard back pages)\n"
        "  -d       debug output\n"
        "  -h       help\n"
        "  --getkey capture pairing key from ScanSnap Home\n"
        "  --getkey-ip IP\n"
        "           advertise this host IP in fake scanner mode\n"
        "  --getkey-name NAME\n"
        "           fake scanner device name (default: iX500-A0PB023744)\n"
        "  --getkey-model MODEL\n"
        "           fake scanner model string (default: ScanSnap iX500)\n"
        "  --getkey-mac MAC\n"
        "           fake scanner MAC (default: 00:80:92:58:c1:5c)\n"
        "  --getkey-tail HEX\n"
        "           8-byte hex tail for UDP device info response\n");
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    atexit(cleanup_on_exit);

    /* Check for --getkey before getopt so it can run standalone */
    bool want_getkey = false;
    const char *getkey_ip = NULL;
    const char *getkey_name = NULL;
    const char *getkey_model = NULL;
    const char *getkey_mac = NULL;
    const char *getkey_tail = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--getkey") == 0) {
            want_getkey = true;
        } else if (strcmp(argv[i], "-d") == 0) {
            g_debug = true;
        } else if (strcmp(argv[i], "--getkey-ip") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --getkey-ip requires an IP address\n");
                return 1;
            }
            getkey_ip = argv[++i];
        } else if (strncmp(argv[i], "--getkey-ip=", 12) == 0) {
            getkey_ip = argv[i] + 12;
        } else if (strcmp(argv[i], "--getkey-name") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --getkey-name requires a value\n");
                return 1;
            }
            getkey_name = argv[++i];
        } else if (strncmp(argv[i], "--getkey-name=", 14) == 0) {
            getkey_name = argv[i] + 14;
        } else if (strcmp(argv[i], "--getkey-model") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --getkey-model requires a value\n");
                return 1;
            }
            getkey_model = argv[++i];
        } else if (strncmp(argv[i], "--getkey-model=", 15) == 0) {
            getkey_model = argv[i] + 15;
        } else if (strcmp(argv[i], "--getkey-mac") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --getkey-mac requires a value\n");
                return 1;
            }
            getkey_mac = argv[++i];
        } else if (strncmp(argv[i], "--getkey-mac=", 13) == 0) {
            getkey_mac = argv[i] + 13;
        } else if (strcmp(argv[i], "--getkey-tail") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --getkey-tail requires a value\n");
                return 1;
            }
            getkey_tail = argv[++i];
        } else if (strncmp(argv[i], "--getkey-tail=", 14) == 0) {
            getkey_tail = argv[i] + 14;
        }
    }
    if (want_getkey) {
        return do_getkey(getkey_ip, getkey_name, getkey_model,
                         getkey_mac, getkey_tail) < 0 ? 1 : 0;
    }

    const char *scanner_str = NULL, *output = NULL, *key_str = NULL;
    bool jpeg_mode = false, simplex = false;
    int opt;
    while ((opt = getopt(argc, argv, "s:k:o:j1dh")) != -1) {
        switch (opt) {
        case 's': scanner_str = optarg; break;
        case 'k': key_str = optarg; break;
        case 'o': output = optarg; break;
        case 'j': jpeg_mode = true; break;
        case '1': simplex = true; break;
        case 'd': g_debug = true; break;
        case 'h': usage(); return 0;
        default:  usage(); return 1;
        }
    }

    uint32_t scanner_ip;
    if (key_str)
        g_pairing_key = key_str;
    else
        g_pairing_key = load_key();

    if (!g_pairing_key) {
        fprintf(stderr, "Error: no pairing key (use -k or run --getkey first)\n");
        return 1;
    }

    if (scanner_str) {
        if (inet_pton(AF_INET, scanner_str, &scanner_ip) != 1) {
            fprintf(stderr, "Error: invalid IP address: %s\n", scanner_str);
            return 1;
        }
    } else {
        scanner_ip = discover();
        if (scanner_ip == 0) return 1;
    }

    uint8_t mac[6];
    uint32_t local_ip;
    if (detect_network(scanner_ip, mac, &local_ip) < 0) {
        fprintf(stderr, "Error: failed to detect network\n");
        return 1;
    }
    if (g_debug) {
        struct in_addr a = { .s_addr = local_ip };
        fprintf(stderr, "MAC=%02x:%02x:%02x:%02x:%02x:%02x IP=%s\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], inet_ntoa(a));
    }

    g_scanner_ip = scanner_ip;
    memcpy(g_mac, mac, 6);

    if (do_register(scanner_ip, local_ip, mac) < 0
        || do_handshake_conn1(scanner_ip, local_ip, mac) < 0
        || do_init_session(scanner_ip, mac) < 0) return 1;
    do_re_register(scanner_ip, local_ip, mac);

    struct page all_pages[MAX_PAGES];
    int total = 0;
    if (do_scan(scanner_ip, mac, all_pages, &total) < 0) return 1;
    if (total == 0) { fprintf(stderr, "No pages scanned\n"); return 1; }

    /* Filter simplex (front pages only) */
    struct page *out = all_pages;
    int out_n = total;
    struct page *simplex_buf = NULL;
    if (simplex) {
        simplex_buf = calloc((size_t)total, sizeof(struct page));
        if (!simplex_buf) { fprintf(stderr, "Error: out of memory\n"); return 1; }
        out_n = 0;
        for (int i = 0; i < total; i += 2) simplex_buf[out_n++] = all_pages[i];
        out = simplex_buf;
    }

    char default_name[64];
    if (!output) {
        time_t now = time(NULL);
        struct tm *tm = localtime(&now);
        strftime(default_name, sizeof(default_name), "scan_%Y%m%d_%H%M", tm);
        output = default_name;
    }

    int rc = 0;
    if (jpeg_mode) {
        for (int i = 0; i < out_n; i++) {
            char path[256];
            snprintf(path, sizeof(path), out_n > 1 ? "%s_p%d.jpg" : "%s.jpg", output, i + 1);
            int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd < 0) { perror(path); rc = 1; break; }
            if (write_all(fd, out[i].data, out[i].len) < 0) {
                fprintf(stderr, "Error: failed to write %s\n", path);
                close(fd); rc = 1; break;
            }
            close(fd);
            fprintf(stderr, "Saved %s\n", path);
        }
    } else {
        char path[256];
        size_t olen = strlen(output);
        if (olen >= 4 && strcmp(output + olen - 4, ".pdf") == 0)
            snprintf(path, sizeof(path), "%s", output);
        else
            snprintf(path, sizeof(path), "%s.pdf", output);
        if (save_pdf(out, out_n, path) < 0) {
            fprintf(stderr, "Error: failed to write %s\n", path);
            rc = 1;
        } else {
            fprintf(stderr, "Saved %s (%d pages)\n", path, out_n);
        }
    }

    for (int i = 0; i < total; i++) free(all_pages[i].data);
    free(simplex_buf);
    return rc;
}
