/* Raw-ACL output for DS5 BT reports — FORWARDER mode. See ds5_acl_tx.h.
 *
 * The webOS app jail lets us bind an HCI_CHANNEL_RAW socket but DENIES the ACL
 * write() (EPERM), so in-process raw-ACL injection is impossible. Instead a root
 * daemon (ds5_txd) does the privileged write: it captures the connection template
 * via HCI_CHANNEL_MONITOR (root), publishes a readiness file, and injects each
 * report we hand it over a local AF_UNIX SOCK_DGRAM socket. We therefore touch no
 * HCI here at all — only a local datagram send (~tens of microseconds, no
 * buffering, no round trip; far below the ~10ms audio grid) plus a poll of the
 * readiness file. Until the daemon signals it has a template, we return HIDRAW so
 * the caller seeds the report on /dev/hidraw (which puts it on air for the daemon
 * to capture the template from). If the daemon is absent, everything degrades to
 * the normal hidraw path — no regression.
 */

#define _GNU_SOURCE

#include "ds5_acl_tx.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#define ACL_MAX_REPORT 4096

/* Tagged-datagram framing (multi-controller): [0xA5][kind][addr 6, LSB-first, i.e.
 * HCI byte order matching the daemon's captured bound_addr][report]. Byte 0 is not
 * a valid DS5 output report id (0x31/0x32/0x36), so the daemon tells a tagged
 * datagram from a legacy untagged one by inspecting it alone.
 *
 *   ACL_TAG_INJECT — forward the report onto that controller's link. Sent ONLY
 *                    while the link is ready, i.e. while we are not seeding hidraw.
 *   ACL_TAG_ASSERT — identity assertion, never injected. Sent alongside the hidraw
 *                    seed while NOT ready, so the daemon can match the bytes it
 *                    sees on air and learn which BT address owns that ACL handle
 *                    (the only way to re-identify a pad that was already connected
 *                    when the daemon started: no HCI connect event ever arrives).
 *                    Keeping it un-injectable prevents a double-send across the
 *                    readiness flip: the daemon may bind the link up to one
 *                    readiness-poll interval before we notice, and an injectable
 *                    datagram in that window would go on air on top of our own
 *                    hidraw write of the same frame. */
#define ACL_TAG_M0      0xA5
#define ACL_TAG_INJECT  0x5A
#define ACL_TAG_ASSERT  0x5B
#define ACL_TAG_LEN     8       /* 2 magic/kind + 6 address */

struct ds5_acl_tx {
    ds5_acl_log_fn log_fn;      /* routes milestones to the controller file log */
    void     *log_ctx;
    int       unixfd;           /* AF_UNIX SOCK_DGRAM to the root daemon */
    struct sockaddr_un daddr;   /* daemon socket address (path-based) */
    char      tmpl_path[256];   /* readiness/template file the daemon publishes */

    int       tagged;           /* 1 = prepend the target-address tag on every send */
    uint8_t   tag[ACL_TAG_LEN]; /* [M0][kind][addr LSB-first]; kind stamped per send */

    pthread_t poll_thread;
    int       poll_started;
    volatile int running;
    volatile int ready;         /* daemon has a live template -> safe to forward */

    long      injected;         /* reports handed to the daemon (== on-air injects) */
    long      dropped;          /* transient send congestion */
};

/* Parse "aa:bb:cc:dd:ee:ff" into 6 bytes in LSB-first (HCI) order: out[0] is the
 * LAST octet of the human string. Also emits the colon-stripped lowercase hex
 * (out_hex, 13 bytes incl. NUL) for the per-address readiness filename. Returns 1
 * on a well-formed 6-octet address, 0 otherwise (caller stays untagged/legacy). */
static int parse_bt_mac(const char *s, uint8_t out[6], char out_hex[13])
{
    if (!s || !s[0]) return 0;
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return 0;
    for (int i = 0; i < 6; i++) {
        if (v[i] > 0xff) return 0;
        out[5 - i] = (uint8_t)v[i];                 /* human MSB..LSB -> LSB-first bytes */
    }
    for (int i = 0; i < 6; i++)
        snprintf(out_hex + i * 2, 3, "%02x", v[i]); /* human order, lowercase, no colons */
    return 1;
}

/* Route a milestone to the controller log (if set) or stderr. */
static void acl_log(ds5_acl_tx_t *t, const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (t && t->log_fn) t->log_fn(t->log_ctx, buf);
    else fprintf(stderr, "[ds5-acl] %s\n", buf);
}

/* Readiness poller: the root daemon publishes a 16-byte record
 * ['D''S''5''T'][ver=1][flags][nonce LE16][acl_hdr 8]; flags bit0 = valid (the
 * daemon has captured the current connection's template and can inject). We only
 * need the valid bit: ready=1 => forward to the daemon; ready=0 => seed via
 * hidraw so the daemon can capture the template from on-air traffic. */
static void *acl_mon_thread(void *arg)
{
    ds5_acl_tx_t *t = (ds5_acl_tx_t *)arg;
    acl_log(t, "forwarder readiness watching %s", t->tmpl_path);
    int last = -1;
    while (t->running) {
        int valid = 0;
        int fd = open(t->tmpl_path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            uint8_t rec[16];
            ssize_t n = read(fd, rec, sizeof rec);
            close(fd);
            if (n == 16 && rec[0] == 'D' && rec[1] == 'S' && rec[2] == '5' && rec[3] == 'T' &&
                rec[4] == 1 && (rec[5] & 1))
                valid = 1;
        }
        if (valid != last) {
            __atomic_store_n(&t->ready, valid, __ATOMIC_RELEASE);
            acl_log(t, valid ? "daemon template ready -> raw-ACL forward ACTIVE"
                             : "daemon template not ready -> hidraw seeding");
            last = valid;
        }
        for (int i = 0; i < 4 && t->running; i++) usleep(50000);   /* ~200ms poll */
    }
    return NULL;
}

ds5_acl_tx_t *ds5_acl_tx_start(int hci_dev, const char *bt_mac,
                               ds5_acl_log_fn log_fn, void *log_ctx)
{
    (void)hci_dev;
    ds5_acl_tx_t *t = (ds5_acl_tx_t *)calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->log_fn = log_fn;
    t->log_ctx = log_ctx;
    t->unixfd = -1;
    t->running = 1;

    /* Multi-controller tag: parse the controller's BT address once. On success
     * every send is tagged and readiness is tracked in a per-address file; on
     * failure (no/!valid mac — USB pad, unknown addr) we stay on the legacy
     * untagged wire + shared readiness file (the daemon's primary link). */
    uint8_t addr[6]; char machex[13];
    t->tagged = parse_bt_mac(bt_mac, addr, machex);
    if (t->tagged) {
        t->tag[0] = ACL_TAG_M0;         /* tag[1] = kind, stamped per send */
        memcpy(t->tag + 2, addr, 6);
    }

    const char *tp = getenv("DS5_ACL_TMPL");
    const char *base = (tp && tp[0]) ? tp : "/tmp/ds5_acl_tmpl";
    if (t->tagged)
        snprintf(t->tmpl_path, sizeof t->tmpl_path, "%s.%s", base, machex);
    else
        snprintf(t->tmpl_path, sizeof t->tmpl_path, "%s", base);
    const char *sp = getenv("DS5_ACL_SOCK");
    const char *sock = (sp && sp[0]) ? sp : "/tmp/ds5_acl.sock";

    t->unixfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (t->unixfd < 0) {
        acl_log(t, "unix socket failed errno=%d (staying on hidraw)", errno);
        free(t);
        return NULL;
    }
    int fl = fcntl(t->unixfd, F_GETFL, 0);
    if (fl >= 0) fcntl(t->unixfd, F_SETFL, fl | O_NONBLOCK);   /* never stall the session thread */
    t->daddr.sun_family = AF_UNIX;
    snprintf(t->daddr.sun_path, sizeof t->daddr.sun_path, "%s", sock);

    if (pthread_create(&t->poll_thread, NULL, acl_mon_thread, t) != 0) {
        acl_log(t, "readiness thread failed errno=%d (staying on hidraw)", errno);
        close(t->unixfd);
        free(t);
        return NULL;
    }
    t->poll_started = 1;
    acl_log(t, "raw-ACL forwarder ON: sock=%s tag=%s (root ds5_txd does the inject)",
            sock, t->tagged ? machex : "none(legacy)");
    return t;
}

/* Send one tagged datagram [tag][report]; iovec avoids copying the report body. A
 * datagram is delivered atomically, so the daemon always sees tag+report together
 * (never a torn frame). Returns the raw sendmsg() result. */
static ssize_t send_tagged(ds5_acl_tx_t *t, uint8_t kind, const uint8_t *report, size_t len)
{
    t->tag[1] = kind;
    struct iovec iov[2] = {
        { .iov_base = t->tag,           .iov_len = ACL_TAG_LEN },
        { .iov_base = (void *)report,   .iov_len = len },
    };
    struct msghdr mh; memset(&mh, 0, sizeof mh);
    mh.msg_name = &t->daddr; mh.msg_namelen = sizeof t->daddr;
    mh.msg_iov = iov; mh.msg_iovlen = 2;
    return sendmsg(t->unixfd, &mh, 0);
}

int ds5_acl_tx_send(ds5_acl_tx_t *t, const uint8_t *report, size_t len)
{
    if (!t) return DS5_ACL_TX_HIDRAW;
    if (!report || len == 0 || len > ACL_MAX_REPORT) return DS5_ACL_TX_HIDRAW;
    if (!__atomic_load_n(&t->ready, __ATOMIC_ACQUIRE)) {
        /* Not ready -> the caller seeds this exact report via hidraw. For a tagged
         * pad ALSO send it as an identity ASSERT: after a daemon restart with the
         * pad still connected there is no HCI connect event (and webOS returns an
         * empty HCIGETCONNLIST) for the daemon to learn the handle->address
         * mapping from, so it instead matches these asserted bytes against its
         * on-air capture of the very hidraw write we trigger — and flips
         * readiness once the pad's link is bound. Best-effort, non-blocking; NOT
         * an inject (no link exists yet), hidraw stays the sender of record. */
        if (t->tagged) (void)send_tagged(t, ACL_TAG_ASSERT, report, len);
        return DS5_ACL_TX_HIDRAW;
    }

    ssize_t wr;
    if (t->tagged) {
        wr = send_tagged(t, ACL_TAG_INJECT, report, len);
        if (wr == (ssize_t)(ACL_TAG_LEN + len)) { t->injected++; return DS5_ACL_TX_SENT; }
    } else {
        wr = sendto(t->unixfd, report, len, 0,
                    (struct sockaddr *)&t->daddr, sizeof t->daddr);
        if (wr == (ssize_t)len) { t->injected++; return DS5_ACL_TX_SENT; }
    }
    if (wr < 0 && (errno == EINTR || errno == EAGAIN ||
                   errno == EWOULDBLOCK || errno == ENOBUFS)) {
        t->dropped++;                 /* daemon recv buffer momentarily full — skip */
        return DS5_ACL_TX_DROP;
    }
    /* Daemon gone / socket missing (ENOENT, ECONNREFUSED): fall back to hidraw for
     * this frame. NOT permanent — the daemon may come back and the readiness poll
     * will re-enable forwarding. */
    return DS5_ACL_TX_HIDRAW;
}

void ds5_acl_tx_stats(ds5_acl_tx_t *t, long *injected, long *dropped, int *ready)
{
    if (!t) {
        if (injected) *injected = 0;
        if (dropped) *dropped = 0;
        if (ready) *ready = 0;
        return;
    }
    if (injected) *injected = t->injected;
    if (dropped) *dropped = t->dropped;
    if (ready) *ready = __atomic_load_n(&t->ready, __ATOMIC_ACQUIRE);
}

void ds5_acl_tx_stop(ds5_acl_tx_t *t)
{
    if (!t) return;
    t->running = 0;
    if (t->poll_started) {
        pthread_join(t->poll_thread, NULL);
        t->poll_started = 0;
    }
    if (t->unixfd >= 0) { close(t->unixfd); t->unixfd = -1; }
    free(t);
}
