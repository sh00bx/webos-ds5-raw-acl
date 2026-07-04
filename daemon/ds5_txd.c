// ds5_txd.c — root DS5 raw-ACL transport forwarder for the jailed Aurora app.
//
// The webOS app jail lets the app BIND an HCI_CHANNEL_RAW socket but DENIES the
// ACL write() (EPERM), so in-process raw-ACL injection is impossible. This root
// daemon performs the privileged work the app cannot:
//   1. Captures the on-air ACL template (conn handle + dest L2CAP CID) via
//      HCI_CHANNEL_MONITOR (works as root) from our own outgoing HID-output.
//   2. Publishes a readiness/template record into the jail-shared tmp file so the
//      app knows when to stop seeding via hidraw and start forwarding.
//   3. Receives each already-built, already-CRC-signed report from the app over a
//      local AF_UNIX SOCK_DGRAM socket and injects it as a raw HCI ACL packet
//      (root write is permitted) — bypassing webOS BT one-outstanding metering.
//
// IPC is one local datagram per report (~tens of microseconds, no buffering, no
// round trip) — far below the ~10ms audio grid. The app falls back to its normal
// hidraw write if the daemon is absent, so this never regresses.
//
// HID-FD BROKER (Option A — app becomes jail-node-independent):
//   The jail's /dev/hidraw* is a STATIC snapshot taken at jail-build (copynodall),
//   so a controller hot-plugged afterwards onto a hidraw minor the snapshot never
//   covered (e.g. /dev/hidraw5) simply does not exist inside the jail — the app's
//   open() returns ENOENT and the bridge dies. We (root, real /dev) open the node
//   the app names and hand the OPEN FD across the jail via SCM_RIGHTS over a second
//   AF_UNIX SOCK_STREAM socket. The app then holds a real kernel fd and every
//   read/write/ioctl works unchanged. Only used as a fallback when the app's own
//   open() fails, so the static-node path is untouched (no regression).
//
//   usage: ds5_txd [sock_path] [tmpl_path] [hidfd_sock_path]
//
// ALT-LATCH HARDENING (2026-06-27, review wf_a75a6ae7) — see ALTLATCH_AUDIT.md:
//   Identity-bind the inject template to the DS5 bdaddr and refuse to inject onto a
//   handle we cannot prove is the DS5, so a flapped+reused 12-bit ACL handle can no
//   longer carry our HID-output onto a foreign device (the Magic-Remote Left-Alt
//   latch). Defences, in layers:
//     (a) Fail CLOSED: a template is published VALID only once the bound handle's
//         bdaddr is known (learned from HCI events or HCIGETCONNLIST). Until then the
//         app keeps seeding via hidraw — safe, never blind-injects.
//     (b) Event-driven invalidation: DISCONN / reassign-to-different-bdaddr of the
//         bound handle drops the template instantly (covers BR/EDR + legacy & enhanced
//         LE connect events).
//     (c) Idle backstop: evaluated every monitor wakeup (not only on recv-timeout),
//         so it still fires under continuous unrelated BT traffic — the DS5 going
//         silent after a flap invalidates within IDLE_INVALIDATE_MS even if the
//         DISCONN event was dropped.
//     (d) Atomic check-and-inject: the bdaddr re-check and the write() happen under
//         one lock, closing the check->inject TOCTOU.
//     (e) Single-controller scope: only hci_dev=0 (the inject target) is tracked, so
//         a second adapter's handle reuse can't pollute the table.
//   Plus hardening the two IPC surfaces the audit named: the report datagram socket
//   now requires SO_PEERCRED == jail uid, and the hid-fd broker only ever hands out
//   an allowlisted game pad's hidraw (PAD_ALLOW; DS5, DS4, Xbox, Switch Pro,
//   8BitDo), never a system HID device's node.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <time.h>

#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH 31
#endif
#define BTPROTO_HCI         1
#define HCI_CHANNEL_RAW     0
#define HCI_CHANNEL_MONITOR 2
#define HCI_DEV_NONE        0xffff
#define HCI_ACLDATA_PKT     0x02
#define MON_EVENT_PKT       3
#define MON_ACL_TX_PKT      4
#define ACL_MAX_REPORT      4096

/* HCI event codes we parse off the MONITOR stream to track handle<->device. */
#define HCI_EV_CONN_COMPLETE    0x03
#define HCI_EV_DISCONN_COMPLETE 0x05
#define HCI_EV_NUM_COMP_PKTS    0x13
#define HCI_EV_LE_META          0x3e
#define STALL_RESET_MS          150   /* credits stopped this long -> resync g_outstanding */
#define HCI_SUBEV_LE_CONN       0x01   /* LE Connection Complete                 */
#define HCI_SUBEV_LE_ENH_CONN   0x0a   /* Enhanced LE Connection Complete (BT5)  */

/* The single controller we inject on and therefore track. MUST equal the raw
 * inject socket's hci_dev (see main()). The MONITOR header's index field carries
 * the controller number (hci0 -> index 0); ignoring other indices stops a second
 * adapter's handle reuse from polluting g_htab or falsely invalidating the DS5. */
#define TARGET_HCI_INDEX    0

#define IDLE_INVALIDATE_MS  1500   /* drop the template after this much DS5 silence */
#define DRAIN_CAP           1024   /* max reports drained per poll wakeup (anti-flood) */
#define JAIL_UID            6261   /* aurora jail uid — only sender allowed to inject */
#define DS5_VID             0x054c /* Sony      } primary device; the broker additionally */
#define DS5_PID             0x0ce6 /* DualSense } allows a small game-pad list, see PAD_ALLOW */

struct sockaddr_hci { unsigned short hci_family, hci_dev, hci_channel; };
struct hci_mon_hdr  { uint16_t opcode, index, len; } __attribute__((packed));

/* hidraw VID/PID query — used to confine the broker to the DS5's own node. */
struct hidraw_devinfo { uint32_t bustype; int16_t vendor; int16_t product; };
#ifndef HIDIOCGRAWINFO
#define HIDIOCGRAWINFO _IOR('H', 0x03, struct hidraw_devinfo)
#endif

/* HCIGETCONNLIST: bluez-compatible connection-list ioctl (best-effort startup
 * seed of the handle->bdaddr table for a controller already connected before we
 * started monitoring; if the kernel lacks it we fall back to event parsing). */
typedef struct { uint8_t b[6]; } bdaddr_t;
struct hci_conn_info { uint16_t handle; bdaddr_t bdaddr; uint8_t type, out;
                       uint16_t state; uint32_t link_mode; };
struct hci_conn_list_req { uint16_t dev_id, conn_num; struct hci_conn_info ci[16]; };
#ifndef HCIGETCONNLIST
#define HCIGETCONNLIST _IOR('H', 212, int)
#endif

static int injectable(uint8_t id){ return id==0x31 || id==0x32 || id==0x36; }
static uint64_t now_ms(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return (uint64_t)ts.tv_sec*1000ull+ts.tv_nsec/1000000ull; }
static uint64_t now_us(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return (uint64_t)ts.tv_sec*1000000ull+ts.tv_nsec/1000ull; }

/* Max outstanding raw-ACL TX packets (a credit window). The inject path bypasses the
 * webOS BT one-outstanding metering: keeping it at 1 was the original jitter wall,
 * but removing the bound ENTIRELY lets our output backlog the controller's TX queue,
 * so the baseband spends its slots draining TX and polls the DS5 less -> its INPUT
 * reports gap (controller lag while the video/WiFi stays smooth). A small credit
 * window is the fix: pipeline enough packets to keep haptics tight, but never so many
 * that TX starves the input poll. It is INHERENTLY ADAPTIVE and prioritises input
 * without a static rate cap -- when the link is idle the controller confirms our
 * packets fast (NOCP), credits free immediately and we inject at full haptic rate;
 * only under contention (input/video needing airtime) do the credits lag, and output
 * automatically backs off to whatever bandwidth is left. Live-tunable via
 * /tmp/ds5_inject_maxq (>=1; a large value approximates the original unmetered path).
 * Cached ~1/sec.
 *
 * Default 12 (measured 2026-07-04 in-game): the DS5 speaker/haptics 0x36 audio
 * stream is ~94 frames/s, and a window of 3 filled constantly under contention
 * -> the drop-newest path fired ~180x/10s = audible audio/haptic dropouts. A
 * gap sweep (3/8/12/16) vs DS5 input-report rate showed input is BT-connection-
 * -interval bound (~22ms floor) and barely moves with the window: 3->16 cost
 * only ~5% input rate (496->469 reports/10s) while cutting audio drops ~97%
 * (180->5). 12 is the balance: drops ~14/10s, input 482/10s (~3% under floor). */
#define INJECT_MAXQ_DEFAULT 12
static int inject_maxq(void){
    static int q=INJECT_MAXQ_DEFAULT; static uint64_t last=0;
    uint64_t n=now_us();
    if(last==0 || n-last>1000000ull){
        last=n;
        FILE *f=fopen("/tmp/ds5_inject_maxq","r");
        if(f){ int v=0; if(fscanf(f,"%d",&v)==1 && v>=1 && v<=1000) q=v; fclose(f); }
    }
    return q;
}

/* g_lock guards the shared template/identity state below. It is held only for
 * short, NON-BLOCKING work — never across filesystem I/O. Publishing the template
 * record (which does open/write/rename and can block on the jail mount) is done by
 * publish_current() OUTSIDE g_lock, serialized by g_pub_lock, to keep the inject
 * loop's critical section bounded (no audio-grid stalls). */
static pthread_mutex_t g_lock     = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_pub_lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t  g_hdr[8];
static int      g_have = 0;
static uint16_t g_nonce = 0;
static uint64_t g_last_seen = 0;
static int      g_outstanding = 0;   /* our raw-ACL TX packets queued in the controller but not yet
                                        confirmed on-air (via HCI Number_Of_Completed_Packets). Bounded
                                        by inject_maxq() so the baseband keeps polling the DS5 for INPUT. */
static uint64_t g_last_nocp  = 0;    /* last NOCP time; stall backstop if credits stop returning */
static const char *g_tmpl_path;

/* ---- handle<->device identity binding (anti cross-contamination) ----------- *
 * The compositor Left-Alt latch traced to raw-ACL injection landing on the WRONG
 * BT device (the Magic Remote) after the DS5 link flapped and its 12-bit ACL
 * handle was REUSED for another device: the kernel routes our inject purely by
 * that handle, write() still succeeds (handle valid, wrong device), so the old
 * EBADF guard never tripped. We close it by binding the template to the BD_ADDR it
 * was captured on (guaranteed to be the DS5 — only a DualSense receives an 0xA2
 * 0x31/0x32/0x36 HID output) and refusing to inject the instant that handle's
 * bdaddr stops matching. handle->bdaddr is learned from CONN_COMPLETE /
 * (Enhanced)LE_CONN_COMPLETE / DISCONN_COMPLETE events on the SAME monitor socket
 * we already hold, seeded by HCIGETCONNLIST. No address is hardcoded — the binding
 * self-configures, so swapping controllers needs no rebuild.
 *
 * INVARIANT: g_have==1  =>  the live template was bound with a KNOWN bdaddr
 * (g_bound_known==1, g_bound_addr valid). Capture refuses to set g_have without a
 * known bdaddr (fail closed), so every reader can trust g_bound_addr when g_have. */
struct htab_ent { uint8_t addr[6]; uint8_t known; };
static struct htab_ent g_htab[4096];   /* indexed by handle & 0x0fff */
static uint16_t g_handle = 0;          /* handle the live template is bound to */
static uint8_t  g_bound_addr[6];       /* device identity captured with the template */
static int      g_bound_known = 0;     /* g_bound_addr is valid (capture-time gate) */
static int      g_rawfd = -1;          /* main's raw HCI socket, shared for link-policy writes */

/* Disable sniff/hold/park on the DS5 ACL link (keep role-switch). Measured live
 * 2026-07-02: the stack lets the link fall into SNIFF (interval 124 slots =
 * 77.5 ms) every ~30 s; input collapses to ~13 Hz for ~0.5 s until the app's
 * 500 ms stopSniff poll recovers it — the user-visible input dropouts. Clearing
 * the sniff policy bit makes the LMP layer reject sniff requests from EITHER
 * side, so the mode never changes. Per-packet write on a SOCK_RAW datagram
 * socket is atomic, so racing with main's ACL injects is safe. */
#define OP_WRITE_LINK_POLICY 0x080d
#define LINK_POLICY_ACTIVE   0x0001    /* role switch only; sniff/hold/park off */
static void send_link_policy(uint16_t handle){
    if(g_rawfd<0) return;
    uint8_t cmd[8]={ 0x01 /*HCI_COMMAND_PKT*/,
        OP_WRITE_LINK_POLICY&0xff, OP_WRITE_LINK_POLICY>>8, 4,
        (uint8_t)(handle&0xff), (uint8_t)((handle>>8)&0x0f),
        LINK_POLICY_ACTIVE&0xff, LINK_POLICY_ACTIVE>>8 };
    if(write(g_rawfd,cmd,sizeof cmd)!=(ssize_t)sizeof cmd)
        fprintf(stderr,"[txd] link-policy write failed: %s\n",strerror(errno));
}

/* Publish the 16-byte readiness/template record atomically (temp+rename). */
static void publish(uint8_t flags, uint16_t nonce, const uint8_t hdr[8]){
    uint8_t rec[16];
    rec[0]='D';rec[1]='S';rec[2]='5';rec[3]='T';rec[4]=1;rec[5]=flags;
    rec[6]=(uint8_t)(nonce&0xff); rec[7]=(uint8_t)(nonce>>8);
    if(hdr) memcpy(rec+8,hdr,8); else memset(rec+8,0,8);
    char tmp[600]; snprintf(tmp,sizeof tmp,"%s.tmp",g_tmpl_path);
    int fd=open(tmp,O_WRONLY|O_CREAT|O_TRUNC,0644);
    if(fd<0) return;
    ssize_t w=write(fd,rec,16); fchmod(fd,0644); close(fd);
    if(w==16) { if(rename(tmp,g_tmpl_path)<0) unlink(tmp); } else unlink(tmp);
}

/* Publish whatever the CURRENT template state is. g_pub_lock serializes publishers;
 * the g_lock snapshot is taken INSIDE the g_pub_lock section so the last publisher to
 * acquire g_pub_lock reads the latest committed state and writes it LAST — the file
 * therefore converges to the current state regardless of the order two threads call
 * this (snapshotting outside g_pub_lock would let an earlier snapshot's write land
 * last and leave a stale record). Lock order is always g_pub_lock -> g_lock;
 * publish_current is the only place that nests them and every caller has already
 * released g_lock before calling, so there is no inversion. File I/O (in publish())
 * still never runs under g_lock. MUST be called WITHOUT g_lock held. */
static void publish_current(void){
    uint8_t hdr[8]; uint16_t nonce; int have;
    pthread_mutex_lock(&g_pub_lock);
    pthread_mutex_lock(&g_lock);
    have = g_have; nonce = g_nonce; memcpy(hdr, g_hdr, 8);
    pthread_mutex_unlock(&g_lock);
    publish(have ? 1 : 0, nonce, have ? hdr : NULL);
    pthread_mutex_unlock(&g_pub_lock);
}

/* ---- jail-tmp remount self-heal ----------------------------------------- *
 * Both rendezvous sockets live at a PATH inside the app's jail tmp. When Aurora
 * (re)launches it mounts a FRESH tmpfs over /var/palm/jail/<app>/tmp, shadowing
 * the directory our socket node lives in: the bound socket stays alive in the
 * kernel (we hold the fd) but the PATH now resolves into the new, empty mount —
 * so the jailed app's sendto()/connect() by path gets ENOENT and silently falls
 * back to the flow-controlled hidraw write → DS5 audio/haptic dropouts. (The
 * tmpl FILE survives only because publish() re-open(O_CREAT)s it into whatever
 * mount is on top.) We give the sockets the same treatment: watch the mount
 * table via poll() on /proc/self/mountinfo — the kernel wakes us EXACTLY on a
 * mount/unmount, no time-based polling — and re-bind the node into the current
 * top mount whenever the path stops resolving to a socket. If the watch fd can't
 * be opened we degrade to a 500ms time-based poll (never lose self-heal). */

/* True iff a socket node is currently present at path (resolves in the live mount). */
static int node_alive(const char *path){
    struct stat st;
    return stat(path,&st)==0 && S_ISSOCK(st.st_mode);
}

/* Open the mount-change watch. poll() on this fd returns POLLPRI|POLLERR on every
 * mount-table change in our namespace; drain it once so the first poll blocks. */
static int open_mount_watch(void){
    int fd=open("/proc/self/mountinfo",O_RDONLY|O_CLOEXEC);
    if(fd<0){ perror("[txd] open mountinfo"); return -1; }
    char b[4096]; while(read(fd,b,sizeof b)>0){}   /* drain to EOF -> armed */
    return fd;
}

/* Re-arm the watch after an event: rewind and read to EOF (the mount list changed). */
static void rearm_mount_watch(int fd){
    if(lseek(fd,0,SEEK_SET)<0) return;
    char b[4096]; while(read(fd,b,sizeof b)>0){}
}

/* Create + bind a fresh AF_UNIX SOCK_DGRAM node at path (the report channel).
 * Non-blocking so the poll-driven recv drain terminates on EAGAIN. SO_PASSCRED so
 * each datagram carries the sender's SCM_CREDENTIALS for the peer-cred gate. -1 on
 * failure (e.g. parent dir momentarily absent mid-relaunch — caller retries). */
static int bind_unix_dgram(const char *path){
    int fd=socket(AF_UNIX,SOCK_DGRAM,0);
    if(fd<0) return -1;
    struct sockaddr_un ua; memset(&ua,0,sizeof ua);
    ua.sun_family=AF_UNIX; snprintf(ua.sun_path,sizeof ua.sun_path,"%s",path);
    unlink(path);
    if(bind(fd,(struct sockaddr*)&ua,sizeof ua)<0){ close(fd); return -1; }
    chmod(path,0666);   /* the jailed uid (6261) must be able to sendto it */
    int one=1; setsockopt(fd,SOL_SOCKET,SO_PASSCRED,&one,sizeof one);  /* recv SCM_CREDENTIALS */
    int rcv=1<<20; setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&rcv,sizeof rcv);
    int fl=fcntl(fd,F_GETFL,0); if(fl>=0) fcntl(fd,F_SETFL,fl|O_NONBLOCK);
    return fd;
}

/* Create + bind + listen a fresh AF_UNIX SOCK_STREAM node at path (the broker
 * channel). Non-blocking listener so accept() can never block the broker thread on
 * a stale poll wakeup after a remount-rebind. -1 on failure. */
static int bind_unix_stream(const char *path){
    int fd=socket(AF_UNIX,SOCK_STREAM,0);
    if(fd<0) return -1;
    struct sockaddr_un ba; memset(&ba,0,sizeof ba);
    ba.sun_family=AF_UNIX; snprintf(ba.sun_path,sizeof ba.sun_path,"%s",path);
    unlink(path);
    if(bind(fd,(struct sockaddr*)&ba,sizeof ba)<0){ close(fd); return -1; }
    chmod(path,0666);   /* the jailed uid (6261) must be able to connect */
    int fl=fcntl(fd,F_GETFL,0); if(fl>=0) fcntl(fd,F_SETFL,fl|O_NONBLOCK);
    if(listen(fd,8)<0){ close(fd); return -1; }
    return fd;
}

/* ---- HID-FD broker ------------------------------------------------------- *
 * Hand the jailed app an open fd for a /dev/hidrawN node its static jail /dev
 * never received. One request per connection: the app writes the device path it
 * wants (newline-terminated); we authenticate the peer, validate the path, confirm
 * the node is the DS5's own hidraw, open it, and reply with a 1-byte status
 * ('O'=ok / 'E'=error) plus — on success — the open fd as SCM_RIGHTS ancillary. */

/* Defence in depth: only ever open /dev/hidraw<digits>, never an arbitrary path. */
static int valid_hidraw_path(const char *p){
    if(strncmp(p,"/dev/hidraw",11)!=0) return 0;
    const char *d=p+11;
    if(!*d) return 0;
    for(; *d; ++d) if(*d<'0'||*d>'9') return 0;
    return 1;
}

/* Broker allowlist: game controllers whose hidraw node may be handed into the
 * jail. Closes the audit's "second contamination route" — the broker must never
 * hand the app (or any local process) RW access to the Magic Remote's, a
 * keyboard's, or any other system HID node. Kept as an explicit VID/PID list
 * (pid 0 = whole vendor) rather than "anything that looks like a pad": every
 * entry here is reachable RW from the jail. */
static const struct { uint16_t vid, pid; } PAD_ALLOW[] = {
    {DS5_VID, DS5_PID}, /* Sony DualSense */
    {0x054c,  0x0df2},  /* Sony DualSense Edge */
    {0x054c,  0x05c4},  /* Sony DualShock 4 v1 */
    {0x054c,  0x09cc},  /* Sony DualShock 4 v2 */
    {0x054c,  0x0ba0},  /* Sony DS4 USB wireless dongle */
    {0x045e,  0x02e0},  /* Xbox One S pad (BT) */
    {0x045e,  0x02fd},  /* Xbox One S pad (BT, fw 3.x) */
    {0x045e,  0x0b05},  /* Xbox Elite Series 2 (BT) */
    {0x045e,  0x0b13},  /* Xbox Series X|S pad (BT) */
    {0x045e,  0x0b20},  /* Xbox One S pad (BLE fw 5.x) */
    {0x045e,  0x0b22},  /* Xbox Elite Series 2 (BLE fw 5.x) */
    {0x057e,  0x2009},  /* Nintendo Switch Pro Controller */
    {0x2dc8,  0x0000},  /* 8BitDo (controllers only as a vendor) */
};
static int is_allowed_pad_hidraw(int fd){
    struct hidraw_devinfo info;
    if(ioctl(fd,HIDIOCGRAWINFO,&info)<0) return 0;
    uint16_t v=(uint16_t)info.vendor, p=(uint16_t)info.product;
    for(size_t i=0;i<sizeof PAD_ALLOW/sizeof PAD_ALLOW[0];++i)
        if(PAD_ALLOW[i].vid==v && (PAD_ALLOW[i].pid==p || PAD_ALLOW[i].pid==0)) return 1;
    return 0;
}

/* True iff a connected peer's uid is allowed to drive us (jail app or root). */
static int uid_ok(uid_t u){ return u==(uid_t)JAIL_UID || u==0; }

/* Extract the sender's SCM_CREDENTIALS from a recvmsg() control buffer and check
 * the uid. Rejects (0) if no credentials are present. */
static int cred_ok(struct msghdr *mh){
    for(struct cmsghdr *c=CMSG_FIRSTHDR(mh); c; c=CMSG_NXTHDR(mh,c)){
        if(c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_CREDENTIALS &&
           c->cmsg_len==CMSG_LEN(sizeof(struct ucred))){
            struct ucred uc; memcpy(&uc,CMSG_DATA(c),sizeof uc);
            return uid_ok(uc.uid);
        }
    }
    return 0;
}

/* Send status byte + (optionally) one fd as SCM_RIGHTS on a stream conn. */
static int send_fd(int conn, int fd, char status){
    char c=status;
    struct iovec iov; iov.iov_base=&c; iov.iov_len=1;
    struct msghdr msg; memset(&msg,0,sizeof msg);
    msg.msg_iov=&iov; msg.msg_iovlen=1;
    char cbuf[CMSG_SPACE(sizeof(int))];
    if(fd>=0){
        memset(cbuf,0,sizeof cbuf);
        msg.msg_control=cbuf; msg.msg_controllen=sizeof cbuf;
        struct cmsghdr *cm=CMSG_FIRSTHDR(&msg);
        cm->cmsg_level=SOL_SOCKET; cm->cmsg_type=SCM_RIGHTS; cm->cmsg_len=CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cm),&fd,sizeof(int));
    }
    return (int)sendmsg(conn,&msg,0);
}

static void *broker_thread(void *arg){
    prctl(PR_SET_NAME,(unsigned long)"ds5-brk",0,0,0);
    const char *path=(const char*)arg;
    int sfd=bind_unix_stream(path);
    if(sfd<0){ perror("[txd] bind broker"); return NULL; }
    fprintf(stderr,"[txd] hid-fd broker up: %s\n",path);
    int minfo=open_mount_watch();   /* self-heal the broker node across jail-tmp remounts */
    for(;;){
        /* Steady state: block on accept-ready + mount changes. A 500ms timeout
         * engages while a rebind is pending (node gone, dir not yet ready) or the
         * mount watch is unavailable (degrade to time-based polling). poll() ignores
         * a pollfd whose fd is < 0, so a dead minfo simply contributes nothing. */
        struct pollfd pf[2]={{sfd,POLLIN,0},{minfo,POLLPRI,0}};
        int to=(sfd<0 || minfo<0)?500:-1;
        int pr=poll(pf,2,to);
        if(pr<0){ if(errno==EINTR) continue; usleep(5000); continue; }
        if(pr==0 || pf[1].revents){
            if(minfo<0) minfo=open_mount_watch();        /* retry a previously-failed watch */
            else if(pf[1].revents) rearm_mount_watch(minfo);
            if(!node_alive(path)){
                if(sfd>=0){ close(sfd); sfd=-1; }
                int ns=bind_unix_stream(path);
                if(ns>=0){ sfd=ns; fprintf(stderr,"[txd] jail-tmp remount -> rebound %s\n",path); }
            }
            continue;   /* re-poll with fresh fds; never accept() on a stale revents */
        }
        if(sfd<0 || !(pf[0].revents&POLLIN)) continue;
        int conn=accept(sfd,NULL,NULL);
        if(conn<0){ if(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK) continue; usleep(5000); continue; }
        /* Authenticate the peer before doing any privileged work for it. */
        struct ucred uc; socklen_t ucl=sizeof uc;
        if(getsockopt(conn,SOL_SOCKET,SO_PEERCRED,&uc,&ucl)<0){ close(conn); continue; }
        if(!uid_ok(uc.uid)){ fprintf(stderr,"[txd] broker rejected peer uid=%u\n",uc.uid); send_fd(conn,-1,'E'); close(conn); continue; }
        struct timeval tv={.tv_sec=2,.tv_usec=0};
        setsockopt(conn,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
        char req[80]; ssize_t n=recv(conn,req,sizeof req-1,0);
        if(n<=0){ close(conn); continue; }
        req[n]='\0';
        for(char *e=req+strlen(req); e>req && (e[-1]=='\n'||e[-1]=='\r'||e[-1]==' '); --e) e[-1]='\0';
        int hfd=-1;
        if(valid_hidraw_path(req)){
            hfd=open(req,O_RDWR|O_CLOEXEC);
            if(hfd<0) hfd=open(req,O_RDONLY|O_CLOEXEC);
            if(hfd>=0 && !is_allowed_pad_hidraw(hfd)){   /* only allowlisted pads leave the broker */
                fprintf(stderr,"[txd] broker refused non-allowlisted hidraw %s\n",req);
                close(hfd); hfd=-1;
            }
        }
        if(hfd>=0){
            send_fd(conn,hfd,'O');
            fprintf(stderr,"[txd] broker handed fd for %s\n",req);
            close(hfd);   /* app now holds its own ref via SCM_RIGHTS */
        } else {
            send_fd(conn,-1,'E');
            fprintf(stderr,"[txd] broker open/verify failed for '%s' errno=%d\n",req,errno);
        }
        close(conn);
    }
}

/* Parse one HCI event packet off the MONITOR stream and maintain the
 * handle->bdaddr table; invalidate the live template if the bound handle drops or
 * is reassigned to a different device. Called from capture_thread WITHOUT g_lock
 * held (it takes g_lock for the shared state, then publishes outside it). */
static void handle_hci_event(const uint8_t *e, int el){
    if(el < 2) return;
    uint8_t code=e[0]; const uint8_t *p=e+2; int pl=el-2;   /* skip [code][param_len] */
    const char *reason=NULL;
    if(code==HCI_EV_CONN_COMPLETE && pl>=9){                /* status,handle(2),bdaddr(6),... */
        if(p[0]!=0x00) return;
        uint16_t hh=(uint16_t)((p[1]|(p[2]<<8))&0x0fff);
        pthread_mutex_lock(&g_lock);
        memcpy(g_htab[hh].addr,p+3,6); g_htab[hh].known=1;
        if(g_have && hh==g_handle && memcmp(p+3,g_bound_addr,6)!=0){ g_have=0; reason="bound handle reassigned (BR/EDR)"; }
        pthread_mutex_unlock(&g_lock);
    } else if(code==HCI_EV_DISCONN_COMPLETE && pl>=4){      /* status,handle(2),reason */
        if(p[0]!=0x00) return;
        uint16_t hh=(uint16_t)((p[1]|(p[2]<<8))&0x0fff);
        pthread_mutex_lock(&g_lock);
        g_htab[hh].known=0;
        if(g_have && hh==g_handle){ g_have=0; reason="bound handle disconnected"; }
        pthread_mutex_unlock(&g_lock);
    } else if(code==HCI_EV_LE_META && pl>=12){              /* subev,status,handle(2),role,atype,addr(6) */
        /* Legacy (0x01) and Enhanced (0x0A) LE Connection Complete share the same
         * prefix layout through peer_addr, so one offset path covers both. */
        if((p[0]!=HCI_SUBEV_LE_CONN && p[0]!=HCI_SUBEV_LE_ENH_CONN) || p[1]!=0x00) return;
        uint16_t hh=(uint16_t)((p[2]|(p[3]<<8))&0x0fff);
        pthread_mutex_lock(&g_lock);
        memcpy(g_htab[hh].addr,p+6,6); g_htab[hh].known=1;
        if(g_have && hh==g_handle && memcmp(p+6,g_bound_addr,6)!=0){ g_have=0; reason="bound handle reassigned (LE)"; }
        pthread_mutex_unlock(&g_lock);
    } else if(code==HCI_EV_NUM_COMP_PKTS && pl>=1){        /* TX credits returned: free the outstanding window */
        int nh=p[0];
        if(pl < 1+nh*4) return;
        pthread_mutex_lock(&g_lock);
        if(g_have){
            uint16_t bh=(uint16_t)((g_hdr[0]|(g_hdr[1]<<8))&0x0fff);
            for(int i=0;i<nh;i++){
                uint16_t hh=(uint16_t)((p[1+i*4]|(p[2+i*4]<<8))&0x0fff);
                if(hh==bh){
                    int cnt=(int)(p[3+i*4]|(p[4+i*4]<<8));
                    g_outstanding-=cnt; if(g_outstanding<0) g_outstanding=0;
                    /* Refresh the stall timestamp ONLY for OUR handle's completions:
                     * a global refresh would let any other device's NOCP chatter
                     * (Magic Remote etc.) suppress the 150ms backstop exactly when
                     * our credits are the ones wedged. */
                    g_last_nocp=now_ms();
                }
            }
        }
        pthread_mutex_unlock(&g_lock);
        return;   /* NOCP never affects template validity */
    } else return;
    if(reason){ publish_current(); fprintf(stderr,"[txd] %s -> template INVALID\n",reason); }
}

/* Best-effort: seed/refresh the handle->bdaddr table from the kernel's current
 * connection list, so a controller already connected before we started monitoring
 * (or whose CONN_COMPLETE we missed) is still identity-bound. Uses a throwaway
 * unbound HCI socket (the bluez convention). Quiet on repeat: logs the
 * "unavailable" notice once and a seeded handle only when its mapping changes.
 * Safe to call repeatedly from capture_thread (takes g_lock itself). */
static void seed_conn_list(void){
    static int warned=0;
    int s=socket(AF_BLUETOOTH,SOCK_RAW,BTPROTO_HCI);
    if(s<0) return;
    struct hci_conn_list_req req; memset(&req,0,sizeof req);
    req.dev_id=TARGET_HCI_INDEX; req.conn_num=16;
    if(ioctl(s,HCIGETCONNLIST,&req)<0){
        if(!warned){ fprintf(stderr,"[txd] HCIGETCONNLIST unavailable (errno=%d) -> event-parse only\n",errno); warned=1; }
        close(s); return;
    }
    close(s);
    int n=req.conn_num>16?16:req.conn_num;
    /* Stage changed entries, then log AFTER releasing g_lock — seed_conn_list now runs
     * at runtime from capture_thread (the need_learn path), and a blocking fprintf
     * under g_lock could stall the inject thread waiting on the same lock (cf. #9). */
    struct { uint16_t hh; uint8_t a[6]; } chg[16]; int nchg=0;
    pthread_mutex_lock(&g_lock);
    for(int i=0;i<n;i++){
        uint16_t hh=req.ci[i].handle & 0x0fff;
        if(!g_htab[hh].known || memcmp(g_htab[hh].addr,req.ci[i].bdaddr.b,6)!=0){
            memcpy(g_htab[hh].addr,req.ci[i].bdaddr.b,6); g_htab[hh].known=1;
            chg[nchg].hh=hh; memcpy(chg[nchg].a,req.ci[i].bdaddr.b,6); nchg++;
        }
    }
    pthread_mutex_unlock(&g_lock);
    for(int i=0;i<nchg;i++){ const uint8_t*a=chg[i].a;
        fprintf(stderr,"[txd] seed handle=0x%03x addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
                chg[i].hh,a[5],a[4],a[3],a[2],a[1],a[0]); }
}

/* Capture thread: watch HCI_CHANNEL_MONITOR (root) for our outgoing HID-output
 * and keep the current connection's handle+CID published — but only ever publish
 * VALID once the bound handle's bdaddr is known (fail closed). */
static void *capture_thread(void *arg){
    (void)arg;
    prctl(PR_SET_NAME,(unsigned long)"ds5-cap",0,0,0);
    int mfd=socket(AF_BLUETOOTH,SOCK_RAW,BTPROTO_HCI);
    if(mfd<0){ perror("[txd] socket monitor"); return NULL; }
    struct sockaddr_hci ma; memset(&ma,0,sizeof ma);
    ma.hci_family=AF_BLUETOOTH; ma.hci_dev=HCI_DEV_NONE; ma.hci_channel=HCI_CHANNEL_MONITOR;
    if(bind(mfd,(struct sockaddr*)&ma,sizeof ma)<0){ perror("[txd] bind monitor"); close(mfd); return NULL; }
    struct timeval tv={.tv_sec=0,.tv_usec=300000}; setsockopt(mfd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    uint8_t buf[2048];
    uint64_t last_learn=0, last_policy=0;
    for(;;){
        /* Idle backstop: evaluated EVERY wakeup (not only on recv-timeout) so it
         * still fires while other BT devices keep the monitor socket busy. After a
         * flap the DS5 stops emitting HID-output -> g_last_seen ages out -> template
         * invalidated within IDLE_INVALIDATE_MS even if the DISCONN event was lost. */
        int idle_inval=0; int reassert_handle=-1;
        pthread_mutex_lock(&g_lock);
        if(g_have && now_ms()-g_last_seen>IDLE_INVALIDATE_MS){ g_have=0; idle_inval=1; }
        if(g_have && now_ms()-last_policy>5000){ last_policy=now_ms(); reassert_handle=g_handle; }
        pthread_mutex_unlock(&g_lock);
        if(idle_inval){ publish_current(); fprintf(stderr,"[txd] link idle -> template INVALID\n"); }
        /* Re-assert the no-sniff link policy every 5 s while bound: the LG stack can
         * rewrite the policy on its own events, and the command is a no-op on air. */
        if(reassert_handle>=0) send_link_policy((uint16_t)reassert_handle);

        int r=(int)recv(mfd,buf,sizeof buf,0);
        if(r<0){
            /* EAGAIN/EWOULDBLOCK is the normal 300ms SO_RCVTIMEO tick, EINTR a signal;
             * any other errno is a real socket error -> back off so we never busy-spin. */
            if(errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR) usleep(50000);
            continue;
        }
        if(r<(int)sizeof(struct hci_mon_hdr)) continue;
        struct hci_mon_hdr*h=(struct hci_mon_hdr*)buf;
        if(h->index!=TARGET_HCI_INDEX) continue;   /* track only the controller we inject on */
        uint8_t*d=buf+sizeof(struct hci_mon_hdr); int dl=h->len;
        if(r<(int)(sizeof(struct hci_mon_hdr)+dl)) continue;
        if(h->opcode==MON_EVENT_PKT){ handle_hci_event(d,dl); continue; }
        if(h->opcode!=MON_ACL_TX_PKT) continue;
        if(dl<10) continue;
        uint8_t pb=(uint8_t)((d[1]>>4)&0x3); if(pb==1) continue;
        if(d[8]!=0xA2 || !injectable(d[9])) continue;
        uint16_t acl_len=(uint16_t)(d[2]|(d[3]<<8)), l2_len=(uint16_t)(d[4]|(d[5]<<8));
        if(acl_len!=(uint16_t)(dl-4)) continue;
        if(l2_len !=(uint16_t)(acl_len-4)) continue;

        uint16_t hh=(uint16_t)((d[0]|(d[1]<<8))&0x0fff);
        int did_capture=0, need_learn=0; unsigned cid=0; uint16_t nonce=0;
        pthread_mutex_lock(&g_lock);
        /* Single inject slot: once bound, HID-output on any OTHER handle is a
         * FOREIGN pad (reachable since the multi-pad broker — e.g. a second
         * DualSense seeding via hidraw, or other tooling driving DS5#2). Ignore
         * it entirely: never flip-flop the template per report, and never let
         * foreign traffic refresh g_last_seen (the idle backstop must track the
         * BOUND pad only). Rebind happens only after invalidation clears g_have. */
        if(g_have && hh!=g_handle){ pthread_mutex_unlock(&g_lock); continue; }
        g_last_seen=now_ms();
        /* Only handle (d[0..1]) + CID (d[6..7]) are connection-constant; lengths
         * (d[2..5]) vary per report id and are recomputed at inject. */
        int changed = (!g_have || g_hdr[0]!=d[0]||g_hdr[1]!=d[1]||g_hdr[6]!=d[6]||g_hdr[7]!=d[7]);
        if(changed){
            if(g_htab[hh].known){
                /* Identity confirmed: bind the template to the DS5 bdaddr on this
                 * handle and go VALID. By the 0xA2 + 0x31/0x32/0x36 content filter
                 * above, that device IS the DS5, so any later reassignment of this
                 * handle to a different bdaddr is a contamination event we reject. */
                memcpy(g_hdr,d,8); g_handle=hh; memcpy(g_bound_addr,g_htab[hh].addr,6);
                g_bound_known=1; g_have=1; g_nonce++;
                g_outstanding=0; g_last_nocp=now_ms();   /* fresh link = fresh credit window:
                     never inherit phantom credits from a flapped connection whose
                     NOCPs were lost (they can never be drained once g_have dropped) */
                did_capture=1; cid=(unsigned)(d[6]|(d[7]<<8)); nonce=g_nonce;
            } else {
                /* Fail CLOSED: bdaddr unknown -> do NOT publish valid. The app keeps
                 * seeding via hidraw (safe) until we learn the identity. */
                need_learn=1;
            }
        }
        pthread_mutex_unlock(&g_lock);
        if(did_capture){
            publish_current();
            send_link_policy(hh);   /* pin the link ACTIVE the moment we bind it */
            fprintf(stderr,"[txd] template handle=0x%03x CID=0x%04x nonce=%u bound (sniff off)\n",hh,cid,nonce);
        }
        if(need_learn){
            /* Throttled refresh of the handle->bdaddr table for the case where the
             * DS5 was already connected before we started (no CONN_COMPLETE seen).
             * Once HCIGETCONNLIST fills g_htab[hh], the next report binds + goes valid. */
            uint64_t t=now_ms();
            if(t-last_learn>500){ last_learn=t; seed_conn_list(); }
        }
    }
}

int main(int argc,char**argv){
    const char *sock_path = argc>1?argv[1]:"/var/palm/jail/com.aurora.gamestream/tmp/ds5_acl.sock";
    g_tmpl_path           = argc>2?argv[2]:"/var/palm/jail/com.aurora.gamestream/tmp/ds5_acl_tmpl";
    const char *hidfd_path= argc>3?argv[3]:"/var/palm/jail/com.aurora.gamestream/tmp/ds5_hidfd.sock";

    /* Leave the MAIN thread's comm at its default (argv[0] basename "ds5_txd"): the
     * launcher and management scripts (enforce_single.sh, revert_until_up.sh, etc.)
     * identify the daemon with `pkill -x ds5_txd`, which matches the comm — renaming
     * main would silently break every one of them. Only the worker threads are named
     * (ds5-cap/ds5-brk, per audit O3) so the respawner can still target them by TID. */
    struct sched_param sp; memset(&sp,0,sizeof sp); sp.sched_priority=14;
    sched_setscheduler(0,SCHED_FIFO,&sp);

    publish(0,0,NULL);   /* start INVALID so a stale boot file can't mislead the app */
    seed_conn_list();    /* identity-bind a controller already connected at startup */

    /* Root HCI raw socket for injection (write is permitted as root). Bound to the
     * SAME controller index we track on MONITOR (TARGET_HCI_INDEX). */
    int rawfd=socket(AF_BLUETOOTH,SOCK_RAW,BTPROTO_HCI);
    if(rawfd<0){ perror("[txd] socket raw"); return 1; }
    struct sockaddr_hci ra; memset(&ra,0,sizeof ra);
    ra.hci_family=AF_BLUETOOTH; ra.hci_dev=TARGET_HCI_INDEX; ra.hci_channel=HCI_CHANNEL_RAW;
    if(bind(rawfd,(struct sockaddr*)&ra,sizeof ra)<0){ perror("[txd] bind raw"); return 1; }
    int fl=fcntl(rawfd,F_GETFL,0); if(fl>=0) fcntl(rawfd,F_SETFL,fl|O_NONBLOCK);
    g_rawfd=rawfd;   /* published before the capture thread starts (policy writes) */

    /* AF_UNIX datagram socket the jailed app sends reports to (non-blocking, 1MB
     * recv buffer, SO_PASSCRED — see bind_unix_dgram). Self-healed across remounts. */
    int ufd=bind_unix_dgram(sock_path);
    if(ufd<0){ perror("[txd] bind unix"); return 1; }

    pthread_t cap; pthread_create(&cap,NULL,capture_thread,NULL);
    pthread_t brk; pthread_create(&brk,NULL,broker_thread,(void*)hidfd_path);
    fprintf(stderr,"[txd] forwarder up: unix=%s tmpl=%s hidfd=%s\n",sock_path,g_tmpl_path,hidfd_path);

    /* Event loop: wait on forwarded reports (ufd) AND mount-table changes (minfo)
     * at once. Pure poll(-1) in steady state; a 500ms tick engages only while a
     * rebind is pending or the mount watch is unavailable (degrade to polling). */
    int minfo=open_mount_watch();   /* self-heal ds5_acl.sock across jail-tmp remounts */
    uint8_t rep[ACL_MAX_REPORT], frame[1+8+1+ACL_MAX_REPORT];
    long injected=0, dropped=0, paced=0; uint64_t last_log=now_ms();
    g_last_nocp=now_ms();   /* seed the stall backstop so output can't wedge before the first NOCP */
    for(;;){
        struct pollfd pfd[2]={{ufd,POLLIN,0},{minfo,POLLPRI,0}};
        int to=(ufd<0 || minfo<0)?500:-1;
        int pr=poll(pfd,2,to);
        if(pr<0){ if(errno==EINTR) continue; usleep(2000); continue; }

        /* Mount table changed (or retry tick while rebinding / watch down): if our
         * node's path stopped resolving to a socket, Aurora remounted its tmp under
         * us — bind a fresh node into the current top mount and re-publish readiness. */
        if(pr==0 || pfd[1].revents){
            if(minfo<0) minfo=open_mount_watch();           /* retry a previously-failed watch */
            else if(pfd[1].revents) rearm_mount_watch(minfo);
            if(!node_alive(sock_path)){
                if(ufd>=0){ close(ufd); ufd=-1; }
                int nu=bind_unix_dgram(sock_path);
                if(nu>=0){
                    ufd=nu;
                    publish_current();   /* re-publish current state into the new mount */
                    fprintf(stderr,"[txd] jail-tmp remount -> rebound ds5_acl.sock + re-published\n");
                }
            }
        }

        /* Drain reports queued on the (non-blocking) report socket, bounded per
         * wakeup so a flood can't monopolize the loop or starve the mount watch. */
        if(ufd>=0 && (pfd[0].revents&POLLIN)){
            for(int drained=0; drained<DRAIN_CAP; drained++){
                struct iovec iov={.iov_base=rep,.iov_len=sizeof rep};
                union { char b[CMSG_SPACE(sizeof(struct ucred))]; struct cmsghdr a; } cmsgu;
                struct msghdr mh; memset(&mh,0,sizeof mh);
                mh.msg_iov=&iov; mh.msg_iovlen=1; mh.msg_control=cmsgu.b; mh.msg_controllen=sizeof cmsgu.b;
                ssize_t n=recvmsg(ufd,&mh,0);
                if(n<0){ if(errno==EINTR) continue; break; }   /* EAGAIN -> drained */
                if(n==0) continue;                             /* zero-length datagram: skip, keep draining */
                if(mh.msg_flags & MSG_TRUNC){ dropped++; continue; } /* oversized: never inject a truncated frame */
                if(!cred_ok(&mh)){ dropped++; continue; }      /* peer-cred gate: jail uid only */
                if(!injectable(rep[0])){ dropped++; continue; }/* only DS5 output reports (0x31/0x32/0x36) */

                int ok=0, need_inval=0, over=0; const char *reason=NULL;
                /* Read the tunable BEFORE taking g_lock: inject_maxq() refreshes its
                 * cache from /tmp ~1/s, and g_lock must never be held across
                 * filesystem I/O (see the invariant above g_lock). Per-report constant. */
                int maxq=inject_maxq();
                pthread_mutex_lock(&g_lock);
                if(g_have){
                    /* Re-check the live handle->bdaddr mapping and inject under the
                     * SAME lock so a reassignment can't slip into a check->write gap
                     * (TOCTOU). g_have implies g_bound_known, so g_bound_addr is valid. */
                    uint16_t hh=(uint16_t)((g_hdr[0]|(g_hdr[1]<<8))&0x0fff);
                    if(g_htab[hh].known && memcmp(g_htab[hh].addr,g_bound_addr,6)!=0){
                        g_have=0; need_inval=1; reason="bound handle now foreign -> template INVALID";
                    } else if(g_outstanding>=maxq &&
                              !(g_last_nocp && now_ms()-g_last_nocp>STALL_RESET_MS)){
                        /* Credit window full: the controller hasn't confirmed our queued TX,
                         * so the link is busy (input/video wants airtime). Drop this output
                         * report (real-time, latest wins) instead of deepening the backlog.
                         * Only happens under contention -> no static bandwidth sacrifice. */
                        over=1;
                    } else {
                        if(g_outstanding>=maxq) g_outstanding=0; /* stall backstop: credits stopped -> resync */
                        uint16_t l2=(uint16_t)(1+n), acl=(uint16_t)(4+l2);
                        frame[0]=HCI_ACLDATA_PKT; memcpy(frame+1,g_hdr,8);
                        frame[3]=(uint8_t)(acl&0xff); frame[4]=(uint8_t)(acl>>8);
                        frame[5]=(uint8_t)(l2&0xff);  frame[6]=(uint8_t)(l2>>8);
                        frame[9]=0xA2; memcpy(frame+10,rep,n);
                        ssize_t wr=write(rawfd,frame,10+n);
                        if(wr==(ssize_t)(10+n)){ ok=1; g_outstanding++; }
                        else if(wr<0 && errno==EBADF){   /* stale handle (reconnect): force reseed */
                            g_have=0; need_inval=1; reason="inject EBADF -> template INVALID (reconnect)";
                        }
                    }
                }
                pthread_mutex_unlock(&g_lock);
                if(ok) injected++; else if(over) paced++; else dropped++;
                if(need_inval){ publish_current(); fprintf(stderr,"[txd] %s\n",reason); }
            }
        }
        if(now_ms()-last_log>10000){ fprintf(stderr,"[txd] inj=%ld drop=%ld backoff=%ld q=%d/%d\n",injected,dropped,paced,g_outstanding,inject_maxq()); last_log=now_ms(); }
    }
    return 0;
}
