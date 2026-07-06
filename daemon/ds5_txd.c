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
#define MON_COMMAND_PKT     2
#define MON_EVENT_PKT       3
#define MON_ACL_TX_PKT      4
#define ACL_MAX_REPORT      4096

/* HCI event codes we parse off the MONITOR stream to track handle<->device. */
#define HCI_EV_CONN_COMPLETE    0x03
#define HCI_EV_DISCONN_COMPLETE 0x05
#define HCI_EV_CMD_COMPLETE     0x0e
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

/* Elastic FIFO for 0x36 speaker/haptics audio (OPT-IN, default 0 = disabled =
 * legacy drop-newest behavior). When the credit window is transiently full
 * (BT airtime lost to input/video), the drop-newest path punches a ~10ms hole
 * in the audio -> audible "Aussetzer". With a FIFO of depth N>0, a full-window
 * audio frame is instead HELD and injected as soon as a credit frees (drained
 * on the next report arrival, ~10ms grid), converting a transient drop into a
 * few-ms delay. The window (inject_maxq) still bounds the controller's TX queue,
 * so input polling is unaffected -- the FIFO holds frames in OUR memory, not in
 * the controller. Sustained congestion overflows the FIFO -> drop-oldest, so
 * latency is bounded by N frames (~10.7ms each). Live-tunable via
 * /tmp/ds5_inject_fifo (0..FIFO_MAX). Cached ~1/sec. */
#define FIFO_MAX             16
#define FIFO_ENTRY_MAX       256   /* audio 0x36 reports are well under this */
#define INJECT_FIFO_DEFAULT  0
static int inject_fifo(void){
    static int d=INJECT_FIFO_DEFAULT; static uint64_t last=0;
    uint64_t n=now_us();
    if(last==0 || n-last>1000000ull){
        last=n;
        FILE *f=fopen("/tmp/ds5_inject_fifo","r");
        if(f){ int v=-1; if(fscanf(f,"%d",&v)==1 && v>=0 && v<=FIFO_MAX) d=v; fclose(f); }
    }
    return d;
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

/* In-flight TX type ring (guarded by g_lock, same lifetime as g_outstanding).
 * NOCP credits do not say WHICH packet completed, so per-type accounting
 * approximates FIFO: injects push their type, each returned credit pops the
 * oldest. The rumble count this yields (g_rumble_fly) is what lets the credit
 * window be type-aware — rumble bounded by its OWN occupancy instead of the
 * total (a window full of audio must never read as "rumble is over budget").
 * The approximation errs OPEN under foreign kernel-path TX on the same handle
 * (their NOCPs pop our entries early -> g_rumble_fly under-counts -> rumble
 * slightly more permissive), which is the safe direction: it can relax the
 * rumble cap a little, never starve it. */
#define TXRING 64
static uint8_t g_txtype[TXRING];     /* 1 = rumble (0x31/0x32), 0 = audio (0x36) */
static int g_tx_head=0, g_tx_cnt=0;
static int g_rumble_fly=0;           /* believed-in-flight rumble packets */
static void txwin_reset(void){ g_tx_head=0; g_tx_cnt=0; g_rumble_fly=0; }
static void txwin_push(int rumble){
    if(g_tx_cnt==TXRING){             /* overflow (huge tuned maxq): age out oldest */
        if(g_txtype[g_tx_head]) g_rumble_fly--;
        g_tx_head=(g_tx_head+1)%TXRING; g_tx_cnt--;
    }
    g_txtype[(g_tx_head+g_tx_cnt)%TXRING]=(uint8_t)(rumble?1:0);
    g_tx_cnt++; if(rumble) g_rumble_fly++;
}
static void txwin_pop(int cnt){
    while(cnt-->0 && g_tx_cnt>0){
        if(g_txtype[g_tx_head]) g_rumble_fly--;
        g_tx_head=(g_tx_head+1)%TXRING; g_tx_cnt--;
    }
}
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

/* Inject one output report as a raw-ACL frame under g_lock, honoring the credit
 * window. Critical section identical in scope to the legacy inline path (one
 * bounded, non-blocking write; TOCTOU handle re-check under the same lock).
 *
 * The window is TYPE-AWARE, derived from rep[0]:
 *   audio (0x36):        may fill maxq-1 credits. The last credit is RESERVED so
 *                        a fresh rumble frame always finds room the moment none
 *                        of its own are in flight — without the reserve, the
 *                        ~94/s audio stream keeps the window pinned at full
 *                        under contention and a rumble state change (e.g. the
 *                        OFF after a burst) is dropped for as long as the
 *                        contention lasts: the pad keeps buzzing with the last
 *                        applied intensity.
 *   rumble (0x31/0x32):  bounded by the full window AND by its OWN in-flight
 *                        count (g_rumble_fly) at maxq/2 — counting rumble by
 *                        its own occupancy, not the total, is what makes the
 *                        "rumble may only fill half the window" contract real.
 *
 * Stall backstop: window full with no NOCP for STALL_RESET_MS means the credits
 * are presumed lost (a flap ate the NOCPs) -> resync to empty AND RE-ARM
 * g_last_nocp. Without the re-arm a long radio blackout (NOCPs delayed, not
 * lost) keeps the stall condition true, so the window would reset every time it
 * refills (~130ms at audio rate) — i.e. unbounded injection into the controller
 * TX queue for the whole blackout, exactly the input-poll starvation the window
 * exists to prevent. Audio-only: a rumble call operates at half occupancy and
 * must never zero the shared accounting.
 *
 * Returns:  1 = injected (g_outstanding++),
 *           0 = credit window full (caller may queue or drop),
 *          -1 = template invalidated (foreign handle / EBADF; *reason set, caller
 *               must publish_current() + log),
 *          -2 = no live template (g_have==0). */
static int inject_one(int rawfd, const uint8_t *rep, int n, int maxq, const char **reason){
    uint8_t frame[1+8+1+ACL_MAX_REPORT];
    int r=-2;
    int is_rumble=(rep[0]!=0x36);
    int lim  = is_rumble ? maxq : (maxq>1 ? maxq-1 : 1);   /* audio leaves 1 credit reserved */
    int rcap = (maxq/2)>0 ? (maxq/2) : 1;
    pthread_mutex_lock(&g_lock);
    if(g_have){
        uint16_t hh=(uint16_t)((g_hdr[0]|(g_hdr[1]<<8))&0x0fff);
        if(g_htab[hh].known && memcmp(g_htab[hh].addr,g_bound_addr,6)!=0){
            g_have=0; *reason="bound handle now foreign -> template INVALID"; r=-1;
        } else {
            if(!is_rumble && g_outstanding>=lim &&
               g_last_nocp && now_ms()-g_last_nocp>STALL_RESET_MS){
                g_outstanding=0; txwin_reset();   /* credits presumed lost -> resync */
                g_last_nocp=now_ms();             /* re-arm: at most one resync per STALL_RESET_MS */
            }
            if(g_outstanding>=lim || (is_rumble && g_rumble_fly>=rcap)){
                r=0;
            } else {
                uint16_t l2=(uint16_t)(1+n), acl=(uint16_t)(4+l2);
                frame[0]=HCI_ACLDATA_PKT; memcpy(frame+1,g_hdr,8);
                frame[3]=(uint8_t)(acl&0xff); frame[4]=(uint8_t)(acl>>8);
                frame[5]=(uint8_t)(l2&0xff);  frame[6]=(uint8_t)(l2>>8);
                frame[9]=0xA2; memcpy(frame+10,rep,n);
                ssize_t wr=write(rawfd,frame,10+n);
                if(wr==(ssize_t)(10+n)){ r=1; g_outstanding++; txwin_push(is_rumble); }
                else if(wr<0 && errno==EBADF){ g_have=0; *reason="inject EBADF -> template INVALID (reconnect)"; r=-1; }
                else r=0;
            }
        }
    }
    pthread_mutex_unlock(&g_lock);
    return r;
}

/* Audio-only elastic FIFO (single-threaded: touched only by the main poll loop).
 * g_fifo_gen stamps the backlog with the template nonce it was queued under, so
 * frames held across an invalidate->rebind (a new session, new nonce) are
 * recognized as stale and dropped instead of being injected as a burst of
 * last-session audio at the head of the new one. */
static struct { uint8_t buf[FIFO_ENTRY_MAX]; int len; } g_fifo[FIFO_MAX];
static int g_fifo_head=0, g_fifo_count=0;
static uint16_t g_fifo_gen=0;
static void fifo_clear(void){ g_fifo_head=0; g_fifo_count=0; }

/* Drain the audio backlog oldest-first while credits allow (main thread only).
 * Runs even when the FIFO tunable is 0 so disabling it flushes a residual
 * backlog instead of stranding it. Returns the number injected; on template
 * invalidation sets need_inval + reason (caller publishes) and drops the stale
 * backlog. */
static long drain_fifo(int rawfd, int maxq, int *need_inval, const char **reason){
    long inj=0;
    while(g_fifo_count>0){
        int idx=g_fifo_head;
        int r=inject_one(rawfd,g_fifo[idx].buf,g_fifo[idx].len,maxq,reason);
        if(r==1){ g_fifo_head=(g_fifo_head+1)%FIFO_MAX; g_fifo_count--; inj++; continue; }
        if(r==-1){ *need_inval=1; fifo_clear(); }  /* template gone -> drop stale audio */
        else if(r==-2) fifo_clear();               /* no template: backlog is already stale */
        break;                                     /* credits full (0) -> retry next wakeup */
    }
    return inj;
}
static int      g_rawfd = -1;          /* main's raw HCI socket, shared for link-policy writes */

/* HCI command health guard + rate discipline (2026-07-05, reworked 07-06).
 * PROVEN on-air (raw-write + monitor-listen probe): the LG vendor stack holds
 * the adapter in user-channel mode — the controller answers every command
 * fine, but the responses bypass the kernel's command tracking. So EVERY
 * command we send via the kernel path occupies a 2s "command tx timeout"
 * slot; the kernel drains OUR queue at a fixed 1 command / 2s (0.5/s). Send
 * faster than that for long enough and the socket sndbuf overflows (~30min at
 * the old 1Hz scan war) -> permanent EAGAIN and our scan-offs arrive minutes
 * late (the night's "firmware wedge" + "dropouts got worse", both really this
 * arithmetic). Rules:
 *  (a) steady-state command rate stays well under the 0.5/s drain (10s
 *      link-policy refresh + >=3s-ratelimited scan sends <= 0.43/s typical);
 *      BURSTS (template flap = invalidate+rebind = up to 3 commands) are
 *      absorbed by a hard unacked-queue cap (CMD_PEND_MAX): once that many
 *      commands await their Command Complete, further sends are refused and
 *      the reconcilers simply retry later — the sndbuf can never build more
 *      than ~CMD_PEND_MAX*2s of backlog no matter how hard the session flaps.
 *  (b) every sent command is queued with its timestamp and watched for a
 *      Command Complete on the MONITOR socket (sees responses even in
 *      user-channel mode). The no-response deadline SCALES with the queue
 *      depth we created ourselves — N unacked commands legitimately take
 *      ~2N s to drain, so a fixed deadline false-tripped on a mere flap
 *      burst — miss = cease commands and enter the DEAD state;
 *  (c) EAGAIN on a command write (= sndbuf already full) trips immediately;
 *  (d) DEAD is no longer terminal: every 60s ONE probe command is sent past
 *      the gate; a monitor-observed Command Complete for it clears the state
 *      (logged CMDRECOVER). A foreign completion of the same opcode inside
 *      the probe window can recover us spuriously — harmless, the guard
 *      re-trips on the next unanswered command if the path is really dead.
 * Raw-ACL injection bypasses the cmd queue and is unaffected.
 * All fields are capture-thread-only, no locking needed. */
static volatile int g_cmd_dead = 0;
static uint64_t g_cmd_dead_t = 0;    /* trip time; schedules the 60s recovery probes */
static uint16_t g_probe_op   = 0;    /* recovery probe awaiting Command Complete */
static volatile long g_scan_ctr = 0; /* foreign scan re-enables countered (fight-rate telemetry) */
static long g_gap30=0, g_gap50=0, g_gap80=0; /* NOCP-gap histogram 30-50/50-80/>=80ms (main thread) */
#define CMD_PEND_MAX 8
static struct { uint16_t op; uint64_t deadline; } g_pend[CMD_PEND_MAX];
static int g_pend_n = 0;             /* commands written but with no Command Complete seen yet */
static void cmd_guard_trip(const char *why, unsigned detail){
    if(g_cmd_dead) return;
    g_cmd_dead=1; g_cmd_dead_t=now_ms(); g_pend_n=0;
    fprintf(stderr,"[txd] HCI COMMAND PATH DEAD (%s 0x%04x) -> ceasing HCI commands "
                   "(scan/sniff mgmt paused; ACL inject unaffected; recovery probe every 60s).\n",
            why,detail);
}
/* Single choke point for HCI commands: dead-gate, unacked-queue cap, EAGAIN
 * trip, pend bookkeeping. force=1 is reserved for the recovery probe.
 * Returns 0 = written (pend entry queued), -1 = not sent (caller retries). */
static int cmd_send(const uint8_t *cmd, size_t len, uint16_t op, int force){
    if(g_rawfd<0) return -1;
    if(g_cmd_dead && !force) return -1;
    if(g_pend_n>=CMD_PEND_MAX) return -1;          /* >=16s of drain already queued: refuse */
    if(write(g_rawfd,cmd,len)!=(ssize_t)len){
        if(errno==EAGAIN||errno==EWOULDBLOCK) cmd_guard_trip("write EAGAIN",op);
        else fprintf(stderr,"[txd] hci cmd 0x%04x write failed: %s\n",op,strerror(errno));
        return -1;
    }
    /* The no-response deadline is fixed at ENQUEUE from the entry's queue
     * position: with N entries already ahead, the kernel needs ~2s each before
     * this one even goes on air. Scaling by the CURRENT depth instead would
     * shrink the allowance as earlier entries complete while the survivor's age
     * keeps growing — the tail of a full burst would false-trip. */
    g_pend[g_pend_n].op=op;
    g_pend[g_pend_n].deadline=now_ms()+6000ull+2000ull*(uint64_t)(g_pend_n+1);
    g_pend_n++;
    return 0;
}

/* Disable sniff/hold/park on the DS5 ACL link (keep role-switch). Measured live
 * 2026-07-02: the stack lets the link fall into SNIFF (interval 124 slots =
 * 77.5 ms) every ~30 s; input collapses to ~13 Hz for ~0.5 s until the app's
 * 500 ms stopSniff poll recovers it — the user-visible input dropouts. Clearing
 * the sniff policy bit makes the LMP layer reject sniff requests from EITHER
 * side, so the mode never changes. Per-packet write on a SOCK_RAW datagram
 * socket is atomic, so racing with main's ACL injects is safe. */
#define OP_WRITE_LINK_POLICY 0x080d
#define LINK_POLICY_ACTIVE   0x0001    /* role switch only; sniff/hold/park off */
static int send_link_policy(uint16_t handle){
    uint8_t cmd[8]={ 0x01 /*HCI_COMMAND_PKT*/,
        OP_WRITE_LINK_POLICY&0xff, OP_WRITE_LINK_POLICY>>8, 4,
        (uint8_t)(handle&0xff), (uint8_t)((handle>>8)&0x0f),
        LINK_POLICY_ACTIVE&0xff, LINK_POLICY_ACTIVE>>8 };
    return cmd_send(cmd,sizeof cmd,OP_WRITE_LINK_POLICY,0);
}

/* BR/EDR scan control (Write_Scan_Enable). Measured live 2026-07-05: the
 * controller's periodic page/inquiry scan blocks the DS5 ACL link for
 * 86-234ms on a ~1.28s grid (EPISODE detector) — audible speaker dropouts and
 * the input hiccups. Scan-off while a template is bound removed ~8x of the
 * blackouts and made input clean in the live A/B. Scan mode 2 (connectable,
 * not discoverable) is restored when the template goes invalid so devices can
 * (re)connect outside sessions.
 *
 * Implemented as a WANT/SENT reconciler instead of scattered direct sends:
 * every state change (bind, invalidate — from ANY thread via g_scan_restore —
 * or a foreign re-enable observed on the monitor) only updates the DESIRED
 * mode; the capture loop converges the actual mode toward it under one shared
 * >=3s limiter. This makes flap storms rate-safe by construction (a swallowed
 * transition is re-sent on the next pass, so the final state is always
 * reached) and keeps the whole command machinery capture-thread-only. */
#define OP_WRITE_SCAN_ENABLE 0x0c1a
#define SCAN_MIN_GAP_MS      3000
static uint8_t  g_scan_want = 0xff;  /* desired mode; 0xff = no opinion yet (pre-first-bind:
                                        never touch the TV's scan state before a session) */
static uint8_t  g_scan_sent = 0xff;  /* mode we last wrote; 0xff = unknown (force re-send) */
static uint64_t g_scan_tx   = 0;     /* last scan write time (the shared limiter) */
static volatile int g_scan_restore = 0; /* main-thread invalidations request a mode-2 restore
                                           here; the capture thread owns the send machinery */
static void scan_reconcile(void){
    if(g_scan_want==0xff || g_scan_want==g_scan_sent) return;
    uint64_t t=now_ms();
    if(g_scan_tx && t-g_scan_tx<SCAN_MIN_GAP_MS) return;
    uint8_t cmd[5]={ 0x01,
        OP_WRITE_SCAN_ENABLE&0xff, OP_WRITE_SCAN_ENABLE>>8, 1, g_scan_want };
    if(cmd_send(cmd,sizeof cmd,OP_WRITE_SCAN_ENABLE,0)==0){
        g_scan_tx=t; g_scan_sent=g_scan_want;
        fprintf(stderr,"[txd] scan_enable=%u (%s)\n",g_scan_want,
                g_scan_want?"restored":"off for session");
    }
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
    if(code==HCI_EV_CMD_COMPLETE && pl>=3){                 /* ncmd,opcode(2),status... */
        uint16_t op=(uint16_t)(p[1]|(p[2]<<8));
        for(int i=0;i<g_pend_n;i++)                         /* pop the oldest matching pend */
            if(g_pend[i].op==op){
                g_pend_n--;
                memmove(&g_pend[i],&g_pend[i+1],(size_t)(g_pend_n-i)*sizeof g_pend[0]);
                break;
            }
        if(g_cmd_dead && g_probe_op && op==g_probe_op){     /* recovery probe answered */
            g_cmd_dead=0; g_probe_op=0; g_pend_n=0;
            fprintf(stderr,"[txd] CMDRECOVER: Command Complete 0x%04x on air -> HCI command path back up\n",op);
        }
        return;
    }
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
                    txwin_pop(cnt);   /* FIFO-approximate the per-type in-flight counts */
                    /* Refresh the stall timestamp ONLY for OUR handle's completions:
                     * a global refresh would let any other device's NOCP chatter
                     * (Magic Remote etc.) suppress the 150ms backstop exactly when
                     * our credits are the ones wedged. */
                    g_last_nocp=now_ms();
                    /* NOCP for the bound handle also proves the LINK is alive:
                     * the controller is completing OUR injections. Without this,
                     * g_last_seen is only refreshed by kernel-path HID writes
                     * (the tmpld seeder) -- if that write blocks >1.5s on the
                     * one-outstanding flow control under full raw-inject load,
                     * the idle backstop misfires mid-stream and the resulting
                     * template-invalidate/rebind cycle stalls injection (an
                     * audible speaker dropout). A real flap stops producing
                     * NOCPs for this handle, and handle-reassignment is caught
                     * by the CONN/DISCONN handlers, so the backstop's purpose
                     * is preserved. */
                    g_last_seen=now_ms();
                }
            }
        }
        pthread_mutex_unlock(&g_lock);
        return;   /* NOCP never affects template validity */
    } else return;
    if(reason){ publish_current(); fprintf(stderr,"[txd] %s -> template INVALID\n",reason); g_scan_want=2; }
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
    uint16_t policy_handle=0xffff;   /* handle the last link-policy write was for */
    for(;;){
        /* Idle backstop: evaluated EVERY wakeup (not only on recv-timeout) so it
         * still fires while other BT devices keep the monitor socket busy. After a
         * flap the DS5 stops emitting HID-output -> g_last_seen ages out -> template
         * invalidated within IDLE_INVALIDATE_MS even if the DISCONN event was lost. */
        int idle_inval=0; int bh=-1;
        pthread_mutex_lock(&g_lock);
        if(g_have && now_ms()-g_last_seen>IDLE_INVALIDATE_MS){ g_have=0; idle_inval=1; }
        if(g_have) bh=g_handle;
        pthread_mutex_unlock(&g_lock);
        if(idle_inval){ publish_current(); fprintf(stderr,"[txd] link idle -> template INVALID\n"); g_scan_want=2; }
        /* Main-thread invalidations (EBADF / foreign-handle caught in inject_one)
         * cannot touch the command machinery (g_pend/scan state is capture-thread-
         * -owned); they raise g_scan_restore instead and the restore lands here.
         * Skipped if a new session already rebound meanwhile — want stays 0. */
        if(g_scan_restore){ g_scan_restore=0; if(bh<0) g_scan_want=2; }
        /* Link-policy reconcile: pin sniff off within ~300ms of a bind (handle
         * change) and refresh every 10s while bound; never more often than every
         * 3s so a flap storm cannot flood the 0.5/s kernel drain (bursts beyond
         * that are additionally absorbed by cmd_send's unacked-queue cap). */
        if(bh>=0){
            uint64_t t=now_ms();
            int need = (policy_handle!=(uint16_t)bh) || (t-last_policy>10000);
            if(need && (!last_policy || t-last_policy>3000) &&
               send_link_policy((uint16_t)bh)==0){ last_policy=t; policy_handle=(uint16_t)bh; }
        } else policy_handle=0xffff;
        /* Converge the actual scan mode toward the desired one (shared limiter). */
        scan_reconcile();
        /* Command health: no ON-AIR Command Complete (monitor-observed) for the
         * OLDEST unacked command by its enqueue-time deadline (6s + 2s per queue
         * position — the kernel drains 1 cmd / 2s in user-channel mode, so a
         * burst legitimately takes that long; a fixed 6s deadline used to
         * false-trip on a mere template-flap burst of 3 commands). Miss = enter
         * the DEAD state before retries fill the sndbuf. */
        if(!g_cmd_dead && g_pend_n>0 && now_ms()>g_pend[0].deadline){
            cmd_guard_trip("no response to",g_pend[0].op);
        }
        /* Recovery probe: DEAD is not terminal. Every 60s send ONE command past
         * the gate — the currently-desired scan mode, so a successful recovery
         * also reconciles scan state. Pre-probe the pend queue holds only dead-era
         * junk (nothing else is sent while dead); drop it so 8 failed probes can
         * never wedge the queue cap and stop probing forever. */
        if(g_cmd_dead && now_ms()-g_cmd_dead_t>60000){
            g_cmd_dead_t=now_ms(); g_pend_n=0;
            uint8_t mode=(g_scan_want!=0xff)?g_scan_want:2;
            uint8_t cmd[5]={ 0x01,
                OP_WRITE_SCAN_ENABLE&0xff, OP_WRITE_SCAN_ENABLE>>8, 1, mode };
            if(cmd_send(cmd,sizeof cmd,OP_WRITE_SCAN_ENABLE,1)==0){
                g_probe_op=OP_WRITE_SCAN_ENABLE;
                g_scan_tx=now_ms(); g_scan_sent=mode;
            }
        }

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
        if(h->opcode==MON_COMMAND_PKT){
            /* Event-driven scan-off: the LG stack re-enables page/inquiry scan on
             * its own (measured: scan blackouts leak back within seconds). Instead
             * of a blind 1Hz reassert we watch the command stream: a foreign
             * Write_Scan_Enable with mode!=0 while we want it off just marks our
             * sent-state unknown — the reconciler re-sends mode 0 under the shared
             * >=3s limiter on the next pass. Zero commands from us unless someone
             * actually flips scan back on; our own writes while want==0 are mode=0
             * and can't retrigger (and our mode-2 restores run while want==2).
             * Payload: opcode(2LE), plen(1), params. */
            if(dl>=4 && (uint16_t)(d[0]|(d[1]<<8))==OP_WRITE_SCAN_ENABLE && d[3]!=0 &&
               g_scan_want==0){
                if(g_scan_sent==0) g_scan_ctr++;   /* count fights, not every burst packet */
                g_scan_sent=0xff;
            }
            continue;
        }
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
                g_outstanding=0; g_last_nocp=now_ms(); txwin_reset();   /* fresh link =
                     fresh credit window: never inherit phantom credits (or per-type
                     counts) from a flapped connection whose NOCPs were lost (they
                     can never be drained once g_have dropped) */
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
            /* Radio hygiene via the reconcilers (next loop pass, <=300ms): the
             * link-policy pin fires on the handle change, scan-off on want=0.
             * Direct sends here were unthrottled — a flap storm (bind/invalidate
             * cycling) could beat the 0.5/s kernel drain and overflow the sndbuf. */
            g_scan_want=0;
            policy_handle=0xffff;
            fprintf(stderr,"[txd] template handle=0x%03x CID=0x%04x nonce=%u bound (sniff-off+noscan pending)\n",hh,cid,nonce);
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

    /* Seed the stall backstop BEFORE the worker threads exist: g_last_nocp is a
     * 64-bit field guarded by g_lock, and an unlocked store after thread creation
     * could tear against a capture-thread writer on 32-bit ARM. Pre-thread, plain
     * store is fine and output still can't wedge before the first NOCP. */
    g_last_nocp=now_ms();

    pthread_t cap; pthread_create(&cap,NULL,capture_thread,NULL);
    pthread_t brk; pthread_create(&brk,NULL,broker_thread,(void*)hidfd_path);
    fprintf(stderr,"[txd] forwarder up (cmdguard): unix=%s tmpl=%s hidfd=%s\n",sock_path,g_tmpl_path,hidfd_path);

    /* Event loop: wait on forwarded reports (ufd) AND mount-table changes (minfo)
     * at once. Pure poll(-1) in steady state; a 500ms tick engages only while a
     * rebind is pending or the mount watch is unavailable (degrade to polling). */
    int minfo=open_mount_watch();   /* self-heal ds5_acl.sock across jail-tmp remounts */
    uint8_t rep[ACL_MAX_REPORT];   /* inject framing now lives in inject_one() */
    long injected=0, dropped=0, paced=0; uint64_t last_log=now_ms();
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
        /* Radio-episode detector: outstanding credits with no NOCP for >80ms
         * means the controller is not getting airtime (WiFi-scan blackout,
         * interference burst) -- the invisible cause of "late but not lost"
         * audio/input. Timestamped so felt dropouts can be correlated. */
        uint16_t snap_nonce=0;   /* template generation this wakeup (stamps FIFO entries) */
        {
            static uint64_t ep_start=0, gap_hi=0;
            uint64_t nowm=now_ms();
            pthread_mutex_lock(&g_lock);
            int qd=g_outstanding; uint64_t ln=g_last_nocp; int hv=g_have;
            snap_nonce=g_nonce;
            pthread_mutex_unlock(&g_lock);
            /* Stale-backlog gate: a rebind bumps the nonce, so audio still held
             * from the previous binding must be dropped, not played into the new
             * session (drain_fifo also clears on the no-template path, but that
             * never runs when the invalidate->rebind happens between wakeups). */
            if(g_fifo_count>0 && g_fifo_gen!=snap_nonce) fifo_clear();
            if(hv && qd>0 && ln && nowm-ln>80){
                if(!ep_start){ ep_start=nowm; fprintf(stderr,"[txd] EPISODE start t=%llu q=%d\n",(unsigned long long)nowm,qd); }
            } else if(ep_start){
                fprintf(stderr,"[txd] EPISODE end t=%llu dur=%dms\n",(unsigned long long)nowm,(int)(nowm-ep_start));
                ep_start=0;
            }
            /* Sub-episode gap histogram: the EPISODE lines only show >80ms, but a
             * 56ms DS5 buffer already underruns on 50-80ms NOCP gaps (the felt
             * "minimal dropouts" tail at low slider values, 2026-07-05). Track the
             * high-watermark of each credit-starved stretch and bucket it when a
             * NOCP resets the gap. Loop wakes ~94/s in-session -> ~10ms resolution. */
            uint64_t cur=(hv && qd>0 && ln)?(nowm-ln):0;
            if(cur>gap_hi) gap_hi=cur;
            else if(gap_hi){
                if(gap_hi>=80) g_gap80++;
                else if(gap_hi>=50) g_gap50++;
                else if(gap_hi>=30) g_gap30++;
                gap_hi=0;
            }
        }
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

                int need_inval=0; const char *reason=NULL;
                /* Read the tunables BEFORE taking g_lock: they fopen /tmp ~1/s and
                 * g_lock must never wrap filesystem I/O (see the invariant above
                 * g_lock). Per-report constants. inject_one() takes/releases g_lock
                 * itself per frame, keeping each critical section as short as the
                 * legacy inline path. */
                int maxq=inject_maxq();
                int fdepth=inject_fifo();
                int r;

                if(rep[0]!=0x36){
                    /* Rumble FIRST, before the audio backlog: it is an independent
                     * stream (its ordering vs audio does not matter), and draining
                     * held audio ahead of it would hand every freed credit to audio
                     * within the same wakeup — starvation by ordering, on top of
                     * the type-aware window in inject_one(). Rumble itself stays
                     * latest-wins on a full window: a stale rumble is wrong. */
                    r=inject_one(rawfd,rep,(int)n,maxq,&reason);
                    if(r==1) injected++;
                    else if(r==-1) need_inval=1;
                    else if(r==0) paced++;         /* latest-wins drop */
                    else dropped++;                /* r==-2: no live template */
                    if(!need_inval) injected+=drain_fifo(rawfd,maxq,&need_inval,&reason);
                } else {
                    /* Audio: strict FIFO order — backlog first, then the fresh
                     * frame. On a full window with the FIFO enabled the fresh frame
                     * is HELD (few-ms delay, drained on the next arrival) rather
                     * than punching a ~10ms hole; FIFO-off stays latest-wins. */
                    injected+=drain_fifo(rawfd,maxq,&need_inval,&reason);
                    if(need_inval){
                        dropped++;                 /* template just died; fresh frame is moot */
                    } else {
                        r=inject_one(rawfd,rep,(int)n,maxq,&reason);
                        if(r==1) injected++;
                        else if(r==-1){ need_inval=1; fifo_clear(); }
                        else if(r==0){
                            if(fdepth>0 && (int)n<=FIFO_ENTRY_MAX){
                                /* Evict-to-fit: fdepth can be LOWERED at runtime; a
                                 * single-evict would balance every insert and keep
                                 * the count at the old high-water forever under
                                 * congestion, voiding the latency bound. */
                                while(g_fifo_count>=fdepth){ g_fifo_head=(g_fifo_head+1)%FIFO_MAX; g_fifo_count--; dropped++; }
                                int tail=(g_fifo_head+g_fifo_count)%FIFO_MAX;
                                memcpy(g_fifo[tail].buf,rep,(size_t)n); g_fifo[tail].len=(int)n; g_fifo_count++;
                                g_fifo_gen=snap_nonce;   /* held under THIS binding */
                            } else {
                                paced++;           /* legacy latest-wins drop */
                            }
                        }
                        else dropped++;            /* r==-2: no live template */
                    }
                }
                if(need_inval){
                    publish_current(); fprintf(stderr,"[txd] %s\n",reason);
                    /* Scan restore for MAIN-thread invalidations: this thread must
                     * not touch the capture-owned command machinery, so it only
                     * raises the flag; the capture loop sends the mode-2 restore
                     * (and ignores it if a new session rebinds first). Without
                     * this, an EBADF/foreign-handle invalidation left page scan
                     * off until the LG stack happened to re-enable it. */
                    g_scan_restore=1;
                }
            }
        }
        if(now_ms()-last_log>10000){ fprintf(stderr,"[txd] inj=%ld drop=%ld backoff=%ld q=%d/%d rq=%d fifo=%d/%d scanctr=%ld gaps=%ld/%ld/%ld pend=%d%s\n",injected,dropped,paced,g_outstanding,inject_maxq(),g_rumble_fly,g_fifo_count,inject_fifo(),g_scan_ctr,g_gap30,g_gap50,g_gap80,g_pend_n,g_cmd_dead?" CMDDEAD":""); last_log=now_ms(); }
    }
    return 0;
}
