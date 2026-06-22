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
#include <time.h>

#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH 31
#endif
#define BTPROTO_HCI         1
#define HCI_CHANNEL_RAW     0
#define HCI_CHANNEL_MONITOR 2
#define HCI_DEV_NONE        0xffff
#define HCI_ACLDATA_PKT     0x02
#define MON_ACL_TX_PKT      4
#define ACL_MAX_REPORT      4096

struct sockaddr_hci { unsigned short hci_family, hci_dev, hci_channel; };
struct hci_mon_hdr  { uint16_t opcode, index, len; } __attribute__((packed));

static int injectable(uint8_t id){ return id==0x31 || id==0x32 || id==0x36; }
static uint64_t now_ms(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return (uint64_t)ts.tv_sec*1000ull+ts.tv_nsec/1000000ull; }

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t  g_hdr[8];
static int      g_have = 0;
static uint16_t g_nonce = 0;
static uint64_t g_last_seen = 0;
static const char *g_tmpl_path;

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
 * top mount whenever the path stops resolving to a socket. */

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
 * Non-blocking so the poll-driven recv drain terminates on EAGAIN. -1 on failure
 * (e.g. parent dir momentarily absent mid-relaunch — caller retries). */
static int bind_unix_dgram(const char *path){
    int fd=socket(AF_UNIX,SOCK_DGRAM,0);
    if(fd<0) return -1;
    struct sockaddr_un ua; memset(&ua,0,sizeof ua);
    ua.sun_family=AF_UNIX; snprintf(ua.sun_path,sizeof ua.sun_path,"%s",path);
    unlink(path);
    if(bind(fd,(struct sockaddr*)&ua,sizeof ua)<0){ close(fd); return -1; }
    chmod(path,0666);   /* the jailed uid (6261) must be able to sendto it */
    int rcv=1<<20; setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&rcv,sizeof rcv);
    int fl=fcntl(fd,F_GETFL,0); if(fl>=0) fcntl(fd,F_SETFL,fl|O_NONBLOCK);
    return fd;
}

/* Create + bind + listen a fresh AF_UNIX SOCK_STREAM node at path (the broker
 * channel). -1 on failure. */
static int bind_unix_stream(const char *path){
    int fd=socket(AF_UNIX,SOCK_STREAM,0);
    if(fd<0) return -1;
    struct sockaddr_un ba; memset(&ba,0,sizeof ba);
    ba.sun_family=AF_UNIX; snprintf(ba.sun_path,sizeof ba.sun_path,"%s",path);
    unlink(path);
    if(bind(fd,(struct sockaddr*)&ba,sizeof ba)<0){ close(fd); return -1; }
    chmod(path,0666);   /* the jailed uid (6261) must be able to connect */
    if(listen(fd,8)<0){ close(fd); return -1; }
    return fd;
}

/* ---- HID-FD broker ------------------------------------------------------- *
 * Hand the jailed app an open fd for a /dev/hidrawN node its static jail /dev
 * never received. One request per connection: the app writes the device path it
 * wants (newline-terminated); we validate it is a real hidraw node, open it, and
 * reply with a 1-byte status ('O'=ok / 'E'=error) plus — on success — the open fd
 * as SCM_RIGHTS ancillary data. */

/* Defence in depth: only ever open /dev/hidraw<digits>, never an arbitrary path
 * the app might name (it is our app, but the broker runs as root). */
static int valid_hidraw_path(const char *p){
    if(strncmp(p,"/dev/hidraw",11)!=0) return 0;
    const char *d=p+11;
    if(!*d) return 0;
    for(; *d; ++d) if(*d<'0'||*d>'9') return 0;
    return 1;
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
    const char *path=(const char*)arg;
    int sfd=bind_unix_stream(path);
    if(sfd<0){ perror("[txd] bind broker"); return NULL; }
    fprintf(stderr,"[txd] hid-fd broker up: %s\n",path);
    int minfo=open_mount_watch();   /* self-heal the broker node across jail-tmp remounts */
    for(;;){
        /* Steady state: block on accept-ready + mount changes. The short timeout
         * only engages while a rebind is pending (node gone, dir not yet ready). */
        struct pollfd pf[2]={{sfd,POLLIN,0},{minfo,POLLPRI,0}};
        int to=(sfd<0)?500:-1;
        int pr=poll(pf,(minfo>=0)?2:1,to);
        if(pr<0){ if(errno==EINTR) continue; usleep(5000); continue; }
        if((pr==0 || (pf[1].revents)) ){
            if(pf[1].revents) rearm_mount_watch(minfo);
            if(!node_alive(path)){
                if(sfd>=0){ close(sfd); sfd=-1; }
                int ns=bind_unix_stream(path);
                if(ns>=0){ sfd=ns; fprintf(stderr,"[txd] jail-tmp remount -> rebound %s\n",path); }
            }
            if(!(pf[0].revents&POLLIN)) continue;
        }
        if(sfd<0 || !(pf[0].revents&POLLIN)) continue;
        int conn=accept(sfd,NULL,NULL);
        if(conn<0){ if(errno==EINTR) continue; usleep(5000); continue; }
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
        }
        if(hfd>=0){
            send_fd(conn,hfd,'O');
            fprintf(stderr,"[txd] broker handed fd for %s\n",req);
            close(hfd);   /* app now holds its own ref via SCM_RIGHTS */
        } else {
            send_fd(conn,-1,'E');
            fprintf(stderr,"[txd] broker open failed for '%s' errno=%d\n",req,errno);
        }
        close(conn);
    }
}

/* Capture thread: watch HCI_CHANNEL_MONITOR (root) for our outgoing HID-output
 * and keep the current connection's handle+CID published. */
static void *capture_thread(void *arg){
    (void)arg;
    int mfd=socket(AF_BLUETOOTH,SOCK_RAW,BTPROTO_HCI);
    if(mfd<0){ perror("[txd] socket monitor"); return NULL; }
    struct sockaddr_hci ma; memset(&ma,0,sizeof ma);
    ma.hci_family=AF_BLUETOOTH; ma.hci_dev=HCI_DEV_NONE; ma.hci_channel=HCI_CHANNEL_MONITOR;
    if(bind(mfd,(struct sockaddr*)&ma,sizeof ma)<0){ perror("[txd] bind monitor"); close(mfd); return NULL; }
    struct timeval tv={.tv_sec=0,.tv_usec=300000}; setsockopt(mfd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    uint8_t buf[2048];
    for(;;){
        int r=(int)recv(mfd,buf,sizeof buf,0);
        if(r<0){
            pthread_mutex_lock(&g_lock);
            if(g_have && now_ms()-g_last_seen>1500){ g_have=0; publish(0,g_nonce,NULL);
                fprintf(stderr,"[txd] link idle -> template INVALID\n"); }
            pthread_mutex_unlock(&g_lock);
            continue;
        }
        if(r<(int)sizeof(struct hci_mon_hdr)) continue;
        struct hci_mon_hdr*h=(struct hci_mon_hdr*)buf;
        if(h->opcode!=MON_ACL_TX_PKT) continue;
        uint8_t*d=buf+sizeof(struct hci_mon_hdr); int dl=h->len;
        if(r<(int)(sizeof(struct hci_mon_hdr)+dl)) continue;
        if(dl<10) continue;
        uint8_t pb=(uint8_t)((d[1]>>4)&0x3); if(pb==1) continue;
        if(d[8]!=0xA2 || !injectable(d[9])) continue;
        uint16_t acl_len=(uint16_t)(d[2]|(d[3]<<8)), l2_len=(uint16_t)(d[4]|(d[5]<<8));
        if(acl_len!=(uint16_t)(dl-4)) continue;
        if(l2_len !=(uint16_t)(acl_len-4)) continue;
        pthread_mutex_lock(&g_lock);
        g_last_seen=now_ms();
        /* Only handle (d[0..1]) + CID (d[6..7]) are connection-constant; lengths
         * (d[2..5]) vary per report id and are recomputed at inject. */
        if(!g_have || g_hdr[0]!=d[0]||g_hdr[1]!=d[1]||g_hdr[6]!=d[6]||g_hdr[7]!=d[7]){
            memcpy(g_hdr,d,8); g_have=1; g_nonce++; publish(1,g_nonce,g_hdr);
            unsigned hnd=(unsigned)((d[0]|(d[1]<<8))&0x0fff), cid=(unsigned)(d[6]|(d[7]<<8));
            fprintf(stderr,"[txd] template handle=0x%03x CID=0x%04x nonce=%u\n",hnd,cid,g_nonce);
        }
        pthread_mutex_unlock(&g_lock);
    }
}

int main(int argc,char**argv){
    const char *sock_path = argc>1?argv[1]:"/var/palm/jail/com.aurora.gamestream/tmp/ds5_acl.sock";
    g_tmpl_path           = argc>2?argv[2]:"/var/palm/jail/com.aurora.gamestream/tmp/ds5_acl_tmpl";
    const char *hidfd_path= argc>3?argv[3]:"/var/palm/jail/com.aurora.gamestream/tmp/ds5_hidfd.sock";

    struct sched_param sp; memset(&sp,0,sizeof sp); sp.sched_priority=14;
    sched_setscheduler(0,SCHED_FIFO,&sp);

    publish(0,0,NULL);   /* start INVALID so a stale boot file can't mislead the app */

    /* Root HCI raw socket for injection (write is permitted as root). */
    int rawfd=socket(AF_BLUETOOTH,SOCK_RAW,BTPROTO_HCI);
    if(rawfd<0){ perror("[txd] socket raw"); return 1; }
    struct sockaddr_hci ra; memset(&ra,0,sizeof ra);
    ra.hci_family=AF_BLUETOOTH; ra.hci_dev=0; ra.hci_channel=HCI_CHANNEL_RAW;
    if(bind(rawfd,(struct sockaddr*)&ra,sizeof ra)<0){ perror("[txd] bind raw"); return 1; }
    int fl=fcntl(rawfd,F_GETFL,0); if(fl>=0) fcntl(rawfd,F_SETFL,fl|O_NONBLOCK);

    /* AF_UNIX datagram socket the jailed app sends reports to (non-blocking, 1MB
     * recv buffer — see bind_unix_dgram). Self-healed across jail-tmp remounts below. */
    int ufd=bind_unix_dgram(sock_path);
    if(ufd<0){ perror("[txd] bind unix"); return 1; }

    pthread_t cap; pthread_create(&cap,NULL,capture_thread,NULL);
    pthread_t brk; pthread_create(&brk,NULL,broker_thread,(void*)hidfd_path);
    fprintf(stderr,"[txd] forwarder up: unix=%s tmpl=%s hidfd=%s\n",sock_path,g_tmpl_path,hidfd_path);

    /* Event loop: wait on forwarded reports (ufd) AND mount-table changes (minfo)
     * at once. Pure poll(-1) in steady state — it sleeps until a report arrives or
     * a mount/unmount happens; the 500ms timeout only engages while a rebind is
     * pending (path stale, jail tmp not yet ready). */
    int minfo=open_mount_watch();   /* self-heal ds5_acl.sock across jail-tmp remounts */
    uint8_t rep[ACL_MAX_REPORT], frame[1+8+1+ACL_MAX_REPORT];
    long injected=0, dropped=0; uint64_t last_log=now_ms();
    for(;;){
        struct pollfd pfd[2]={{ufd,POLLIN,0},{minfo,POLLPRI,0}};
        int nf=(minfo>=0)?2:1;
        int to=(ufd<0)?500:-1;
        int pr=poll(pfd,nf,to);
        if(pr<0){ if(errno==EINTR) continue; usleep(2000); continue; }

        /* Mount table changed (or retry tick while rebinding): if our node's path
         * stopped resolving to a socket, Aurora remounted its tmp under us — bind a
         * fresh node into the current top mount and re-publish readiness there. */
        if(pr==0 || pfd[1].revents){
            if(pfd[1].revents) rearm_mount_watch(minfo);
            if(!node_alive(sock_path)){
                if(ufd>=0){ close(ufd); ufd=-1; }
                int nu=bind_unix_dgram(sock_path);
                if(nu>=0){
                    ufd=nu;
                    uint8_t hsnap[8]; int hv; uint16_t nn;
                    pthread_mutex_lock(&g_lock); hv=g_have; memcpy(hsnap,g_hdr,8); nn=g_nonce; pthread_mutex_unlock(&g_lock);
                    if(hv) publish(1,nn,hsnap); else publish(0,nn,NULL);
                    fprintf(stderr,"[txd] jail-tmp remount -> rebound ds5_acl.sock + re-published\n");
                }
            }
        }

        /* Drain all reports queued on the (non-blocking) report socket. */
        if(ufd>=0 && (pfd[0].revents&POLLIN)){
            for(;;){
                ssize_t n=recv(ufd,rep,sizeof rep,0);
                if(n<0){ if(errno==EINTR) continue; break; }   /* EAGAIN -> drained */
                if(n==0) break;
                uint8_t hdr[8]; int have;
                pthread_mutex_lock(&g_lock); have=g_have; memcpy(hdr,g_hdr,8); pthread_mutex_unlock(&g_lock);
                if(!have){ dropped++; continue; }   /* no template yet: app still seeding via hidraw */
                uint16_t l2=(uint16_t)(1+n), acl=(uint16_t)(4+l2);
                frame[0]=HCI_ACLDATA_PKT; memcpy(frame+1,hdr,8);
                frame[3]=(uint8_t)(acl&0xff); frame[4]=(uint8_t)(acl>>8);
                frame[5]=(uint8_t)(l2&0xff);  frame[6]=(uint8_t)(l2>>8);
                frame[9]=0xA2; memcpy(frame+10,rep,n);
                ssize_t wr=write(rawfd,frame,10+n);
                if(wr==(ssize_t)(10+n)) injected++;
                else { dropped++;
                    if(wr<0 && errno==EBADF){   /* stale handle (reconnect): force the app to reseed */
                        pthread_mutex_lock(&g_lock); g_have=0; publish(0,g_nonce,NULL); pthread_mutex_unlock(&g_lock);
                        fprintf(stderr,"[txd] inject EBADF -> template INVALID (reconnect)\n");
                    }
                }
            }
        }
        if(now_ms()-last_log>10000){ fprintf(stderr,"[txd] inj=%ld drop=%ld\n",injected,dropped); last_log=now_ms(); }
    }
    return 0;
}
