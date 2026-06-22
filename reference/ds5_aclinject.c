// ds5_aclinject.c -- FEASIBILITY: bypass webOS' one-outstanding HID-output flow
// control by injecting the DS5 0x36 report as RAW HCI ACL straight to the
// controller, instead of writing /dev/hidraw3 (which routes through
// webos-bluetooth-service and gets paced to ~62/s).
//
// NON-INVASIVE + reversible: opens a second raw HCI socket and sends ACL data;
// stops -> nothing persists. Does NOT modify any binary.
//
// Method:
//   Phase 1 (capture): listen on the MONITOR channel for ONE real on-air DS5
//     0x36 output frame (run ds5_spk_flex briefly to seed it). Grab the exact
//     ACL+L2CAP header (8B: handle/flags/len + L2CAP len/CID) and the 398-byte
//     0x36 report that follows the 0xA2 HID prefix. Verbatim framing = the DS5
//     accepts it identically.
//   Phase 2 (inject): build HCI ACL packets [0x02][acl_hdr 8][0xA2][report 398]
//     and write() them to the raw HCI socket at the requested rate, re-stamping
//     seq (report[1]=seq<<4), packetCounter (report[10]) and CRC32 each time so
//     the DS5 sees a valid monotonic stream.
//
// Measure the resulting on-air cadence with ds5_hcimon / ds5_aclre in parallel.
//   usage: ds5_aclinject <rate_per_s> <seconds> [handle_hex=32] [cap_timeout_s=4]
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <time.h>
#include <poll.h>

#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH 31
#endif
#define BTPROTO_HCI 1
#define HCI_CHANNEL_RAW     0
#define HCI_CHANNEL_MONITOR 2
#define HCI_DEV_NONE 0xffff
#define HCI_ACLDATA_PKT 0x02

struct sockaddr_hci { unsigned short hci_family, hci_dev, hci_channel; };
struct hci_mon_hdr  { uint16_t opcode, index, len; } __attribute__((packed));
#define MON_ACL_TX_PKT  4

#define REPORT_SIZE 398

// DS5 output-report CRC32 (seed encodes the 0xA2 HID prefix already), verbatim
// from ds5_av_play.c (on-device verified).
static uint32_t crc32_ds(const uint8_t *data, size_t size) {
    uint32_t crc = ~0xEADA2D49u;
    while (size--) { crc ^= *data++;
        for (int i = 0; i < 8; i++) crc = (crc >> 1) ^ (0xEDB88320u & -(crc & 1)); }
    return ~crc;
}
static double now_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
    return t.tv_sec*1000.0 + t.tv_nsec/1e6; }

int main(int argc, char **argv){
    if(argc<3){ fprintf(stderr,"usage: %s <rate_per_s> <seconds> [handle_hex=32] [cap_timeout_s=4]\n",argv[0]); return 2; }
    int    rate = atoi(argv[1]);
    double dur  = atof(argv[2]);
    uint16_t want_h = (argc>3)?(uint16_t)strtol(argv[3],0,16):0x032;
    double cap_to = (argc>4)?atof(argv[4]):4.0;
    if(rate<1) rate=1;

    // ---- Phase 1: capture one real on-air 0x36 frame as a template ----
    int mfd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if(mfd<0){ perror("socket mon"); return 1; }
    struct sockaddr_hci ma; memset(&ma,0,sizeof ma);
    ma.hci_family=AF_BLUETOOTH; ma.hci_dev=HCI_DEV_NONE; ma.hci_channel=HCI_CHANNEL_MONITOR;
    if(bind(mfd,(struct sockaddr*)&ma,sizeof ma)<0){ perror("bind mon"); return 2; }

    uint8_t acl_hdr[8]; uint8_t report[REPORT_SIZE]; int have=0;
    fprintf(stderr,"[cap] waiting up to %.0fs for a real 0x36 frame on handle 0x%03x (seed it with ds5_spk_flex)...\n", cap_to, want_h);
    double t0=now_ms();
    uint8_t buf[4096];
    while((now_ms()-t0)/1000.0 < cap_to && !have){
        struct pollfd p={mfd,POLLIN,0};
        if(poll(&p,1,300)<=0) continue;
        int n=read(mfd,buf,sizeof buf);
        if(n<(int)sizeof(struct hci_mon_hdr)) continue;
        struct hci_mon_hdr *h=(struct hci_mon_hdr*)buf;
        uint8_t *d=buf+sizeof(struct hci_mon_hdr); int dl=h->len;
        if(h->opcode!=MON_ACL_TX_PKT || dl < 8+1+REPORT_SIZE) continue;
        uint16_t hnd=(d[0]|(d[1]<<8))&0x0FFF; uint8_t pb=(d[1]>>4)&0x3;
        if(hnd!=want_h || pb==1) continue;
        if(d[8]!=0xA2 || d[9]!=0x36) continue;          // HID output prefix + report id 0x36
        memcpy(acl_hdr, d, 8);
        memcpy(report, d+9, REPORT_SIZE);
        have=1;
        uint16_t cid=d[6]|(d[7]<<8);
        fprintf(stderr,"[cap] template captured: handle=0x%03x CID=0x%04x acl_len=%u L2CAP_len=%u\n",
                hnd, cid, d[2]|(d[3]<<8), d[4]|(d[5]<<8));
    }
    if(!have){ fprintf(stderr,"[cap] NO template captured (no 0x36 on air). Run ds5_spk_flex during phase 1.\n"); close(mfd); return 3; }

    // ---- Phase 2: inject re-stamped copies as raw HCI ACL ----
    int rfd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if(rfd<0){ perror("socket raw"); close(mfd); return 1; }
    struct sockaddr_hci ra; memset(&ra,0,sizeof ra);
    ra.hci_family=AF_BLUETOOTH; ra.hci_dev=0; ra.hci_channel=HCI_CHANNEL_RAW;
    if(bind(rfd,(struct sockaddr*)&ra,sizeof ra)<0){ perror("bind raw"); close(mfd); close(rfd); return 1; }

    // HCI ACL frame = [0x02][handle/flags 2][acl_len 2][l2cap_len 2][cid 2][0xA2][report 398]
    // acl_hdr(8) = handle/flags + acl_len + l2cap_len + cid (verbatim from the captured
    // on-air frame); the 0xA2 HID prefix and the re-stamped report follow.
    uint8_t frame[1+8+1+REPORT_SIZE];
    frame[0]=HCI_ACLDATA_PKT;
    memcpy(frame+1, acl_hdr, 8);
    frame[9]=0xA2;
    int framelen = 1+8+1+REPORT_SIZE;                   // 408

    long period_ns = 1000000000L / rate;
    struct timespec next; clock_gettime(CLOCK_MONOTONIC,&next);
    long sent=0, werr=0; uint8_t seq=0, pktctr=0;
    fprintf(stderr,"[inj] injecting %d/s for %.1fs via raw HCI ACL (framelen=%d)...\n", rate, dur, framelen);
    double ti=now_ms();
    while((now_ms()-ti)/1000.0 < dur){
        report[1]  = (uint8_t)(seq<<4); seq=(seq+1)&0x0F;
        report[10] = pktctr++;
        uint32_t crc = crc32_ds(report, REPORT_SIZE-4);
        report[394]=crc&0xFF; report[395]=(crc>>8)&0xFF; report[396]=(crc>>16)&0xFF; report[397]=(crc>>24)&0xFF;
        memcpy(frame+10, report, REPORT_SIZE);
        if(write(rfd, frame, framelen) < 0){ werr++; if(werr<=3) fprintf(stderr,"[inj] write: %s\n", strerror(errno)); }
        else sent++;
        next.tv_nsec += period_ns;
        while(next.tv_nsec>=1000000000L){ next.tv_nsec-=1000000000L; next.tv_sec++; }
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL);
    }
    double el=(now_ms()-ti)/1000.0;
    fprintf(stderr,"[inj] done: sent=%ld write_err=%ld in %.1fs (%.0f/s attempted)\n", sent, werr, el, sent/el);
    close(rfd); close(mfd); return 0;
}
