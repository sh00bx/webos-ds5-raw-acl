// ds5_aclre.c -- NON-INVASIVE RE of the webOS BT output path, for direct-ACL
// injection feasibility. Two questions answered, zero modification:
//   (1) How many ACL buffers does the controller have? (= how deep we can pipeline
//       past webOS' one-outstanding flow control). Read_Buffer_Size(0x1005) sent on
//       a RAW HCI socket; response read on the MONITOR channel (webOS' own stack
//       eats command-complete on the raw socket, but the monitor mirrors it).
//   (2) The EXACT on-air framing of one of our 0x36 output reports: ACL header
//       (handle+PB/BC flags) + L2CAP length + CID + first HID bytes (0xA2 prefix +
//       report id). We must replicate this verbatim to inject.
// Run this while a 0x36 report stream is on air (e.g. host test tone -> ds5_av_play).
//   usage: ds5_aclre [seconds=6] [handle_hex=32]
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
#define HCI_COMMAND_PKT 0x01

struct sockaddr_hci { unsigned short hci_family, hci_dev, hci_channel; };
struct hci_mon_hdr  { uint16_t opcode, index, len; } __attribute__((packed));

#define MON_COMMAND_PKT 2
#define MON_EVENT_PKT   3
#define MON_ACL_TX_PKT  4
#define MON_ACL_RX_PKT  5

#define OP_READ_BUFSIZE    0x1005
#define OP_LE_READ_BUFSIZE 0x2002

static double now_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
    return t.tv_sec*1000.0 + t.tv_nsec/1e6; }

static void dumphex(const char*tag, const uint8_t*p, int n){
    fprintf(stderr,"%s [%dB]:", tag, n);
    for(int i=0;i<n && i<40;i++) fprintf(stderr," %02x", p[i]);
    fprintf(stderr,"\n");
}

int main(int argc,char**argv){
    double dur = (argc>1)?atof(argv[1]):6.0;
    uint16_t ds5h = (argc>2)?(uint16_t)strtol(argv[2],0,16):0x032;

    // --- raw socket: send Read_Buffer_Size + LE_Read_Buffer_Size ---
    int rfd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if(rfd<0){ perror("socket raw"); return 1; }
    struct sockaddr_hci ra; memset(&ra,0,sizeof ra);
    ra.hci_family=AF_BLUETOOTH; ra.hci_dev=0; ra.hci_channel=HCI_CHANNEL_RAW;
    if(bind(rfd,(struct sockaddr*)&ra,sizeof ra)<0){ perror("bind raw"); /* keep going for monitor */ }

    // --- monitor socket: read everything ---
    int mfd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if(mfd<0){ perror("socket mon"); return 1; }
    struct sockaddr_hci ma; memset(&ma,0,sizeof ma);
    ma.hci_family=AF_BLUETOOTH; ma.hci_dev=HCI_DEV_NONE; ma.hci_channel=HCI_CHANNEL_MONITOR;
    if(bind(mfd,(struct sockaddr*)&ma,sizeof ma)<0){ perror("bind mon"); return 2; }

    // fire the two buffer-size queries
    uint8_t c1[4]={HCI_COMMAND_PKT, OP_READ_BUFSIZE&0xff, OP_READ_BUFSIZE>>8, 0};
    uint8_t c2[4]={HCI_COMMAND_PKT, OP_LE_READ_BUFSIZE&0xff, OP_LE_READ_BUFSIZE>>8, 0};
    if(write(rfd,c1,4)<0) fprintf(stderr,"write Read_Buffer_Size: %s\n", strerror(errno));
    if(write(rfd,c2,4)<0) fprintf(stderr,"write LE_Read_Buffer_Size: %s\n", strerror(errno));

    fprintf(stderr,"RE monitor %.0fs, DS5 handle=0x%03x ...\n", dur, ds5h);
    uint8_t buf[4096];
    double t0=now_ms(), el=0;
    int tx_dumped=0;
    long tx_start=0;
    while(el<dur){
        struct pollfd p={mfd,POLLIN,0};
        if(poll(&p,1,500)<=0){ el=(now_ms()-t0)/1000.0; continue; }
        int n=read(mfd,buf,sizeof buf); el=(now_ms()-t0)/1000.0;
        if(n<(int)sizeof(struct hci_mon_hdr)) continue;
        struct hci_mon_hdr *h=(struct hci_mon_hdr*)buf;
        uint8_t *d=buf+sizeof(struct hci_mon_hdr); int dl=h->len;

        if(h->opcode==MON_EVENT_PKT && dl>=5 && d[0]==0x0E){ // command complete
            // event: [0]=0x0E [1]=plen [2]=num_cmd [3..4]=opcode [5]=status [6..]=ret
            uint16_t op = d[3]|(d[4]<<8);
            if(op==OP_READ_BUFSIZE || op==OP_LE_READ_BUFSIZE)
                fprintf(stderr,"    [cmd-complete op=0x%04x status=0x%02x dl=%d]\n", op, d[5], dl);
            if(op==OP_READ_BUFSIZE && dl>=11){
                uint16_t aclmtu = d[6]|(d[7]<<8);
                uint16_t aclcnt = d[9]|(d[10]<<8);
                fprintf(stderr,">>> Read_Buffer_Size: status=0x%02x  ACL_MTU=%u  TOTAL_ACL_BUFFERS=%u\n",
                        d[5], aclmtu, aclcnt);
            } else if(op==OP_LE_READ_BUFSIZE && dl>=9){
                uint16_t lemtu = d[6]|(d[7]<<8); uint8_t lecnt = d[8];
                fprintf(stderr,">>> LE_Read_Buffer_Size: status=0x%02x  LE_MTU=%u  LE_BUFFERS=%u\n",
                        d[5], lemtu, lecnt);
            }
        }
        else if(h->opcode==MON_ACL_TX_PKT && dl>=8){
            uint16_t hnd=(d[0]|(d[1]<<8))&0x0FFF; uint8_t pb=(d[1]>>4)&0x3;
            int match = (ds5h==0 || ds5h==0xfff) ? 1 : (hnd==ds5h);
            if(match && pb!=1){
                tx_start++;
                uint16_t acllen=d[2]|(d[3]<<8);
                // Only dump the interesting (large = our 0x36) frames, up to 8.
                if(tx_dumped<8 && acllen>=64){
                    uint16_t l2len =d[4]|(d[5]<<8);
                    uint16_t cid   =d[6]|(d[7]<<8);
                    fprintf(stderr,"--- ACL TX #%d: handle=0x%03x pb=%u bc=%u acl_len=%u L2CAP_len=%u CID=0x%04x\n",
                            tx_dumped, hnd, pb, (d[1]>>6)&0x3, acllen, l2len, cid);
                    dumphex("    raw", d, dl);   // full frame head: ACL hdr + L2CAP hdr + HID start
                    tx_dumped++;
                }
            }
        }
    }
    fprintf(stderr,"=== captured %ld DS5 output start-frames in %.1fs (%.0f/s) ===\n", tx_start, el, tx_start/el);
    close(rfd); close(mfd); return 0;
}
