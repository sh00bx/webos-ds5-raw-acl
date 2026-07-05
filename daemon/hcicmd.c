/* hcicmd — send a no-parameter HCI command via a RAW socket and watch for the
 * Command Complete/Status on the MONITOR channel (which taps everything the
 * driver receives, including responses routed to an HCI_USER_CHANNEL holder).
 * Discriminates "controller deaf" from "kernel blind" (LG vendor stack owning
 * the adapter user-channel: controller answers, kernel logs tx timeout anyway).
 * Usage: hcicmd <opcode-hex> */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH 31
#endif
#define BTPROTO_HCI 1
#define HCI_CHANNEL_RAW     0
#define HCI_CHANNEL_MONITOR 2
#define HCI_DEV_NONE 0xffff
#define MON_EVENT_PKT 3
struct sockaddr_hci { unsigned short hci_family, hci_dev, hci_channel; };
struct hci_mon_hdr { uint16_t opcode, index, len; } __attribute__((packed));
int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s <opcode-hex>\n", argv[0]); return 2; }
    uint16_t op = (uint16_t)strtoul(argv[1], NULL, 16);
    int m = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if (m < 0) { perror("socket mon"); return 1; }
    struct sockaddr_hci ma; memset(&ma, 0, sizeof ma);
    ma.hci_family = AF_BLUETOOTH; ma.hci_dev = HCI_DEV_NONE; ma.hci_channel = HCI_CHANNEL_MONITOR;
    if (bind(m, (struct sockaddr *)&ma, sizeof ma) < 0) { perror("bind mon"); return 1; }
    int s = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if (s < 0) { perror("socket raw"); return 1; }
    struct sockaddr_hci a; memset(&a, 0, sizeof a);
    a.hci_family = AF_BLUETOOTH; a.hci_dev = 0; a.hci_channel = HCI_CHANNEL_RAW;
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind raw"); return 1; }
    uint8_t cmd[4] = { 0x01, (uint8_t)(op & 0xff), (uint8_t)(op >> 8), 0 };
    if (write(s, cmd, sizeof cmd) != 4) { perror("write"); return 1; }
    struct pollfd p = { .fd = m, .events = POLLIN };
    int waited = 0;
    while (waited < 5000) {
        int r = poll(&p, 1, 200); waited += 200;
        if (r <= 0) continue;
        uint8_t buf[2048]; ssize_t n = read(m, buf, sizeof buf);
        if (n < (ssize_t)sizeof(struct hci_mon_hdr)) continue;
        struct hci_mon_hdr *h = (struct hci_mon_hdr *)buf;
        if (h->opcode != MON_EVENT_PKT) continue;
        uint8_t *d = buf + sizeof(struct hci_mon_hdr); int dl = h->len;
        if (dl < 5) continue;
        uint8_t ev = d[0];
        if (ev == 0x0e && dl >= 5 && (d[3] | (d[4] << 8)) == op) {
            printf("op 0x%04x: COMMAND COMPLETE on air (monitor) status=0x%02x after ~%dms\n",
                   op, dl >= 6 ? d[5] : 0xff, waited);
            return 0;
        }
        if (ev == 0x0f && dl >= 6 && (d[4] | (d[5] << 8)) == op) {
            printf("op 0x%04x: COMMAND STATUS on air (monitor) status=0x%02x after ~%dms\n",
                   op, d[2], waited);
            return 0;
        }
    }
    printf("op 0x%04x: NO RESPONSE on air within 5s -> controller really deaf\n", op);
    return 3;
}
