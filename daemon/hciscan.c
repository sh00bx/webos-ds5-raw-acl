/* hciscan — set the BR/EDR scan mode (Write_Scan_Enable, opcode 0x0C1A) on
 * hci0 via a raw HCI socket. webOS has no hciconfig; this is the minimal
 * equivalent of `hciconfig hci0 noscan|pscan|piscan`.
 *
 * Usage: hciscan <mode>   mode: 0=noscan 1=iscan 2=pscan 3=piscan
 *
 * Purpose (2026-07-05): the TV controller's periodic page/inquiry scan blocks
 * the DS5 ACL link for 86-234ms on a ~1.28s grid (measured via ds5_txd's
 * EPISODE detector) — the invisible cause of speaker-audio dropouts and input
 * hiccups during streaming. Scan-off while a session runs removes the
 * blackouts; restore mode 2 afterwards so devices can reconnect.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH 31
#endif
#define BTPROTO_HCI     1
#define HCI_CHANNEL_RAW 0
struct sockaddr_hci { unsigned short hci_family, hci_dev, hci_channel; };

#define OP_WRITE_SCAN_ENABLE 0x0c1a

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s <0|1|2|3>\n", argv[0]); return 2; }
    int mode = atoi(argv[1]);
    if (mode < 0 || mode > 3) { fprintf(stderr, "mode must be 0..3\n"); return 2; }

    int s = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if (s < 0) { fprintf(stderr, "socket: %s\n", strerror(errno)); return 1; }
    struct sockaddr_hci a; memset(&a, 0, sizeof a);
    a.hci_family = AF_BLUETOOTH; a.hci_dev = 0; a.hci_channel = HCI_CHANNEL_RAW;
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) {
        fprintf(stderr, "bind: %s\n", strerror(errno)); return 1;
    }
    uint8_t cmd[5] = { 0x01 /*HCI_COMMAND_PKT*/,
        OP_WRITE_SCAN_ENABLE & 0xff, OP_WRITE_SCAN_ENABLE >> 8, 1,
        (uint8_t)mode };
    if (write(s, cmd, sizeof cmd) != (ssize_t)sizeof cmd) {
        fprintf(stderr, "write: %s\n", strerror(errno)); return 1;
    }
    printf("scan_enable=%d sent\n", mode);
    close(s);
    return 0;
}
