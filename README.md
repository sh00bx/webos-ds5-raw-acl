# webos-ds5-raw-acl

Bypass the webOS Bluetooth **one-outstanding HID-output flow-control jitter wall**
by re-injecting controller output reports as raw HCI-ACL packets — non-invasively,
with no kernel patch, no binary patch, and automatic fallback to the normal path.

Built for streaming **DualSense (DS5)** haptics / controller-audio (the 100/s
`0x36` report stream) from a jailed webOS Moonlight client to a real DS5 over
Bluetooth, but the transport technique applies to any high-rate BT HID-output
stream that webOS' stack paces.

---

## The problem

`webos-bluetooth-service` paces HID output **one-outstanding**: it writes one ACL
packet, waits ~30–40 ms for completion, then sends the next. For a 100/s output
stream (DS5 audio / voice-coil haptics) this collapses the on-air cadence and
adds large jitter gaps — which is exactly what chops the haptics and controller
audio:

| | on-air rate | jitter |
|---|---|---|
| `/dev/hidraw` (through webos-bluetooth-service) | **~62 / s** | gaps **30–67 ms** |
| raw-ACL re-injection (this project) | **100 / s** | mean **10 ms**, max **17 ms**, **zero** gaps > 30 ms |

This was previously assumed irreducible. It is not.

## The technique

A DS5 output report rides an L2CAP HID-interrupt channel as an ACL packet. If you
can put the *exact same on-air framing* on the air yourself — bypassing the
service that meters it — the controller accepts it identically.

1. **Capture the template** on the HCI **monitor** channel (`HCI_CHANNEL_MONITOR`).
   webOS' own stack consumes command-complete on the raw socket, but the monitor
   channel mirrors all TX. From one real on-air report we grab the ACL header
   (connection handle + PB/BC flags), the L2CAP length + CID, and the HID prefix.
2. **Inject** re-stamped copies on a second `HCI_CHANNEL_RAW` socket — verbatim
   framing, with sequence number, packet counter and CRC32 re-stamped per send so
   the controller sees a valid monotonic stream.

`reference/ds5_aclinject.c` is a complete standalone proof of this loop (capture →
inject), and `reference/ds5_aclre.c` is the non-invasive RE tool that first
measured the controller's ACL buffer depth and dumped the exact framing. Both are
self-contained and a good place to start reading.

## Why a root daemon (and not just in-process)

Inside the webOS **app jail** you *can* `bind()` an `HCI_CHANNEL_RAW` socket, but
the ACL `write()` returns **EPERM** — so in-process injection from the app is
impossible. The work is therefore split:

```
   jailed app                                    root
  ┌───────────────────┐   AF_UNIX SOCK_DGRAM   ┌──────────────────────────┐
  │ client/ds5_acl_tx │ ─────(one report)────▶ │ daemon/ds5_txd           │
  │  (forwarder)      │                        │  • MONITOR-capture template│
  │                   │ ◀──readiness file──────│  • RAW-write inject (root) │
  └───────────────────┘                        └──────────────────────────┘
```

- **`client/ds5_acl_tx.{c,h}`** — in-app forwarder. Hands each already-built,
  already-CRC-signed report to the daemon over a local datagram (~tens of µs, no
  round trip, far below the ~10 ms audio grid). Depends on nothing but libc +
  pthreads — drop it into any app.
- **`daemon/ds5_txd.c`** — root helper that does the privileged MONITOR-capture +
  RAW-write, and publishes a 16-byte readiness/template record. Until it signals
  *ready*, the app keeps seeding reports via `/dev/hidraw` — which both works and
  gives the daemon on-air traffic to capture the template from.

**No regression by design:** if the daemon is absent, or before it has a
template, every report falls back to the normal `/dev/hidraw` write. The injector
is also restricted to the high-rate `0x31`/`0x32`/`0x36` reports; everything else
stays on hidraw.

## Bonus: HID-FD broker (jail static-node gap)

The same daemon also fixes a second jail problem. A webOS app jail's `/dev` is a
**static snapshot** taken at jail-build, so a controller hot-plugged onto a
`/dev/hidrawN` minor the snapshot never covered (e.g. `hidraw5`) simply does not
exist inside the jail — the app's `open()` returns `ENOENT`. The daemon (root,
real `/dev`) opens the node and passes the **open fd** across the jail via
`SCM_RIGHTS`. Client: `client/ds5_hidfd.{c,h}` (`ds5_hidfd_request("/dev/hidrawN")`).
Used only as a fallback after a direct `open()` fails, so the static-node path is
untouched.

---

## Build

```sh
make                      # native (x86) — for reading/testing the reference tools
make CC=arm-webos-linux-gnueabi-gcc   # cross-compile the daemon for the TV
```

Builds `ds5_txd` (the daemon) and the two `reference/` tools. The `client/` files
are **drop-in source** for your app, not a standalone binary.

## Run (on the TV, as root)

```sh
ds5_txd [acl_sock_path] [template_path] [hidfd_sock_path]
```

Defaults target the Aurora jail tmp; pass your own paths to match your app. The
forwarder client picks up the same paths via `DS5_ACL_SOCK` / `DS5_ACL_TMPL`
(and `DS5_HIDFD_SOCK` for the broker), defaulting to `/tmp/ds5_acl.sock`,
`/tmp/ds5_acl_tmpl`, `/tmp/ds5_hidfd.sock`.

## Integrating the forwarder into your app

```c
#include "ds5_acl_tx.h"

ds5_acl_tx_t *tx = ds5_acl_tx_start(0, my_log_fn, my_ctx);   /* NULL log ok */

/* per output report you would otherwise write to /dev/hidraw: */
if (ds5_acl_is_injectable(report[0]) &&
    ds5_acl_tx_send(tx, report, len) == DS5_ACL_TX_SENT) {
    /* injected — do NOT also write hidraw */
} else {
    write(hidraw_fd, report, len);   /* seeds template capture + is the fallback */
}

ds5_acl_tx_stop(tx);
```

See `ds5_acl_tx.h` for the full return-code contract.

---

## Status / caveats

- Proven end-to-end on LG webOS with a DualSense over Bluetooth; the report sizes
  and the DS5 output CRC32 (`reference/ds5_aclinject.c`) are DS5-specific.
- The transport (template-capture + raw-ACL re-inject) is webOS-generic; adapt the
  report filter / CRC for a different controller.
- Non-invasive and reversible — nothing is patched or persisted; stop the daemon
  and the system is exactly as before.

## License

MIT — see [LICENSE](LICENSE).
