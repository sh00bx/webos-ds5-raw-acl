#!/bin/sh
# Respawn the DS5 raw-ACL transport forwarder (root) + low-priority watchdog for
# the jail-tmp-remount dropout (see history). Plus: drop ds5_txd off REAL-TIME
# scheduling.
#
# Why the priority drop (2026-06-21): ds5_txd self-sets SCHED_FIFO prio 14 for
# all its threads. Its HCI-monitor thread wakes on every BT packet (~420/s) and,
# at RT prio, PREEMPTS the CTM app's usbip input-handling thread -> the streamed
# DS5 input gets polled late -> input "aussetzer". The old SDL input path had no
# such RT daemon and was smooth; severity scaled with ds5_txd's RT load (old=
# slight, self-heal-binary=severe) -> RT preemption is the fingerprint. Running
# ds5_txd at NORMAL priority lets it interleave with (not preempt) the input
# thread; injection is only ~94/s and the BT controller meters output to ~10ms,
# so haptic stays smooth. Revert = delete the chrt loop.
SOCK=/var/palm/jail/com.aurora.gamestream/tmp/ds5_acl.sock
TMPL=/var/palm/jail/com.aurora.gamestream/tmp/ds5_acl_tmpl
HIDFD=/var/palm/jail/com.aurora.gamestream/tmp/ds5_hidfd.sock

denice() {
  # Take ds5_txd off real-time AND split priorities so neither thread hurts the
  # CTM usbip input thread, while keeping haptic tight:
  #   main/$1 (inject loop, ~94/s): SCHED_OTHER nice -5 -> responsive, tight 0x36
  #     on-air timing, but normal policy so it never preempts the input thread.
  #   other threads (HCI-monitor capture wakes ~420/s): SCHED_OTHER nice 19 ->
  #     yields to the input thread so it stops nibbling input poll latency.
  #
  # 2026-06-22 (V5, audit wf_3b16cc9b): MEASURED in-jail during live Ratchet —
  # the CTM input/session threads run at nice -20 (the aurora app's
  # ctl_set_rt_prio() setpriority(-20) fallback SUCCEEDS; the jail grants
  # CAP_SYS_NICE for nice even though it denies SCHED_FIFO). So inject at -5 sits
  # BELOW input (-20) = input wins, no cross-process preemption. The earlier
  # "inject -5 out-prioritizes input" concern was refuted on this hardware; -5 is
  # correct and kept (slightly tighter haptic than 0, still under input).
  chrt -o -p 0 "$1" 2>/dev/null
  renice -n -5 -p "$1" >/dev/null 2>&1
  for tid in $(ls /proc/"$1"/task 2>/dev/null); do
    [ "$tid" = "$1" ] && continue
    chrt -o -p 0 "$tid" 2>/dev/null
    renice -n 19 -p "$tid" >/dev/null 2>&1
  done
}

while true; do
  /var/lib/webosbrew/ds5_txd "$SOCK" "$TMPL" "$HIDFD" >/tmp/ds5_txd.log 2>&1 &
  TXD=$!
  # wait for bind + thread creation, then take ds5_txd off real-time priority
  i=0
  while [ $i -lt 10 ]; do
    [ -S "$SOCK" ] && break
    kill -0 "$TXD" 2>/dev/null || break
    sleep 1; i=$((i+1))
  done
  denice "$TXD"
  echo "$(date +%H:%M:%S) [tmpld] ds5_txd $TXD -> SCHED_OTHER (normal prio)" >>/tmp/ds5_txd.log
  # supervise: vanished socket node = aurora remounted its tmp -> restart to rebind
  while kill -0 "$TXD" 2>/dev/null; do
    if [ ! -S "$SOCK" ]; then
      echo "$(date +%H:%M:%S) [tmpld] ds5_acl.sock vanished (jail-tmp remount) -> restarting ds5_txd" >>/tmp/ds5_txd.log
      kill "$TXD" 2>/dev/null
      break
    fi
    denice "$TXD"   # re-assert in case a thread was (re)created
    sleep 2
  done
  wait "$TXD" 2>/dev/null
  sleep 1
done
