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

# Take ds5_txd off real-time AND split priorities so neither thread hurts the
# CTM usbip input thread, while keeping haptic tight:
#   main (inject loop, ~94/s): SCHED_OTHER nice -5 -> responsive, tight 0x36 on-air
#     timing, but normal policy so it never preempts the input thread.
#   other threads (HCI-monitor capture wakes ~420/s): SCHED_OTHER nice 19 -> yields
#     to the input thread so it stops nibbling input poll latency.
#
# 2026-06-22 (V5, audit wf_3b16cc9b): MEASURED in-jail during live Ratchet — the CTM
# input/session threads run at nice -20 (the aurora app's ctl_set_rt_prio()
# setpriority(-20) fallback SUCCEEDS; the jail grants CAP_SYS_NICE for nice even
# though it denies SCHED_FIFO). So inject at -5 sits BELOW input (-20) = input wins,
# no cross-process preemption. The earlier "inject -5 out-prioritizes input" concern
# was refuted on this hardware; -5 is correct and kept (still under input).
#
# main is deniced ONCE (denice_main): `renice -n` is RELATIVE on busybox/toybox, so
# re-running `renice -n -5` would drive -5 -> -10 -> -15 -> -20 and TIE the input
# thread (reintroducing the aussetzer). The main thread always exists at startup, so
# one call is correct. Workers are re-asserted (reassert_workers): they may not be
# visible at the first pass (created just after the socket binds), and nice clamps at
# +19 so relative-renice cannot compound them.
denice_main() {
  chrt -o -p 0 "$1" 2>/dev/null
  renice -n -5 -p "$1" >/dev/null 2>&1
}
reassert_workers() {
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
  # Main thread off RT once (relative-renice would compound it on busybox).
  denice_main "$TXD"
  # Workers may not exist at the first pass (created just after the socket binds), so
  # re-assert a SHORT, BOUNDED handful of times to catch a late-spawned thread that
  # would otherwise stay at SCHED_FIFO prio 14 and preempt the CTM input thread
  # (= aussetzer). Then STOP — no steady-state syscall churn (the O2 win); ds5_txd
  # never spawns threads after startup, and +19 clamps so this can't compound.
  n=0
  while [ $n -lt 5 ]; do
    reassert_workers "$TXD"
    n=$((n+1))
    kill -0 "$TXD" 2>/dev/null || break
    [ $n -lt 5 ] && sleep 1
  done
  echo "$(date +%H:%M:%S) [tmpld] ds5_txd $TXD -> SCHED_OTHER (main nice -5, workers nice 19, ${n}x)" >>/tmp/ds5_txd.log
  # Supervise. ds5_txd now self-heals the jail-tmp remount IN-PROCESS (mountinfo
  # poll -> rebind ds5_acl.sock + re-publish, in microseconds). A momentarily-gone
  # socket node is therefore NORMAL and must NOT trigger a restart: the old
  # kill-on-first-vanish raced that in-process rebind and forced a full restart
  # (re-seed, lost template, hidraw fallback) -> the very dropout the self-heal
  # exists to avoid. Only restart if the process dies OR the socket stays gone for a
  # sustained window (~10s = self-heal genuinely stuck).
  gone=0
  while kill -0 "$TXD" 2>/dev/null; do
    if [ ! -S "$SOCK" ]; then
      gone=$((gone+1))
      if [ $gone -ge 6 ]; then   # 6 consecutive misses ~= 10s of 2s ticks
        echo "$(date +%H:%M:%S) [tmpld] ds5_acl.sock gone >10s (in-process self-heal stuck) -> restarting ds5_txd" >>/tmp/ds5_txd.log
        kill "$TXD" 2>/dev/null
        break
      fi
    else
      gone=0
    fi
    sleep 2
  done
  wait "$TXD" 2>/dev/null
  sleep 1
done
