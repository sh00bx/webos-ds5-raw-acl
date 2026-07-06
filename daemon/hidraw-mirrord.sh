#!/bin/sh
# Mirror host hidraw device nodes into the Aurora jail /dev (root side).
#
# Why (verified on-device): the jail /dev of com.aurora.gamestream is populated
# from a STATIC template at jail build time and contains only hidraw0-4. hidraw
# minors are DYNAMIC — after a few BT reconnects the DualSense lands on a host
# minor > 4 (e.g. /dev/hidraw5), the node simply does not exist inside the jail,
# the app's hid open fails errno=2 and the controller bridges as "unknown HID
# device" / not at all. webOS offers no in-jail device manager, so a root-side
# watcher keeps the jail nodes in sync with /sys/class/hidraw: same name, same
# major:minor, mode 0666. Plain 2s poll — one sysfs glob + a handful of reads
# per pass, no inotify dependency, negligible CPU on this resource-sensitive TV.
#
# Ownership discipline: we only ever DELETE nodes recorded in our own state
# file (nodes THIS watcher created). The static template set stays untouched
# even while the host device is absent — those nodes belong to the jail
# builder. The one exception is a jail node whose numbers DISAGREE with a live
# host device of the same name (recycled minor / stale template numbers): such
# a node is useless-to-harmful (open() reaches a different or dead device), so
# it is removed, recreated with the live numbers, and adopted as ours.
#
# All paths are env-overridable so the script is testable off-TV; with
# HIDRAW_MIRROR_DRYRUN=1 actions are echoed to stdout and device nodes are
# stood in by marker files carrying "major:minor" (mknod needs root, markers
# let the decision logic run as any user).

SYSFS="${HIDRAW_MIRROR_SYSFS:-/sys/class/hidraw}"
JAIL="${HIDRAW_MIRROR_JAIL:-/var/palm/jail/com.aurora.gamestream/dev}"
STATE="${HIDRAW_MIRROR_STATE:-/tmp/hidraw_mirror.state}"
LOG="${HIDRAW_MIRROR_LOG:-/tmp/hidraw_mirrord.log}"
PIDFILE="${HIDRAW_MIRROR_PIDFILE:-/tmp/hidraw-mirrord.pid}"
POLL="${HIDRAW_MIRROR_POLL:-2}"
DRYRUN="${HIDRAW_MIRROR_DRYRUN:-0}"

# Singleton guard (same pattern as ds5-tmpld.sh). The boot hook's
# start-stop-daemon --exec check can NEVER dedup a shell script (busybox
# matches --exec against /proc/<pid>/exe, which for a running script is the
# INTERPRETER /bin/sh -> busybox, never the script path), so a hook re-run
# (manual start, hbchannel restart, webosbrew re-elevation) would spawn a
# second watcher and the pair would race each other's create/remove decisions.
# Guard here instead.
#
# Acquisition is ATOMIC (noclobber create): a plain read-check-write has a
# TOCTOU hole — two simultaneous starts both see no live owner and both write
# the pidfile. A stale file (crash leftover, recycled pid) is CLAIMED by
# rename first: mv is atomic, so of several racers exactly one removes it; the
# rest re-loop and either lose the create (and find the winner live) or exit.
#
# Liveness anchors on the process IDENTITY, not just cmdline bytes: a recycled
# pid whose cmdline merely mentions the name (vi/tail/grep on this file) must
# not count as a watcher, or a crash could never be recovered from. A real
# watcher is the script exec'd directly (the kernel sets comm to the script
# basename for a shebang exec) or a shell interpreting it.
is_live_mirrord() {
  kill -0 "$1" 2>/dev/null || return 1
  grep -q "hidraw-mirrord" "/proc/$1/cmdline" 2>/dev/null || return 1
  case "$(cat "/proc/$1/comm" 2>/dev/null)" in
    hidraw-mirror*|sh|ash|dash|busybox) return 0 ;;
  esac
  return 1
}
while :; do
  if ( set -C && echo "$$" > "$PIDFILE" ) 2>/dev/null; then
    break   # we own the pidfile
  fi
  OLD=$(cat "$PIDFILE" 2>/dev/null)
  if [ -n "$OLD" ] && is_live_mirrord "$OLD"; then
    exit 0  # a live watcher already owns it
  fi
  mv -f "$PIDFILE" "$PIDFILE.stale.$$" 2>/dev/null && rm -f "$PIDFILE.stale.$$"
done

# Event-only logging (never per-poll chatter), capped: rotate to .1 above 64KB
# so it can never grow unbounded. Each write reopens the file (>>), so the
# rotate needs no fd gymnastics.
log() {
  if [ -f "$LOG" ]; then   # guard: a bare <"$LOG" redirect failure prints to stderr BEFORE 2>/dev/null applies
    sz=$(wc -c <"$LOG" 2>/dev/null || echo 0)
    [ "${sz:-0}" -gt 65536 ] && mv -f "$LOG" "$LOG.1" 2>/dev/null
  fi
  echo "$(date +%H:%M:%S) [hidraw-mirror] $*" >>"$LOG"
}

# --- node primitives -------------------------------------------------------
# node_ok PATH MAJ MIN: node exists with exactly this identity.
# Real mode: char device + rdev match (stat prints hex, sysfs gives decimal).
# Dry-run: marker file whose content is "MAJ:MIN".
node_ok() {
  if [ "$DRYRUN" = "1" ]; then
    [ -f "$1" ] || return 1
    [ "$(cat "$1" 2>/dev/null)" = "$2:$3" ]
  else
    [ -c "$1" ] || return 1
    [ "$(stat -c '%t:%T' "$1" 2>/dev/null)" = "$(printf '%x:%x' "$2" "$3")" ]
  fi
}
make_node() {
  if [ "$DRYRUN" = "1" ]; then
    echo "DRYRUN: mknod $1 c $2 $3 && chmod 666 $1"
    echo "$2:$3" > "$1" 2>/dev/null
  else
    mknod "$1" c "$2" "$3" 2>/dev/null && chmod 666 "$1" 2>/dev/null
  fi
}
remove_node() {
  [ "$DRYRUN" = "1" ] && echo "DRYRUN: rm $1"
  rm -f "$1" 2>/dev/null
}

# --- ownership state -------------------------------------------------------
# OWNED = names of jail nodes THIS watcher created; persisted (one name per
# line) so a watcher restart keeps reaping rights over its earlier creations.
# Only OWNED nodes are ever removed on device-gone; everything else in the
# jail /dev (the static template set) is off-limits.
OWNED=""
if [ -f "$STATE" ]; then
  while read -r n; do
    [ -n "$n" ] && OWNED="$OWNED $n"
  done < "$STATE"
fi
save_state() { printf '%s\n' $OWNED > "$STATE" 2>/dev/null; }
owns() { case " $OWNED " in *" $1 "*) return 0 ;; esac; return 1; }
adopt() { owns "$1" || { OWNED="$OWNED $1"; save_state; }; }
disown_name() {
  new=""
  for n in $OWNED; do [ "$n" = "$1" ] || new="$new $n"; done
  OWNED=$new
  save_state
}

# Per-name once-per-streak failure note (a persistent mknod failure must not
# turn into per-poll log spam; cleared again on the first success/match).
WARNED=""
warned() { case " $WARNED " in *" $1 "*) return 0 ;; esac; return 1; }
warn_once() { warned "$1" || { WARNED="$WARNED $1"; log "$2"; }; }
unwarn() {
  warned "$1" || return 0
  new=""
  for n in $WARNED; do [ "$n" = "$1" ] || new="$new $n"; done
  WARNED=$new
}

log "watcher up (pid $$, sysfs=$SYSFS, jail=$JAIL, owned:${OWNED:- none})"
[ "$DRYRUN" = "1" ] && log "DRY-RUN mode: marker files instead of device nodes"

while :; do
  # Re-check both dirs EVERY pass: the jail dir may not exist yet (app never
  # launched since boot) and jail paths can be torn down and recreated (see
  # the jail-tmp remount history). Absent dir = keep polling cheaply, no
  # errors, no log chatter. Skipping the reap pass too is deliberate — with
  # sysfs or the jail gone we cannot tell "device gone" from "world gone",
  # and our nodes vanish with a recreated jail anyway (recreated next pass).
  if [ -d "$SYSFS" ] && [ -d "$JAIL" ]; then

    # Ensure a correct jail node for every live host hidraw.
    for d in "$SYSFS"/hidraw*; do
      [ -r "$d/dev" ] || continue      # also drops the unmatched-glob literal
      name=${d##*/}
      read -r devnum < "$d/dev" || continue
      maj=${devnum%%:*}; min=${devnum##*:}
      [ -n "$maj" ] && [ -n "$min" ] || continue
      node="$JAIL/$name"
      if node_ok "$node" "$maj" "$min"; then
        unwarn "$name"
        continue                       # correct node (static or ours): hands off
      fi
      if [ -e "$node" ] || [ -L "$node" ]; then
        # Same name, wrong identity (recycled minor / stale numbers): the node
        # points at the wrong device, replace it and adopt the replacement.
        # ATOMIC replace (mknod to a temp name, rename over): never delete the
        # old node before the new one exists, so a failing mknod cannot leave
        # the name empty — and rename means no open() window without a node.
        tmp="$node.mirror.new"
        rm -f "$tmp" 2>/dev/null
        if make_node "$tmp" "$maj" "$min" && mv -f "$tmp" "$node" 2>/dev/null; then
          log "recreated $name ($maj:$min) — stale major:minor"
          adopt "$name"; unwarn "$name"
        else
          rm -f "$tmp" 2>/dev/null
          warn_once "$name" "FAILED to recreate $name c $maj $min in $JAIL"
        fi
      else
        if make_node "$node" "$maj" "$min"; then
          log "created $name ($maj:$min)"
          adopt "$name"; unwarn "$name"
        else
          warn_once "$name" "FAILED to create $name c $maj $min in $JAIL"
        fi
      fi
    done

    # Reap OUR nodes whose host device disappeared. Never touches nodes we
    # did not create — the static template set stays in place even while the
    # matching host device is absent.
    for name in $OWNED; do
      if [ ! -d "$SYSFS/$name" ]; then
        remove_node "$JAIL/$name"
        disown_name "$name"
        log "removed $name (host device gone)"
      fi
    done
  fi
  sleep "$POLL"
done
