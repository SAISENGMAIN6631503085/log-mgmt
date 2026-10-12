#!/usr/bin/env bash
# Send the sample syslog files to Vector (UDP 514 by default), as a firewall/switch would.
#
# Timestamps are rewritten to "now" so the events land inside the retention window on any day.
# Uses bash's built-in /dev/udp and /dev/tcp, so no netcat is needed.
#
#   ./send_syslog.sh                    # firewall.log + network.log to 127.0.0.1:514/udp
#   ./send_syslog.sh -h 10.0.0.5 -t     # another host, over TCP
#   ./send_syslog.sh myfile.log         # your own file
set -euo pipefail

HOST=127.0.0.1 PORT=514 PROTO=udp  # IPv4: Vector's port is published on IPv4 (SYSLOG_BIND)
while getopts "h:p:t" opt; do
  case $opt in
    h) HOST=$OPTARG ;;
    p) PORT=$OPTARG ;;
    t) PROTO=tcp ;;
    *) echo "usage: $0 [-h host] [-p port] [-t] [files...]" >&2; exit 1 ;;
  esac
done
shift $((OPTIND - 1))

DIR=$(cd "$(dirname "$0")" && pwd)
FILES=("$@")
[ ${#FILES[@]} -eq 0 ] && FILES=("$DIR/firewall.log" "$DIR/network.log")

exec 3<>"/dev/$PROTO/$HOST/$PORT"
count=0
for f in "${FILES[@]}"; do
  while IFS= read -r line || [ -n "$line" ]; do
    [ -z "$line" ] && continue
    now=$(LC_ALL=C date -u '+%b %e %H:%M:%S')   # RFC 3164 timestamp, e.g. "Oct  2 08:15:01"
    # Replace the "Mmm dd hh:mm:ss" right after <PRI> with the current time.
    line=$(printf '%s' "$line" | sed -E "s/^(<[0-9]+>)[A-Z][a-z]{2} +[0-9]{1,2} [0-9:]{8}/\1$now/")
    printf '%s\n' "$line" >&3
    count=$((count + 1))
  done < "$f"
done
exec 3>&-
echo "sent $count syslog line(s) to $HOST:$PORT/$PROTO"
