#!/usr/bin/env python3
"""Live traffic simulator for demos. Python standard library only.

Every second it sends a small batch of realistic events (API, AWS, M365, AD, CrowdStrike over
HTTP; firewall/network over syslog) for each tenant key. Every --attack-every seconds it stages
a brute-force attack, 6 failed AD logons from one IP within a minute, so an alert fires on the
alert worker's next run.

    python3 samples/simulator.py                          # 2 events/s for demoA and demoB, until Ctrl-C
    python3 samples/simulator.py --duration 60 --rate 5
    python3 samples/simulator.py --attack-every 30 --no-syslog
"""
import argparse
import json
import random
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

USERS = ["alice", "bob", "carol", "dave", "erin", "frank"]
INTERNAL = [f"10.0.{s}.{h}" for s in (1, 2, 3) for h in range(10, 60, 7)]
# Background users come from many addresses, so their occasional failed logins (a typo here
# and there) almost never reach 5 per IP in 5 minutes. Only the staged attacks should alert.
EXTERNAL = [f"198.51.100.{h}" for h in range(1, 255)] + [f"192.0.2.{h}" for h in range(1, 255)]
ATTACKERS = [f"203.0.113.{h}" for h in range(100, 200, 9)]


def iso(ms=False):
    now = datetime.now(timezone.utc)
    return now.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def gen_api():
    ok = random.random() > 0.15
    return "api", {"timestamp": iso(), "service": random.choice(["payments-api", "orders-api"]),
                   "event_type": "login_success" if ok else "login_failed", "user": random.choice(USERS),
                   "ip": random.choice(EXTERNAL), "method": "POST", "path": "/api/v1/login",
                   "status": 200 if ok else 401, "req_id": random.getrandbits(48)}


def gen_aws():
    name, src = random.choice([("ConsoleLogin", "signin"), ("RunInstances", "ec2"), ("GetObject", "s3"),
                               ("DeleteBucket", "s3"), ("CreateUser", "iam")])
    rec = {"eventTime": iso(), "eventID": f"{random.getrandbits(64):x}", "eventName": name,
           "eventSource": f"{src}.amazonaws.com", "awsRegion": random.choice(["us-east-1", "eu-west-1"]),
           "sourceIPAddress": random.choice(EXTERNAL), "recipientAccountId": "123456789012",
           "userIdentity": {"type": "IAMUser", "userName": random.choice(USERS), "accountId": "123456789012"}}
    if name == "ConsoleLogin":
        rec["responseElements"] = {"ConsoleLogin": random.choice(["Success"] * 4 + ["Failure"])}
    return "aws", rec


def gen_m365():
    op = random.choice(["UserLoggedIn"] * 4 + ["UserLoginFailed", "FileAccessed", "FileDeleted"])
    return "m365", {"CreationTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
                    "Id": f"{random.getrandbits(64):x}", "Operation": op, "Workload": "AzureActiveDirectory",
                    "ResultStatus": "Failed" if op == "UserLoginFailed" else "Success",
                    "UserId": f"{random.choice(USERS)}@contoso.com", "ClientIP": random.choice(EXTERNAL),
                    "OrganizationId": "contoso-org-id"}


def gen_ad(event_id=None, ip=None, user=None):
    event_id = event_id or random.choice([4624] * 6 + [4625, 4634])
    return "ad", {"TimeCreated": iso(), "EventID": str(event_id), "Computer": "DC01.corp.local",
                  "TargetUserName": user or random.choice(USERS), "IpAddress": ip or random.choice(INTERNAL),
                  "IpPort": str(random.randint(49152, 65535))}


def gen_crowdstrike():
    sev = random.choice([2, 3, 3, 4, 5])
    return "crowdstrike", {
        "metadata": {"eventType": "DetectionSummaryEvent", "eventCreationTime": int(time.time() * 1000),
                     "offset": random.getrandbits(32)},
        "event": {"ComputerName": f"WS-{random.randint(1, 80):03d}", "UserName": random.choice(USERS),
                  "LocalIP": random.choice(INTERNAL), "Severity": sev, "Tactic": "Execution",
                  "DetectName": random.choice(["Suspicious PowerShell", "Malicious document", "Credential dumping"]),
                  "FileName": random.choice(["powershell.exe", "winword.exe", "rundll32.exe"]),
                  "PatternDispositionFlags": {"QuarantineFile": sev >= 4}}}


GENERATORS = [gen_api] * 4 + [gen_aws] * 2 + [gen_m365] * 2 + [gen_ad] * 3 + [gen_crowdstrike]


def syslog_line():
    ts = time.strftime("%b %e %H:%M:%S", time.gmtime())
    if random.random() < 0.7:
        action = random.choice(["accept"] * 3 + ["deny"])
        return (f"<{134 if action == 'accept' else 132}>{ts} fw01 vendor=Fortinet product=FortiGate action={action} "
                f"src={random.choice(INTERNAL + EXTERNAL)} dst={random.choice(INTERNAL)} spt={random.randint(1024, 65535)} "
                f"dpt={random.choice([22, 53, 80, 443, 3389])} proto=tcp")
    state = random.choice(["down", "up"])
    return (f"<{187 if state == 'down' else 189}>{ts} core-sw01 %LINK-3-UPDOWN: vendor=Cisco product=IOS "
            f"event_type=link_{state} interface=Gi1/0/{random.randint(1, 48)}")


class Client:
    def __init__(self, url, insecure):
        self.url = url
        self.ctx = ssl._create_unverified_context() if insecure else None

    def send(self, key, source, events):
        req = Request(f"{self.url}/api/ingest?source={source}", data=json.dumps(events).encode(), method="POST",
                      headers={"X-API-Key": key, "Content-Type": "application/json"})
        try:
            with urlopen(req, context=self.ctx, timeout=10) as r:
                return json.loads(r.read())
        except HTTPError as e:
            return {"error": e.code, "detail": e.read().decode(errors="replace")}
        except URLError as e:
            return {"error": str(e.reason)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="https://localhost")
    ap.add_argument("--keys", default="lm_demoA_dev_key_change_me,lm_demoB_dev_key_change_me",
                    help="comma-separated tenant API keys")
    ap.add_argument("--rate", type=float, default=2, help="HTTP events per second per tenant")
    ap.add_argument("--duration", type=float, default=0, help="seconds to run (0 = until Ctrl-C)")
    ap.add_argument("--attack-every", type=float, default=120, help="seconds between brute-force bursts (0 = never)")
    ap.add_argument("--syslog", default="127.0.0.1:514", help="Vector syslog host:port (UDP)")
    ap.add_argument("--no-syslog", action="store_true")
    ap.add_argument("--verify-tls", action="store_true")
    args = ap.parse_args()

    client = Client(args.url, insecure=not args.verify_tls)
    keys = [k.strip() for k in args.keys.split(",") if k.strip()]
    sock = None if args.no_syslog else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sys_host, _, sys_port = args.syslog.partition(":")
    start = time.time()
    next_attack = start + 10 if args.attack_every else float("inf")  # first attack soon, for the demo
    totals = {"accepted": 0, "errors": 0, "syslog": 0, "attacks": 0}

    print(f"simulating {args.rate}/s per tenant for {len(keys)} tenant(s); Ctrl-C to stop")
    try:
        while not args.duration or time.time() - start < args.duration:
            tick = time.time()
            for key in keys:
                # Group by source: one request per source per tick.
                batch: dict[str, list] = {}
                n = int(args.rate) + (random.random() < args.rate % 1)
                for _ in range(n):
                    source, event = random.choice(GENERATORS)()
                    batch.setdefault(source, []).append(event)
                if time.time() >= next_attack:
                    ip, user = random.choice(ATTACKERS), random.choice(["administrator", "admin", "root"])
                    batch.setdefault("ad", []).extend(gen_ad(4625, ip, user)[1] for _ in range(6))
                    totals["attacks"] += 1
                    print(f"  attack: 6 failed logons for {user!r} from {ip} ({key[:8]}...)")
                for source, events in batch.items():
                    r = client.send(key, source, events)
                    if "error" in r:
                        totals["errors"] += 1
                        print(f"  {source}: {r}", file=sys.stderr)
                    else:
                        totals["accepted"] += r["accepted"]
            if time.time() >= next_attack:
                next_attack = time.time() + args.attack_every
            if sock:
                sock.sendto(syslog_line().encode(), (sys_host, int(sys_port or 514)))
                totals["syslog"] += 1
            time.sleep(max(0.0, 1 - (time.time() - tick)))
    except KeyboardInterrupt:
        pass
    print(f"done: {totals['accepted']} HTTP events accepted, {totals['syslog']} syslog lines sent, "
          f"{totals['attacks']} attack(s), {totals['errors']} error(s)")
    return 1 if totals["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
