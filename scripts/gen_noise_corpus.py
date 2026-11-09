#!/usr/bin/env python3
"""Write the synthetic benign corpus the noise gate measures rules against.

The noise gate (`signalman noise`, `signalman gates --corpus`) reports how
often a rule fires per 100,000 events. Against attack data that number means
nothing; it needs the ordinary activity of a working fleet. There is no such
telemetry in this repository, so this script generates it: users opening
applications from explorer, services under svchost, browsers and updaters
talking to the internet on 443, admins running tools the normal way.

It includes benign uses of binaries that attack rules also name (certutil
hashing a file, rundll32 opening a control panel applet, powershell running
a signed script, net querying the domain). A rule that keys on the binary
alone rather than on how it is used fires on those, which is the noise the
gate exists to show.

The output is deterministic for a seed, so the committed corpus can be
regenerated and diffed. It is synthetic: it finds rules that fire on
everyday activity, and it cannot stand in for a real fleet's long tail.

Process starts are Sysmon event 1, not Security 4688. Most rules resolve
to the Sysmon taxonomy entry, and an event no rule can see would still
count in the per-100k denominator and dilute every rate. Rules on
`service: security` are therefore not exercised by this corpus.

Public addresses come from the RFC 5737 documentation ranges, so no event
names a real third party that an IOC list could match by chance.

Usage: scripts/gen_noise_corpus.py OUT.ndjson [--events N] [--seed S]
The committed corpus is the defaults: 10,000 events, seed 1.
"""

import argparse
import json
import random
import sys

SYSMON = "Microsoft-Windows-Sysmon/Operational"
SYS32 = "C:\\Windows\\System32\\"
PF = "C:\\Program Files\\"
PF86 = "C:\\Program Files (x86)\\"

USERS = [f"CORP\\{u}" for u in ("alee", "bkim", "cdiaz", "dpatel", "eng", "fwong", "gsmith", "hnguyen")]
ADMINS = ["CORP\\adm-ops", "CORP\\adm-it"]
SYSTEM = "NT AUTHORITY\\SYSTEM"
HOSTS_DOCS = ["Q3 plan.docx", "budget.xlsx", "notes.txt", "deck.pptx", "invoice 1182.pdf"]

# (weight, user kind, parent, image, command line template)
PROCESSES = [
    (30, "user", "C:\\Windows\\explorer.exe", PF + "Google\\Chrome\\Application\\chrome.exe", '"{img}" --profile-directory=Default'),
    (12, "user", PF + "Google\\Chrome\\Application\\chrome.exe", PF + "Google\\Chrome\\Application\\chrome.exe",
     '"{img}" --type=renderer --lang=en-US --renderer-client-id={n}'),
    (10, "user", "C:\\Windows\\explorer.exe", PF + "Microsoft Office\\root\\Office16\\WINWORD.EXE", '"{img}" /n "C:\\Users\\{u}\\Documents\\{doc}"'),
    (8, "user", "C:\\Windows\\explorer.exe", PF + "Microsoft Office\\root\\Office16\\EXCEL.EXE", '"{img}" "C:\\Users\\{u}\\Documents\\{doc}"'),
    (8, "user", "C:\\Windows\\explorer.exe", PF + "Microsoft Office\\root\\Office16\\OUTLOOK.EXE", '"{img}"'),
    (6, "user", "C:\\Windows\\explorer.exe", SYS32 + "notepad.exe", '"{img}" C:\\Users\\{u}\\Documents\\notes.txt'),
    (5, "user", "C:\\Windows\\explorer.exe", PF86 + "Microsoft\\Edge\\Application\\msedge.exe", '"{img}" --single-argument https://intranet.corp.local/'),
    (5, "user", "C:\\Windows\\explorer.exe", PF + "Microsoft VS Code\\Code.exe", '"{img}" C:\\src\\service'),
    (4, "user", PF + "Microsoft VS Code\\Code.exe", PF + "Git\\cmd\\git.exe", "git.exe fetch --prune origin"),
    (3, "user", "C:\\Windows\\explorer.exe", SYS32 + "cmd.exe", '"{img}"'),
    (3, "user", SYS32 + "cmd.exe", SYS32 + "ipconfig.exe", "ipconfig /all"),
    (2, "user", SYS32 + "cmd.exe", SYS32 + "ping.exe", "ping -n 4 intranet.corp.local"),
    (20, "system", SYS32 + "services.exe", SYS32 + "svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s {svc}"),
    (6, "system", SYS32 + "svchost.exe", SYS32 + "taskhostw.exe", "taskhostw.exe {{222A245B-E637-4AE9-A93F-A59CA119A75E}}"),
    (5, "system", SYS32 + "svchost.exe", SYS32 + "wbem\\WmiPrvSE.exe", "C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding"),
    (4, "system", SYS32 + "services.exe", PF + "Windows Defender\\MsMpEng.exe", '"{img}"'),
    (4, "system", SYS32 + "svchost.exe", PF86 + "Google\\Update\\GoogleUpdate.exe", '"{img}" /ua /installsource scheduler'),
    (3, "system", SYS32 + "svchost.exe", SYS32 + "wuauclt.exe", "wuauclt.exe /RunHandlerComServer"),
    (2, "system", SYS32 + "services.exe", SYS32 + "msiexec.exe", "C:\\Windows\\system32\\msiexec.exe /V"),
    # Benign uses of tools attack rules name.
    (2, "admin", SYS32 + "cmd.exe", SYS32 + "certutil.exe", "certutil -hashfile C:\\Installers\\agent.msi SHA256"),
    (2, "admin", SYS32 + "cmd.exe", SYS32 + "certutil.exe", "certutil -store My"),
    (2, "admin", SYS32 + "svchost.exe", SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
     "powershell.exe -NoProfile -ExecutionPolicy AllSigned -File C:\\Scripts\\inventory.ps1"),
    (2, "admin", "C:\\Windows\\explorer.exe", SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -File C:\\Scripts\\Get-DiskReport.ps1"),
    (2, "user", "C:\\Windows\\explorer.exe", SYS32 + "rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL desk.cpl"),
    (1, "user", SYS32 + "svchost.exe", SYS32 + "rundll32.exe", "rundll32.exe C:\\Windows\\system32\\PcaSvc.dll,PcaPatchSdbTask"),
    (1, "admin", SYS32 + "cmd.exe", SYS32 + "net.exe", "net user /domain"),
    (1, "admin", SYS32 + "cmd.exe", SYS32 + "net.exe", "net group \"Domain Admins\" /domain"),
    (1, "admin", SYS32 + "cmd.exe", SYS32 + "tasklist.exe", "tasklist /v"),
    (1, "admin", SYS32 + "mmc.exe", SYS32 + "bcdedit.exe", "bcdedit /enum"),
    (1, "admin", "C:\\Windows\\explorer.exe", SYS32 + "mstsc.exe", "mstsc.exe /v:jump01.corp.local"),
    (1, "user", "C:\\Windows\\explorer.exe", SYS32 + "regsvr32.exe", "regsvr32.exe /s C:\\Program Files\\Vendor\\plugin.dll"),
]
SERVICES = ["Schedule", "Winmgmt", "BITS", "wuauserv", "gpsvc", "Appinfo", "ProfSvc"]

# (weight, image, port, ip generator)
CONNECTIONS = [
    (40, PF + "Google\\Chrome\\Application\\chrome.exe", 443, "public"),
    (15, PF + "Microsoft Office\\root\\Office16\\OUTLOOK.EXE", 443, "public"),
    (10, SYS32 + "svchost.exe", 443, "public"),
    (8, SYS32 + "svchost.exe", 53, "dns"),
    (6, PF86 + "Microsoft\\Edge\\Application\\msedge.exe", 443, "intranet"),
    (5, PF + "Windows Defender\\MsMpEng.exe", 443, "public"),
    (4, PF + "Git\\cmd\\git.exe", 22, "intranet"),
    (3, SYS32 + "mstsc.exe", 3389, "intranet"),
    (3, SYS32 + "svchost.exe", 445, "intranet"),
    (2, SYS32 + "svchost.exe", 80, "public"),
]


# The committed corpus's size; the seed default is 1.
EVENTS = 10000


def ip(rng: random.Random, kind: str) -> str:
    if kind == "dns":
        return "10.0.0.53"
    if kind == "intranet":
        return f"10.{rng.randint(1, 40)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    # RFC 5737 documentation ranges: public, never routed, never real.
    net = rng.choice(["192.0.2", "198.51.100", "203.0.113"])
    return f"{net}.{rng.randint(1, 254)}"


def user(rng: random.Random, kind: str) -> str:
    return {"user": rng.choice(USERS), "admin": rng.choice(ADMINS), "system": SYSTEM}[kind]


def process(rng: random.Random) -> dict:
    _, kind, parent, img, cmd = rng.choices(PROCESSES, weights=[p[0] for p in PROCESSES])[0]
    u = user(rng, kind)
    line = cmd.format(img=img, n=rng.randint(1, 900), u=u.split("\\")[-1], doc=rng.choice(HOSTS_DOCS), svc=rng.choice(SERVICES))
    return {"channel": SYSMON, "event_id": 1, "Image": img, "CommandLine": line, "ParentImage": parent, "User": u}


def connection(rng: random.Random) -> dict:
    _, img, port, kind = rng.choices(CONNECTIONS, weights=[c[0] for c in CONNECTIONS])[0]
    return {"channel": SYSMON, "event_id": 3, "Image": img, "DestinationIp": ip(rng, kind), "DestinationPort": port}


def events(n: int, seed: int = 1):
    rng = random.Random(seed)
    for _ in range(n):
        yield process(rng) if rng.random() < 0.7 else connection(rng)


def lines(n: int, seed: int = 1):
    for e in events(n, seed):
        yield json.dumps(e, separators=(",", ":"))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("out")
    p.add_argument("--events", type=int, default=EVENTS)
    p.add_argument("--seed", type=int, default=1)
    args = p.parse_args(argv)
    with open(args.out, "w", encoding="utf-8") as f:
        f.writelines(line + "\n" for line in lines(args.events, args.seed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
