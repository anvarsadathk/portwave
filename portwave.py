#!/usr/bin/env python3
"""
portwave - fast asyncio TCP port scanner with banner grabbing.

TCP connect scan (no raw sockets / root needed). Supports port ranges,
named top-ports sets, concurrency control, and light banner grabbing.

Author: Anvar Sadath K.  |  License: MIT
Active tool — scan only hosts you own or are explicitly authorized to test.
"""
import argparse
import asyncio
import ipaddress
import socket
import sys

TOP_100 = [7,20,21,22,23,25,53,67,68,69,80,110,111,123,135,137,138,139,143,161,
           162,179,389,443,445,465,500,514,515,520,587,631,636,873,990,993,995,
           1080,1194,1433,1434,1521,1723,2049,2082,2083,2086,2087,2095,2096,2181,
           2222,2375,2376,3000,3128,3268,3306,3389,3690,4444,4567,4848,5000,5432,
           5555,5601,5672,5900,5984,6000,6379,6443,6660,6667,7001,7077,7199,8000,
           8008,8009,8080,8081,8088,8089,8161,8443,8500,8888,9000,9042,9090,9092,
           9200,9300,9418,9999,10000,11211,27017]

COMMON_SVC = {22:"ssh",80:"http",443:"https",21:"ftp",25:"smtp",3306:"mysql",
              5432:"postgres",6379:"redis",27017:"mongodb",3389:"rdp",
              9200:"elasticsearch",11211:"memcached",8080:"http-alt"}


def parse_ports(spec: str):
    if spec == "top100":
        return TOP_100
    if spec == "all":
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


async def scan_port(host, port, timeout, grab, sem):
    async with sem:
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        except Exception:
            return None
        banner = ""
        if grab:
            try:
                if port in (80, 8080, 8000, 8888):
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                data = await asyncio.wait_for(reader.read(128), timeout=2)
                banner = data.decode("utf-8", "replace").strip().split("\n")[0][:80]
            except Exception:
                pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return port, banner


async def run(host, ports, timeout, concurrency, grab):
    sem = asyncio.Semaphore(concurrency)
    tasks = [scan_port(host, p, timeout, grab, sem) for p in ports]
    open_ports = []
    for coro in asyncio.as_completed(tasks):
        res = await coro
        if res:
            port, banner = res
            svc = COMMON_SVC.get(port, "")
            line = f"{host}:{port} open  {svc}{('  | ' + banner) if banner else ''}".rstrip()
            print(line)
            open_ports.append((port, svc, banner))
    return open_ports


def main():
    p = argparse.ArgumentParser(description="Async TCP port scanner.")
    p.add_argument("host", help="target host or IP")
    p.add_argument("-p", "--ports", default="top100",
                   help="'top100', 'all', '1-1024', or '22,80,443' (default: top100)")
    p.add_argument("-c", "--concurrency", type=int, default=500)
    p.add_argument("-T", "--timeout", type=float, default=1.5)
    p.add_argument("-b", "--banner", action="store_true", help="attempt banner grab")
    p.add_argument("-o", "--output", help="write open ports to file")
    p.add_argument("--yes-authorized", action="store_true",
                   help="confirm you are authorized to scan this host")
    args = p.parse_args()

    if not args.yes_authorized:
        print("[!] portwave performs an active scan. Re-run with --yes-authorized "
              "to confirm the host is in scope.", file=sys.stderr)
        sys.exit(2)

    try:
        host = socket.gethostbyname(args.host)
    except Exception as e:
        print(f"[!] cannot resolve {args.host}: {e}", file=sys.stderr)
        sys.exit(1)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass

    ports = parse_ports(args.ports)
    print(f"[*] Scanning {args.host} ({host}) — {len(ports)} ports, "
          f"concurrency={args.concurrency}", file=sys.stderr)
    results = asyncio.run(run(host, ports, args.timeout, args.concurrency, args.banner))
    print(f"[+] {len(results)} open port(s).", file=sys.stderr)

    if args.output and results:
        with open(args.output, "w") as f:
            for port, svc, banner in sorted(results):
                f.write(f"{host}:{port} {svc} {banner}\n".rstrip() + "\n")
        print(f"[+] Saved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
