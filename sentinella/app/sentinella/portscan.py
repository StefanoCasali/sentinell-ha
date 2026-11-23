"""Scansione TCP (connect scan) di un elenco mirato di porte."""

import asyncio

# Porte che su una rete domestica indicano un servizio da valutare.
PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 81: "http",
    111: "rpcbind", 139: "netbios", 443: "https", 445: "smb", 548: "afp", 554: "rtsp",
    631: "ipp", 873: "rsync", 1433: "mssql", 1723: "pptp", 1883: "mqtt", 2049: "nfs",
    2323: "telnet", 2375: "docker", 2376: "docker-tls", 3000: "http", 3306: "mysql",
    3389: "rdp", 5000: "http", 5001: "https", 5060: "sip", 5432: "postgresql",
    5555: "adb", 5900: "vnc", 5901: "vnc", 6379: "redis", 7547: "tr-069", 8000: "http",
    8006: "https", 8080: "http", 8081: "http", 8123: "http", 8291: "winbox",
    8443: "https", 8883: "mqtts", 8888: "http", 9000: "http", 9090: "http",
    9100: "jetdirect", 9200: "elasticsearch", 10000: "https", 11211: "memcached",
    27017: "mongodb", 34567: "dvr", 37777: "dvr",
}

CONNECT_TIMEOUT = 1.5
MAX_PARALLEL = 256


async def _check(ip: str, port: int, sem: asyncio.Semaphore) -> bool:
    async with sem:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), CONNECT_TIMEOUT)
        except (OSError, asyncio.TimeoutError):
            return False
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True


async def _scan(ips: list[str], ports: list[int]) -> dict[str, list[int]]:
    sem = asyncio.Semaphore(MAX_PARALLEL)
    pairs = [(ip, port) for ip in ips for port in ports]
    results = await asyncio.gather(*(_check(ip, port, sem) for ip, port in pairs))
    found: dict[str, list[int]] = {ip: [] for ip in ips}
    for (ip, port), is_open in zip(pairs, results):
        if is_open:
            found[ip].append(port)
    return found


def scan(ips: list[str], extra_ports=()) -> dict[str, list[int]]:
    ports = sorted(set(PORTS) | {int(p) for p in extra_ports if 0 < int(p) < 65536})
    return asyncio.run(_scan(ips, ports))
