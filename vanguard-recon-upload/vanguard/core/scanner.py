"""
High-Performance Asynchronous TCP Port Scanner & Banner Grabber.

Utilizes asyncio non-blocking multiplexing with bounded concurrency semaphores
to achieve high-speed, reliable scanning without socket descriptor exhaustion.
"""

import asyncio
import time
from typing import List, Optional, Callable
from pydantic import BaseModel, Field


class PortResult(BaseModel):
    """Result of probing an individual port."""
    port: int
    state: str = "closed"  # "open", "closed", "filtered"
    service: str = "unknown"
    banner: str = ""
    latency_ms: float = 0.0


class ScanSummary(BaseModel):
    """Consolidated summary of a port scan operation."""
    target_host: str
    target_ip: str
    is_private: bool
    total_ports_scanned: int
    open_ports_count: int
    open_ports: List[PortResult] = Field(default_factory=list)
    duration_seconds: float = 0.0


# Well-known port to service heuristic mapping
KNOWN_PORT_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds (smb)",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    2049: "nfs",
    2181: "zookeeper",
    2222: "ssh-alt",
    2375: "docker",
    2376: "docker-tls",
    3000: "http-alt (node/react)",
    3306: "mysql",
    3389: "ms-wbt-server (rdp)",
    5000: "http-alt (flask/dev)",
    5432: "postgresql",
    5672: "rabbitmq",
    5900: "vnc",
    6379: "redis",
    6443: "kubernetes-api",
    7001: "weblogic",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt (jupyter)",
    9000: "http-alt (sonar/s3)",
    9092: "kafka",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb"
}


class AsyncPortScanner:
    """Non-blocking TCP port scanner with semaphore-controlled concurrency."""

    def __init__(
        self,
        target_ip: str,
        ports: List[int],
        timeout: float = 1.5,
        concurrency: int = 50,
        banner_grab: bool = True
    ):
        self.target_ip = target_ip
        self.ports = sorted(list(set(ports)))
        self.timeout = timeout
        self.concurrency = concurrency
        self.banner_grab = banner_grab
        self.semaphore = asyncio.Semaphore(concurrency)

    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> str:
        """Attempts to read banner or send protocol-specific probe."""
        banner = ""
        try:
            # For HTTP ports, send a quick HEAD request
            if port in (80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000):
                probe = b"HEAD / HTTP/1.0\r\nUser-Agent: VanguardRecon/1.0\r\n\r\n"
                writer.write(probe)
                await asyncio.wait_for(writer.drain(), timeout=1.0)
            elif port in (21, 22, 25, 110, 143):
                # FTP, SSH, SMTP usually send a welcome banner immediately
                pass
            elif port == 6379:
                writer.write(b"PING\r\n")
                await asyncio.wait_for(writer.drain(), timeout=1.0)
            else:
                writer.write(b"\r\n")
                await asyncio.wait_for(writer.drain(), timeout=1.0)

            # Read up to 1024 bytes
            data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            if data:
                # Clean up banner text
                banner = data.decode("utf-8", errors="replace").strip()
                # Truncate if overly long
                if len(banner) > 300:
                    banner = banner[:300] + "..."
        except Exception:
            pass
        return banner

    async def probe_port(
        self,
        port: int,
        progress_callback: Optional[Callable[[int, bool], None]] = None
    ) -> PortResult:
        """Probes a single TCP port."""
        async with self.semaphore:
            start_time = time.perf_counter()
            service_name = KNOWN_PORT_MAP.get(port, "unknown")
            try:
                # Attempt non-blocking TCP connect
                connect_coro = asyncio.open_connection(self.target_ip, port)
                reader, writer = await asyncio.wait_for(connect_coro, timeout=self.timeout)
                latency = round((time.perf_counter() - start_time) * 1000, 2)

                banner = ""
                if self.banner_grab:
                    banner = await self._grab_banner(reader, writer, port)

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                result = PortResult(
                    port=port,
                    state="open",
                    service=service_name,
                    banner=banner,
                    latency_ms=latency
                )

                if progress_callback:
                    progress_callback(port, True)
                return result

            except (asyncio.TimeoutError, TimeoutError):
                if progress_callback:
                    progress_callback(port, False)
                return PortResult(port=port, state="filtered", service=service_name)
            except (ConnectionRefusedError, OSError):
                if progress_callback:
                    progress_callback(port, False)
                return PortResult(port=port, state="closed", service=service_name)
            except Exception:
                if progress_callback:
                    progress_callback(port, False)
                return PortResult(port=port, state="closed", service=service_name)

    async def run(
        self,
        progress_callback: Optional[Callable[[int, bool], None]] = None
    ) -> List[PortResult]:
        """Runs the scan across all configured ports concurrently."""
        tasks = [self.probe_port(port, progress_callback) for port in self.ports]
        results = await asyncio.gather(*tasks)
        # Filter for open ports
        open_results = [r for r in results if r.state == "open"]
        open_results.sort(key=lambda x: x.port)
        return open_results
