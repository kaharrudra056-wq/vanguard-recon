"""
VanguardRecon Simulated Vulnerable Service Lab.

Spins up lightweight mock services mimicking real-world vulnerable server banners
for safe, offline testing and portfolio interview demonstrations.
"""

import asyncio
import sys

# Windows stdout encoding check
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


async def handle_ssh(reader, writer):
    writer.write(b"SSH-2.0-OpenSSH_8.5p1 Ubuntu-3ubuntu0.1\r\n")
    await writer.drain()
    await asyncio.sleep(0.5)
    writer.close()
    await writer.wait_closed()


async def handle_proftpd(reader, writer):
    writer.write(b"220 ProFTPD 1.3.5 Server (Ubuntu ProFTPD Default Installation)\r\n")
    await writer.drain()
    await asyncio.sleep(0.5)
    writer.close()
    await writer.wait_closed()


async def handle_apache(reader, writer):
    data = await reader.read(1024)
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Date: Thu, 08 Oct 2026 22:00:00 GMT\r\n"
        b"Server: Apache/2.4.49 (Unix) OpenSSL/1.1.1d\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: 45\r\n"
        b"\r\n"
        b"<html><body><h1>Apache Test Site</h1></body></html>"
    )
    writer.write(response)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def main():
    print("[+] Starting VanguardRecon Local Demo Lab...")

    ssh_server = await asyncio.start_server(handle_ssh, "127.0.0.1", 2222)
    print("    -> Port 2222: Mock OpenSSH 8.5p1 (CVE-2024-6387 regreSSHion)")

    ftp_server = await asyncio.start_server(handle_proftpd, "127.0.0.1", 2121)
    print("    -> Port 2121: Mock ProFTPD 1.3.5 (CVE-2015-3306 mod_copy RCE)")

    http_server = await asyncio.start_server(handle_apache, "127.0.0.1", 8088)
    print("    -> Port 8088: Mock Apache 2.4.49 (CVE-2021-41773 Path Traversal / RCE)")

    print("\n[+] Lab is running! Run the scan in another terminal:")
    print("    python -m vanguard scan 127.0.0.1 -p '2121,2222,8088' --html reports/demo_report.html\n")
    print("[*] Press Ctrl+C to terminate the lab.")

    async with ssh_server, ftp_server, http_server:
        await asyncio.gather(
            ssh_server.serve_forever(),
            ftp_server.serve_forever(),
            http_server.serve_forever()
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Lab terminated.")
