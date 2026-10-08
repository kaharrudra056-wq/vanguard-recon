"""
Integration test for asynchronous port scanner with mock TCP server.
"""

import asyncio
import pytest
from vanguard.core.scanner import AsyncPortScanner


async def handle_client(reader, writer):
    writer.write(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-Test\r\n")
    await writer.drain()
    writer.close()
    await writer.wait_closed()


@pytest.mark.asyncio
async def test_async_port_scanner_mock():
    # Spin up dynamic mock TCP server
    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    assigned_port = server.sockets[0].getsockname()[1]

    async with server:
        # Scan the mock server port + a closed port (64999)
        scanner = AsyncPortScanner(
            target_ip="127.0.0.1",
            ports=[assigned_port, 64999],
            timeout=1.0,
            concurrency=2,
            banner_grab=True
        )
        results = await scanner.run()

        # The mock port must be identified as open with grabbed banner
        open_ports = [r for r in results if r.port == assigned_port]
        assert len(open_ports) == 1
        assert open_ports[0].state == "open"
        assert "OpenSSH_8.2p1" in open_ports[0].banner
