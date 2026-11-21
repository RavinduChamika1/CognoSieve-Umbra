"""Tests for network discovery port scanner."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from umbra.discovery.network import check_port_open, scan_targets


@pytest.mark.asyncio
async def test_check_port_open_success():
    mock_writer = MagicMock()
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()

    async def fake_open(host, port):
        return (MagicMock(), mock_writer)

    with patch("umbra.discovery.network.asyncio.open_connection", side_effect=fake_open):
        is_open = await check_port_open("127.0.0.1", 11434, timeout=1.0)
        assert is_open is True
        mock_writer.close.assert_called_once()


@pytest.mark.asyncio
async def test_check_port_open_refused():
    with patch("umbra.discovery.network.asyncio.open_connection", side_effect=ConnectionRefusedError("Connection refused")):
        is_open = await check_port_open("127.0.0.1", 9999, timeout=1.0)
        assert is_open is False


@pytest.mark.asyncio
async def test_scan_targets():
    async def fake_check(host, port, timeout):
        return host == "127.0.0.1" and port == 11434

    with patch("umbra.discovery.network.check_port_open", side_effect=fake_check):
        open_endpoints = await scan_targets(["127.0.0.1", "127.0.0.2"], [11434, 8000], concurrency=2, timeout=1.0)
        assert len(open_endpoints) == 1
        assert open_endpoints[0] == ("127.0.0.1", 11434)
