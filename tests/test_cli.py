"""Tests for socketry.cli — watch command."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from socketry.cli import app
from socketry.client import Client, Subscription

runner = CliRunner()


MOCK_CREDS: dict[str, Any] = {
    "userId": "U001",
    "macId": "aa:bb:cc:dd:ee:ff",
    "mqttPassWord": "bXF0dHB3ZGVyaXZlZGtleQ==",
    "deviceSn": "SN001",
    "deviceId": "DEV001",
    "deviceName": "My Station",
    "token": "tok",
}


def _make_subscribe_mock(
    messages: list[tuple[str, dict[str, object]]],
    *,
    disconnects: int = 0,
) -> AsyncMock:
    """Create a mock ``Client.subscribe`` that delivers messages then stops.

    *messages* is a list of ``(device_sn, properties)`` tuples that will be
    passed to the callback before the subscription completes.  If *disconnects*
    is non-zero, ``on_disconnect`` is called that many times before delivering
    messages.
    """

    async def fake_subscribe(
        callback: Any,
        *,
        on_disconnect: Any = None,
    ) -> Subscription:
        async def run() -> None:
            for _ in range(disconnects):
                if on_disconnect is not None:
                    await on_disconnect()
            for sn, props in messages:
                await callback(sn, props)

        task = asyncio.get_event_loop().create_task(run())
        return Subscription(task)

    return AsyncMock(side_effect=fake_subscribe)


class TestWatchCommand:
    def test_displays_formatted_updates(self):
        subscribe_mock = _make_subscribe_mock(
            [
                ("SN001", {"oac": 1}),
                ("SN002", {"rb": 85}),
            ]
        )

        with (
            patch.object(Client, "from_saved", return_value=Client(MOCK_CREDS)),
            patch.object(Client, "subscribe", subscribe_mock),
        ):
            result = runner.invoke(app, ["watch"])

        assert result.exit_code == 0
        assert "SN001" in result.output
        assert "AC output (ac)" in result.output
        assert "SN002" in result.output
        assert "Battery (battery)" in result.output
        assert "85%" in result.output

    def test_filters_by_property_name(self):
        subscribe_mock = _make_subscribe_mock(
            [
                ("SN001", {"oac": 1, "rb": 90}),
            ]
        )

        with (
            patch.object(Client, "from_saved", return_value=Client(MOCK_CREDS)),
            patch.object(Client, "subscribe", subscribe_mock),
        ):
            result = runner.invoke(app, ["watch", "battery"])

        assert result.exit_code == 0
        assert "Battery (battery)" in result.output
        assert "90%" in result.output
        # AC output should be filtered out
        assert "AC output" not in result.output

    def test_unknown_property_error(self):
        with patch.object(Client, "from_saved", return_value=Client(MOCK_CREDS)):
            result = runner.invoke(app, ["watch", "nonexistent"])

        assert result.exit_code == 1
        assert "Unknown property" in result.output

    def test_shows_raw_key_for_unknown_property(self):
        subscribe_mock = _make_subscribe_mock(
            [
                ("SN001", {"xyz_unknown": 42}),
            ]
        )

        with (
            patch.object(Client, "from_saved", return_value=Client(MOCK_CREDS)),
            patch.object(Client, "subscribe", subscribe_mock),
        ):
            result = runner.invoke(app, ["watch"])

        assert result.exit_code == 0
        assert "xyz_unknown" in result.output
        assert "42" in result.output

    def test_displays_watching_message(self):
        subscribe_mock = _make_subscribe_mock([])

        with (
            patch.object(Client, "from_saved", return_value=Client(MOCK_CREDS)),
            patch.object(Client, "subscribe", subscribe_mock),
        ):
            result = runner.invoke(app, ["watch"])

        assert result.exit_code == 0
        assert "Watching for property updates" in result.output

    def test_displays_watching_message_with_filter(self):
        subscribe_mock = _make_subscribe_mock([])

        with (
            patch.object(Client, "from_saved", return_value=Client(MOCK_CREDS)),
            patch.object(Client, "subscribe", subscribe_mock),
        ):
            result = runner.invoke(app, ["watch", "battery"])

        assert result.exit_code == 0
        assert "Watching Battery" in result.output

    def test_shows_reconnecting_notice_on_disconnect(self):
        subscribe_mock = _make_subscribe_mock([], disconnects=1)

        with (
            patch.object(Client, "from_saved", return_value=Client(MOCK_CREDS)),
            patch.object(Client, "subscribe", subscribe_mock),
        ):
            result = runner.invoke(app, ["watch"])

        assert result.exit_code == 0
        assert "Disconnected, reconnecting" in result.output
