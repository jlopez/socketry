"""Tests for socketry.client."""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import ssl
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from aioresponses import aioresponses

from socketry._constants import API_BASE, MQTT_HOST, MQTT_PORT
from socketry.client import (
    Client,
    Device,
    MqttError,
    Subscription,
    TokenExpiredError,
    _build_command_payload,
    _decode_jwt_exp,
    _fetch_all_devices,
    _fetch_device_properties,
    _http_login,
    _make_tls_context,
    _mqtt_params,
    _parse_device_update,
    _resolve_value,
)
from socketry.properties import Setting

# Regex patterns for URL matching (aioresponses needs to match full URL with query params)
_LOGIN_URL = re.compile(rf"^{re.escape(API_BASE)}/auth/login")
_PROPERTY_URL = re.compile(rf"^{re.escape(API_BASE)}/device/property")


# ---------------------------------------------------------------------------
# Pure function tests (sync, no mocking needed)
# ---------------------------------------------------------------------------


class TestResolveValue:
    def test_int_passthrough(self):
        s = Setting("oac", "ac", "AC output", "io", action_id=4, values=["off", "on"])
        assert _resolve_value(s, 1) == 1

    def test_named_value_on(self):
        s = Setting("oac", "ac", "AC output", "io", action_id=4, values=["off", "on"])
        assert _resolve_value(s, "on") == 1

    def test_named_value_off(self):
        s = Setting("oac", "ac", "AC output", "io", action_id=4, values=["off", "on"])
        assert _resolve_value(s, "off") == 0

    def test_invalid_named_value(self):
        s = Setting("oac", "ac", "AC output", "io", action_id=4, values=["off", "on"])
        with pytest.raises(ValueError, match="Invalid value 'maybe'"):
            _resolve_value(s, "maybe")

    def test_string_int_without_values(self):
        s = Setting("ast", "auto-shutdown", "Auto shutdown", "settings", action_id=9)
        assert _resolve_value(s, "30") == 30

    def test_invalid_string_without_values(self):
        s = Setting("ast", "auto-shutdown", "Auto shutdown", "settings", action_id=9)
        with pytest.raises(ValueError, match="Expected an integer"):
            _resolve_value(s, "abc")


class TestBuildCommandPayload:
    def test_payload_structure(self):
        payload = _build_command_payload("SN123", 4, {"oac": 1})
        data = json.loads(payload)
        assert data["deviceSn"] == "SN123"
        assert data["actionId"] == 4
        assert data["body"] == {"oac": 1}
        assert data["messageType"] == "DevicePropertyChange"
        assert data["version"] == 0
        assert isinstance(data["id"], int)
        assert isinstance(data["timestamp"], int)

    def test_no_spaces_in_json(self):
        payload = _build_command_payload("SN", 1, {"x": 1})
        assert " " not in payload


# ---------------------------------------------------------------------------
# Async HTTP tests (mocked with aioresponses)
# ---------------------------------------------------------------------------


MOCK_OWNED_DEVICE: dict[str, Any] = {
    "devSn": "SN001",
    "devNickname": "My Power Station",
    "devName": "Explorer 2000 Plus",
    "devId": "DEV001",
    "modelCode": 2,
}

MOCK_SHARED_DATA: dict[str, Any] = {
    "receive": [{"bindUserId": 999, "level": 1, "userName": "friend@example.com"}]
}

MOCK_SHARED_DEVICE: dict[str, Any] = {
    "devSn": "SN002",
    "devNickname": "Shared Station",
    "devName": "Explorer 1000 Plus",
    "devId": "DEV002",
    "modelCode": 5,
}


def _mock_device_endpoints(
    m: aioresponses,
    *,
    owned: list[dict[str, Any]] | None = None,
    shared_data: dict[str, Any] | None = None,
    share_list: list[dict[str, Any]] | None = None,
) -> None:
    """Register mock responses for device list endpoints."""
    m.get(f"{API_BASE}/device/bind/list", payload={"data": owned or []})
    m.get(f"{API_BASE}/device/bind/shared", payload={"data": shared_data or {}})
    if share_list is not None:
        m.post(f"{API_BASE}/device/bind/share/list", payload={"data": share_list})


class TestFetchAllDevices:
    async def test_owned_only(self):
        with aioresponses() as m:
            _mock_device_endpoints(m, owned=[MOCK_OWNED_DEVICE])
            async with aiohttp.ClientSession() as session:
                devices = await _fetch_all_devices("fake-token", session)

        assert len(devices) == 1
        assert devices[0]["devSn"] == "SN001"
        assert devices[0]["devName"] == "My Power Station"
        assert devices[0]["shared"] is False

    async def test_owned_plus_shared(self):
        with aioresponses() as m:
            _mock_device_endpoints(
                m,
                owned=[MOCK_OWNED_DEVICE],
                shared_data=MOCK_SHARED_DATA,
                share_list=[MOCK_SHARED_DEVICE],
            )
            async with aiohttp.ClientSession() as session:
                devices = await _fetch_all_devices("fake-token", session)

        assert len(devices) == 2
        assert devices[0]["shared"] is False
        assert devices[1]["shared"] is True
        assert devices[1]["sharedBy"] == "friend@example.com"
        assert devices[1]["devSn"] == "SN002"

    async def test_deduplication(self):
        dupe = {**MOCK_SHARED_DEVICE, "devSn": "SN001"}
        with aioresponses() as m:
            _mock_device_endpoints(
                m,
                owned=[MOCK_OWNED_DEVICE],
                shared_data=MOCK_SHARED_DATA,
                share_list=[dupe],
            )
            async with aiohttp.ClientSession() as session:
                devices = await _fetch_all_devices("fake-token", session)

        assert len(devices) == 1

    async def test_empty_lists(self):
        with aioresponses() as m:
            _mock_device_endpoints(m)
            async with aiohttp.ClientSession() as session:
                devices = await _fetch_all_devices("fake-token", session)

        assert devices == []

    async def test_http_error_propagates(self):
        with aioresponses() as m:
            m.get(f"{API_BASE}/device/bind/list", status=500)
            async with aiohttp.ClientSession() as session:
                with pytest.raises(aiohttp.ClientResponseError):
                    await _fetch_all_devices("fake-token", session)

    async def test_nickname_fallback_to_devname(self):
        dev: dict[str, Any] = {
            **MOCK_OWNED_DEVICE,
            "devNickname": None,
            "devName": "Fallback Name",
        }
        with aioresponses() as m:
            _mock_device_endpoints(m, owned=[dev])
            async with aiohttp.ClientSession() as session:
                devices = await _fetch_all_devices("fake-token", session)

        assert devices[0]["devName"] == "Fallback Name"

    async def test_nickname_fallback_to_sn(self):
        dev: dict[str, Any] = {"devSn": "SN999", "devId": "D1", "modelCode": 1}
        with aioresponses() as m:
            _mock_device_endpoints(m, owned=[dev])
            async with aiohttp.ClientSession() as session:
                devices = await _fetch_all_devices("fake-token", session)

        assert devices[0]["devName"] == "SN999"


class TestFetchDeviceProperties:
    async def test_success(self):
        mock_props: dict[str, Any] = {
            "device": {"onlineStatus": 1},
            "properties": {"rb": 85, "oac": 1},
        }
        with aioresponses() as m:
            m.get(_PROPERTY_URL, payload={"code": 0, "data": mock_props})
            async with aiohttp.ClientSession() as session:
                result = await _fetch_device_properties("fake-token", "DEV001", session)

        props = result["properties"]
        assert isinstance(props, dict)
        assert props["rb"] == 85

    async def test_api_error_code(self):
        with aioresponses() as m:
            m.get(_PROPERTY_URL, payload={"code": 10600, "msg": "Auth failed"})
            async with aiohttp.ClientSession() as session:
                with pytest.raises(RuntimeError, match="Property fetch failed"):
                    await _fetch_device_properties("fake-token", "DEV001", session)

    async def test_http_error(self):
        with aioresponses() as m:
            m.get(_PROPERTY_URL, status=401)
            async with aiohttp.ClientSession() as session:
                with pytest.raises(aiohttp.ClientResponseError):
                    await _fetch_device_properties("fake-token", "DEV001", session)

    async def test_empty_data(self):
        with aioresponses() as m:
            m.get(_PROPERTY_URL, payload={"code": 0, "data": None})
            async with aiohttp.ClientSession() as session:
                result = await _fetch_device_properties("fake-token", "DEV001", session)

        assert result == {}


class TestHttpLogin:
    async def test_successful_login(self):
        login_response = {
            "code": 0,
            "token": "jwt-token-123",
            "data": {"userId": "U001", "mqttPassWord": "bXF0dHB3"},
        }
        with aioresponses() as m:
            m.post(_LOGIN_URL, payload=login_response)
            _mock_device_endpoints(m, owned=[MOCK_OWNED_DEVICE])

            creds = await _http_login("test@example.com", "password123")

        assert creds["token"] == "jwt-token-123"
        assert creds["userId"] == "U001"
        assert creds["email"] == "test@example.com"
        assert creds["deviceSn"] == "SN001"
        assert creds["deviceId"] == "DEV001"
        devices = creds["devices"]
        assert isinstance(devices, list) and len(devices) == 1

    async def test_login_no_devices(self):
        login_response = {
            "code": 0,
            "token": "jwt-token-123",
            "data": {"userId": "U001", "mqttPassWord": "bXF0dHB3"},
        }
        with aioresponses() as m:
            m.post(_LOGIN_URL, payload=login_response)
            _mock_device_endpoints(m)

            creds = await _http_login("test@example.com", "password123")

        assert creds["deviceSn"] == ""
        assert creds["deviceId"] == ""
        assert creds["devices"] == []

    async def test_login_failure_code(self):
        with aioresponses() as m:
            m.post(_LOGIN_URL, payload={"code": 1, "msg": "Bad credentials"})
            with pytest.raises(RuntimeError, match="Login failed: Bad credentials"):
                await _http_login("bad@example.com", "wrong")

    async def test_login_http_error(self):
        with aioresponses() as m:
            m.post(_LOGIN_URL, status=500)
            with pytest.raises(aiohttp.ClientResponseError):
                await _http_login("test@example.com", "password")


# ---------------------------------------------------------------------------
# Client method tests
# ---------------------------------------------------------------------------


class TestClientProperties:
    def test_user_id_present(self):
        client = Client({"userId": "U42"})
        assert client.user_id == "U42"

    def test_user_id_missing_returns_empty_string(self):
        client = Client({})
        assert client.user_id == ""

    def test_user_id_converts_non_string(self):
        client = Client({"userId": 12345})
        assert client.user_id == "12345"


class TestClientLogin:
    async def test_returns_client(self):
        login_response = {
            "code": 0,
            "token": "jwt-123",
            "data": {"userId": "U001", "mqttPassWord": "bXF0dHB3"},
        }
        with aioresponses() as m:
            m.post(_LOGIN_URL, payload=login_response)
            _mock_device_endpoints(m, owned=[MOCK_OWNED_DEVICE])

            client = await Client.login("test@example.com", "pass")

        assert isinstance(client, Client)
        assert client.token == "jwt-123"
        assert client.device_sn == "SN001"


class TestClientFetchDevices:
    async def test_updates_cache(self):
        client = Client({"token": "tok", "devices": []})
        with aioresponses() as m:
            _mock_device_endpoints(m, owned=[MOCK_OWNED_DEVICE])
            result = await client.fetch_devices()

        assert len(result) == 1
        assert client.devices == result
        assert result[0]["devSn"] == "SN001"


class TestClientGetAllProperties:
    async def test_success(self):
        client = Client({"token": "tok", "deviceId": "DEV001"})
        mock_data: dict[str, Any] = {"properties": {"rb": 90}}
        with aioresponses() as m:
            m.get(_PROPERTY_URL, payload={"code": 0, "data": mock_data})
            result = await client.get_all_properties()

        props = result["properties"]
        assert isinstance(props, dict)
        assert props["rb"] == 90

    async def test_no_device_id(self):
        client = Client({"token": "tok"})
        with pytest.raises(ValueError, match="No deviceId"):
            await client.get_all_properties()


class TestClientGetProperty:
    async def test_known_property(self):
        client = Client({"token": "tok", "deviceId": "DEV001"})
        mock_data: dict[str, Any] = {"properties": {"rb": 85}}
        with aioresponses() as m:
            m.get(_PROPERTY_URL, payload={"code": 0, "data": mock_data})
            setting, value = await client.get_property("battery")

        assert setting.id == "rb"
        assert value == 85

    async def test_unknown_property(self):
        client = Client({"token": "tok", "deviceId": "DEV001"})
        with pytest.raises(KeyError, match="Unknown property"):
            await client.get_property("nonexistent")

    async def test_property_not_in_device_data(self):
        client = Client({"token": "tok", "deviceId": "DEV001"})
        mock_data: dict[str, Any] = {"properties": {"rb": 85}}
        with aioresponses() as m:
            m.get(_PROPERTY_URL, payload={"code": 0, "data": mock_data})
            with pytest.raises(KeyError, match="not reported by device"):
                await client.get_property("ac")


class TestClientSelectDevice:
    def test_select_valid(self):
        devs: list[dict[str, Any]] = [
            {"devSn": "SN001", "devId": "D1", "devName": "First"},
            {"devSn": "SN002", "devId": "D2", "devName": "Second"},
        ]
        client = Client({"devices": devs, "deviceSn": "", "deviceId": "", "deviceName": ""})
        dev = client.select_device(1)
        assert dev["devSn"] == "SN002"
        assert client.device_sn == "SN002"
        assert client.device_id == "D2"

    def test_select_no_devices(self):
        client = Client({"devices": []})
        with pytest.raises(IndexError, match="No cached device list"):
            client.select_device(0)

    def test_select_out_of_range(self):
        client = Client({"devices": [{"devSn": "SN1", "devId": "D1", "devName": "One"}]})
        with pytest.raises(IndexError, match="Invalid index"):
            client.select_device(5)


class TestClientDevice:
    def _client_with_devices(self) -> Client:
        return Client(
            {
                "token": "tok",
                "devices": [
                    {"devSn": "SN001", "devId": "DEV001", "devName": "First", "modelCode": 2},
                    {"devSn": "SN002", "devId": "DEV002", "devName": "Second", "modelCode": 5},
                ],
            }
        )

    def test_device_by_index(self):
        client = self._client_with_devices()
        dev = client.device(0)
        assert isinstance(dev, Device)
        assert dev.sn == "SN001"
        assert dev.name == "First"
        assert dev.model_code == 2

    def test_device_by_sn(self):
        client = self._client_with_devices()
        dev = client.device("SN002")
        assert isinstance(dev, Device)
        assert dev.sn == "SN002"
        assert dev.device_id == "DEV002"

    def test_device_index_out_of_range(self):
        client = self._client_with_devices()
        with pytest.raises(IndexError, match="Invalid index"):
            client.device(5)

    def test_device_sn_not_found(self):
        client = self._client_with_devices()
        with pytest.raises(KeyError, match="No device with SN"):
            client.device("UNKNOWN")

    def test_device_no_cache(self):
        client = Client({"token": "tok", "devices": []})
        with pytest.raises(IndexError, match="No cached device list"):
            client.device(0)

    def test_device_sn_empty_cache_raises_key_error(self):
        """device() with a string SN raises KeyError (not IndexError) when list is empty."""
        client = Client({"token": "tok", "devices": []})
        with pytest.raises(KeyError, match="SN-MISSING"):
            client.device("SN-MISSING")


class TestClientFromSaved:
    def test_no_credentials_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr("socketry.client.CRED_FILE", tmp_path / "nonexistent.json")
        with pytest.raises(FileNotFoundError, match="No saved credentials"):
            Client.from_saved()

    def test_loads_credentials(self, tmp_path, monkeypatch):
        cred_file = tmp_path / "credentials.json"
        cred_file.write_text(json.dumps({"token": "saved-tok", "deviceSn": "SN999"}))
        monkeypatch.setattr("socketry.client.CRED_FILE", cred_file)
        client = Client.from_saved()
        assert client.token == "saved-tok"
        assert client.device_sn == "SN999"


class TestClientSaveCredentials:
    def test_save_and_permissions(self, tmp_path, monkeypatch):
        cred_dir = tmp_path / "config"
        cred_file = cred_dir / "credentials.json"
        monkeypatch.setattr("socketry.client.CRED_DIR", cred_dir)
        monkeypatch.setattr("socketry.client.CRED_FILE", cred_file)

        client = Client({"token": "t", "deviceSn": "SN"})
        client.save_credentials()

        assert cred_file.exists()
        data = json.loads(cred_file.read_text())
        assert data["token"] == "t"
        assert (cred_file.stat().st_mode & 0o777) == 0o600


# ---------------------------------------------------------------------------
# MQTT tests
# ---------------------------------------------------------------------------


MOCK_CREDS: dict[str, object] = {
    "userId": "U001",
    "macId": "aa:bb:cc:dd:ee:ff",
    "mqttPassWord": "bXF0dHB3ZGVyaXZlZGtleQ==",
    "deviceSn": "SN001",
    "deviceId": "DEV001",
    "token": "tok",
}


class TestMakeTlsContext:
    def test_returns_ssl_context(self):
        ctx = _make_tls_context()
        assert isinstance(ctx, ssl.SSLContext)

    def test_ca_cert_loaded(self):
        ctx = _make_tls_context()
        # The context should have at least one CA cert loaded
        stats = ctx.cert_store_stats()
        assert stats["x509_ca"] >= 1


class TestMqttParams:
    def test_hostname_and_port(self):
        params = _mqtt_params(MOCK_CREDS)
        assert params["hostname"] == MQTT_HOST
        assert params["port"] == MQTT_PORT

    def test_identifier(self):
        params = _mqtt_params(MOCK_CREDS)
        assert params["identifier"] == "U001@APP"

    def test_username(self):
        params = _mqtt_params(MOCK_CREDS)
        assert params["username"] == "U001@aa:bb:cc:dd:ee:ff"

    def test_password_is_derived(self):
        params = _mqtt_params(MOCK_CREDS)
        # Password should be a non-empty base64 string (derived from username + mqttPassWord)
        pw = params["password"]
        assert isinstance(pw, str) and len(pw) > 0

    def test_tls_context_present(self):
        params = _mqtt_params(MOCK_CREDS)
        assert isinstance(params["tls_context"], ssl.SSLContext)

    def test_keepalive(self):
        params = _mqtt_params(MOCK_CREDS)
        assert params["keepalive"] == 10

    def test_mac_id_fallback(self):
        creds = {**MOCK_CREDS}
        del creds["macId"]
        params = _mqtt_params(creds)
        # Should still produce a valid username using get_mac_id()
        username = params["username"]
        assert isinstance(username, str)
        assert username.startswith("U001@")


def _make_mock_mqtt_client(
    messages: list[bytes] | None = None,
) -> tuple[AsyncMock, AsyncMock]:
    """Create a mock aiomqtt.Client that works as an async context manager.

    Args:
        messages: List of message payloads to yield from client.messages.

    The message generator blocks forever after exhausting *messages*,
    mirroring real MQTT behaviour (the iterator only ends on disconnect).
    This ensures ``async for`` always suspends, which is required for
    ``task.cancel()`` to deliver ``CancelledError``.
    """
    mock_client = AsyncMock()
    mock_client.publish = AsyncMock()
    mock_client.subscribe = AsyncMock()

    async def _message_generator() -> Any:
        for payload in messages or []:
            msg = MagicMock()
            msg.payload = payload
            yield msg
        # Block forever — a real MQTT connection waits for the next message.
        await asyncio.Event().wait()

    mock_client.messages = _message_generator()

    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    return mock_cm, mock_client


class TestPublishCommand:
    async def test_publishes_to_correct_topic(self):
        mock_cm, mock_client = _make_mock_mqtt_client()
        client = Client({**MOCK_CREDS})

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            await client._publish_command("SN001", 4, {"oac": 1})

        mock_client.publish.assert_awaited_once()
        call_args = mock_client.publish.call_args
        assert call_args[0][0] == "hb/app/U001/command"
        assert call_args[1]["qos"] == 1

    async def test_payload_contains_device_sn(self):
        mock_cm, mock_client = _make_mock_mqtt_client()
        client = Client({**MOCK_CREDS})

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            await client._publish_command("SN001", 4, {"oac": 1})

        payload_str = mock_client.publish.call_args[0][1]
        payload = json.loads(payload_str)
        assert payload["deviceSn"] == "SN001"
        assert payload["actionId"] == 4
        assert payload["body"] == {"oac": 1}

    async def test_mqtt_client_params(self):
        mock_cm, _ = _make_mock_mqtt_client()
        client = Client({**MOCK_CREDS})

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm) as mock_cls:
            await client._publish_command("SN001", 4, {"oac": 1})

        call_kwargs = mock_cls.call_args[1]
        assert call_kwargs["hostname"] == MQTT_HOST
        assert call_kwargs["port"] == MQTT_PORT
        assert call_kwargs["identifier"] == "U001@APP"
        assert call_kwargs["username"] == "U001@aa:bb:cc:dd:ee:ff"
        assert isinstance(call_kwargs["tls_context"], ssl.SSLContext)

    async def test_uses_active_mqtt_when_set(self):
        """When _active_mqtt is set, publish through it without opening a new connection."""
        mock_mqtt = AsyncMock()
        mock_mqtt.publish = AsyncMock()
        client = Client({**MOCK_CREDS})
        client._active_mqtt = mock_mqtt

        with patch("socketry.client.aiomqtt.Client") as mock_cls:
            await client._publish_command("SN001", 4, {"oac": 1})

        mock_cls.assert_not_called()
        mock_mqtt.publish.assert_awaited_once()
        topic = mock_mqtt.publish.call_args[0][0]
        assert topic == "hb/app/U001/command"

    async def test_uses_device_sn_not_selected(self):
        """Device SN from parameter overrides the credentials' selected device."""
        mock_cm, mock_client = _make_mock_mqtt_client()
        client = Client({**MOCK_CREDS})  # MOCK_CREDS has deviceSn = "SN001"

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            await client._publish_command("OTHER_SN", 4, {"oac": 1})

        payload = json.loads(mock_client.publish.call_args[0][1])
        assert payload["deviceSn"] == "OTHER_SN"


class TestPublishAndWait:
    def _device_response(self, body: dict[str, Any], device_sn: str = "SN001") -> bytes:
        """Build a valid DevicePropertyChange response payload."""
        return json.dumps(
            {
                "deviceSn": device_sn,
                "messageType": "DevicePropertyChange",
                "body": body,
            }
        ).encode()

    def _broker_ack(self, device_sn: str = "SN001") -> bytes:
        """Build a broker ACK message (body with only messageId)."""
        return json.dumps(
            {
                "deviceSn": device_sn,
                "messageType": "DevicePropertyChange",
                "body": {"messageId": 0},
            }
        ).encode()

    async def test_happy_path(self):
        response_body = {"oac": 1, "messageId": 12345}
        messages = [self._device_response(response_body)]
        mock_cm, mock_client = _make_mock_mqtt_client(messages)
        client = Client({**MOCK_CREDS})

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            result = await client._publish_and_wait("SN001", 4, {"oac": 1}, expected_keys={"oac"})

        assert result is not None
        assert result["body"] == {"oac": 1}  # messageId stripped by parser
        assert result["deviceSn"] == "SN001"

    async def test_subscribes_before_publish(self):
        messages = [self._device_response({"oac": 1})]
        mock_cm, mock_client = _make_mock_mqtt_client(messages)
        client = Client({**MOCK_CREDS})

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            await client._publish_and_wait("SN001", 4, {"oac": 1}, expected_keys={"oac"})

        # subscribe should have been called
        mock_client.subscribe.assert_awaited_once()
        sub_args = mock_client.subscribe.call_args
        assert sub_args[0][0] == "hb/app/U001/device"
        assert sub_args[1]["qos"] == 1

        # publish should have been called
        mock_client.publish.assert_awaited_once()
        pub_args = mock_client.publish.call_args
        assert pub_args[0][0] == "hb/app/U001/command"

    async def test_skips_broker_ack(self):
        messages = [
            self._broker_ack(),
            self._device_response({"oac": 1, "messageId": 123}),
        ]
        mock_cm, _ = _make_mock_mqtt_client(messages)
        client = Client({**MOCK_CREDS})

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            result = await client._publish_and_wait("SN001", 4, {"oac": 1}, expected_keys={"oac"})

        assert result is not None
        assert result["body"] == {"oac": 1}  # messageId stripped

    async def test_filters_by_device_sn(self):
        messages = [
            self._device_response({"oac": 0}, device_sn="OTHER_SN"),
            self._device_response({"oac": 1}, device_sn="SN001"),
        ]
        mock_cm, _ = _make_mock_mqtt_client(messages)
        client = Client({**MOCK_CREDS})

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            result = await client._publish_and_wait("SN001", 4, {"oac": 1}, expected_keys={"oac"})

        assert result is not None
        assert result["deviceSn"] == "SN001"

    async def test_filters_by_expected_keys(self):
        """Unrelated property updates are skipped; only the commanded key is accepted (fix #14)."""
        messages = [
            self._device_response({"rb": 85}),  # unrelated — skipped
            self._device_response({"bt": 21}),  # unrelated — skipped
            self._device_response({"oac": 1}),  # commanded key — accepted
        ]
        mock_cm, _ = _make_mock_mqtt_client(messages)
        client = Client({**MOCK_CREDS})

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            result = await client._publish_and_wait("SN001", 4, {"oac": 1}, expected_keys={"oac"})

        assert result is not None
        assert isinstance(result["body"], dict)
        assert "oac" in result["body"]

    async def test_ignores_non_json(self):
        messages = [
            b"not json at all",
            self._device_response({"oac": 1}),
        ]
        mock_cm, _ = _make_mock_mqtt_client(messages)
        client = Client({**MOCK_CREDS})

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            result = await client._publish_and_wait("SN001", 4, {"oac": 1}, expected_keys={"oac"})

        assert result is not None
        assert result["body"] == {"oac": 1}

    async def test_ignores_non_device_property_change(self):
        other_msg = json.dumps(
            {
                "deviceSn": "SN001",
                "messageType": "SomeOtherType",
                "body": {"foo": "bar"},
            }
        ).encode()
        messages = [
            other_msg,
            self._device_response({"oac": 1}),
        ]
        mock_cm, _ = _make_mock_mqtt_client(messages)
        client = Client({**MOCK_CREDS})

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            result = await client._publish_and_wait("SN001", 4, {"oac": 1}, expected_keys={"oac"})

        assert result is not None
        assert result["messageType"] == "DevicePropertyChange"

    async def test_ignores_non_dict_body(self):
        msg_with_string_body = json.dumps(
            {
                "deviceSn": "SN001",
                "messageType": "DevicePropertyChange",
                "body": "not a dict",
            }
        ).encode()
        messages = [
            msg_with_string_body,
            self._device_response({"oac": 1}),
        ]
        mock_cm, _ = _make_mock_mqtt_client(messages)
        client = Client({**MOCK_CREDS})

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            result = await client._publish_and_wait("SN001", 4, {"oac": 1}, expected_keys={"oac"})

        assert result is not None
        assert result["body"] == {"oac": 1}

    async def test_timeout_returns_none(self):
        mock_cm, _ = _make_mock_mqtt_client([])
        client = Client({**MOCK_CREDS})

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            result = await client._publish_and_wait(
                "SN001", 4, {"oac": 1}, expected_keys={"oac"}, timeout=0.1
            )

        assert result is None

    async def test_uses_active_mqtt_no_new_connection(self):
        """When _active_mqtt is set, no new MQTT connection is opened."""
        mock_mqtt = AsyncMock()
        mock_mqtt.publish = AsyncMock()
        client = Client({**MOCK_CREDS})
        client._active_mqtt = mock_mqtt

        # Resolve the future via a pending response (simulates the subscribe loop)
        async def _resolve_pending() -> None:
            await asyncio.sleep(0)
            for _pred, fut in client._pending_responses:
                if not fut.done():
                    fut.set_result(("SN001", {"oac": 1}))
                    break

        with patch("socketry.client.aiomqtt.Client") as mock_cls:
            asyncio.create_task(_resolve_pending())
            result = await client._publish_and_wait("SN001", 4, {"oac": 1}, expected_keys={"oac"})

        mock_cls.assert_not_called()
        mock_mqtt.publish.assert_awaited_once()
        assert result is not None
        assert result["body"] == {"oac": 1}

    async def test_active_mqtt_timeout_cleans_up_pending(self):
        """On timeout, the stale future is removed from _pending_responses."""
        mock_mqtt = AsyncMock()
        mock_mqtt.publish = AsyncMock()
        client = Client({**MOCK_CREDS})
        client._active_mqtt = mock_mqtt

        with patch("socketry.client.aiomqtt.Client"):
            result = await client._publish_and_wait(
                "SN001", 4, {"oac": 1}, expected_keys={"oac"}, timeout=0.05
            )

        assert result is None
        assert client._pending_responses == []


class TestSetProperty:
    async def test_fire_and_forget(self):
        mock_cm, mock_client = _make_mock_mqtt_client()

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            client = Client({**MOCK_CREDS})
            result = await client.set_property("ac", "on")

        assert result is None
        mock_client.publish.assert_awaited_once()

    async def test_wait_returns_body(self):
        response_body = {"oac": 1, "messageId": 123}
        response = json.dumps(
            {
                "deviceSn": "SN001",
                "messageType": "DevicePropertyChange",
                "body": response_body,
            }
        ).encode()
        mock_cm, _ = _make_mock_mqtt_client([response])

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            client = Client({**MOCK_CREDS})
            result = await client.set_property("ac", "on", wait=True)

        assert result == {"oac": 1}  # messageId stripped by parser

    async def test_wait_timeout_returns_none(self):
        mock_cm, _ = _make_mock_mqtt_client([])

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            client = Client({**MOCK_CREDS})
            result = await client.set_property("ac", "on", wait=True)

        assert result is None

    async def test_unknown_setting_raises(self):
        client = Client({**MOCK_CREDS})
        with pytest.raises(KeyError, match="Unknown setting"):
            await client.set_property("nonexistent", "on")

    async def test_readonly_setting_raises(self):
        client = Client({**MOCK_CREDS})
        with pytest.raises(ValueError, match="read-only"):
            await client.set_property("battery", "50")

    async def test_invalid_value_raises(self):
        client = Client({**MOCK_CREDS})
        with pytest.raises(ValueError, match="Invalid value"):
            await client.set_property("ac", "maybe")

    async def test_mqtt_error_wrapped_as_socketry_mqtt_error(self):
        """aiomqtt.MqttError is re-raised as socketry.MqttError."""
        import aiomqtt as _aiomqtt

        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(side_effect=_aiomqtt.MqttError("connection refused"))
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        client = Client({**MOCK_CREDS})
        with (
            patch("socketry.client.aiomqtt.Client", return_value=mock_cm),
            pytest.raises(MqttError, match="connection refused"),
        ):
            await client.set_property("ac", "on")

    async def test_mqtt_error_is_connection_error_subclass(self):
        """socketry.MqttError is a ConnectionError subclass for convenient catching."""
        import aiomqtt as _aiomqtt

        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(side_effect=_aiomqtt.MqttError("timeout"))
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        client = Client({**MOCK_CREDS})
        with (
            patch("socketry.client.aiomqtt.Client", return_value=mock_cm),
            pytest.raises(ConnectionError),
        ):
            await client.set_property("ac", "on")

    async def test_mqtt_error_chained_from_aiomqtt(self):
        """The socketry.MqttError is chained from the original aiomqtt.MqttError."""
        import aiomqtt as _aiomqtt

        original = _aiomqtt.MqttError("broker unavailable")
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(side_effect=original)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        client = Client({**MOCK_CREDS})
        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            try:
                await client.set_property("ac", "on")
            except MqttError as exc:
                assert exc.__cause__ is original
            else:
                pytest.fail("MqttError not raised")

    async def test_mqtt_error_wrapped_wait_true(self):
        """aiomqtt.MqttError is wrapped as socketry.MqttError for the wait=True path."""
        import aiomqtt as _aiomqtt

        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(side_effect=_aiomqtt.MqttError("connection reset"))
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        client = Client({**MOCK_CREDS})
        with (
            patch("socketry.client.aiomqtt.Client", return_value=mock_cm),
            pytest.raises(MqttError, match="connection reset"),
        ):
            await client.set_property("ac", "on", wait=True)


# ---------------------------------------------------------------------------
# _parse_device_update tests
# ---------------------------------------------------------------------------


class TestParseDeviceUpdate:
    def _update(self, body: dict[str, Any], device_sn: str = "SN001") -> bytes:
        return json.dumps(
            {
                "deviceSn": device_sn,
                "messageType": "DevicePropertyChange",
                "body": body,
            }
        ).encode()

    def test_valid_update(self):
        result = _parse_device_update(self._update({"oac": 1, "messageId": 123}))
        assert result is not None
        sn, props = result
        assert sn == "SN001"
        assert props == {"oac": 1}  # messageId stripped

    def test_strips_message_id(self):
        result = _parse_device_update(self._update({"rb": 85, "messageId": 999}))
        assert result is not None
        _, props = result
        assert "messageId" not in props
        assert props == {"rb": 85}

    def test_non_json_returns_none(self):
        assert _parse_device_update(b"not json") is None

    def test_missing_device_sn_returns_none(self):
        payload = json.dumps({"messageType": "DevicePropertyChange", "body": {"oac": 1}}).encode()
        assert _parse_device_update(payload) is None

    def test_wrong_message_type_returns_none(self):
        payload = json.dumps(
            {"deviceSn": "SN001", "messageType": "SomeOther", "body": {"oac": 1}}
        ).encode()
        assert _parse_device_update(payload) is None

    def test_non_dict_body_returns_none(self):
        payload = json.dumps(
            {"deviceSn": "SN001", "messageType": "DevicePropertyChange", "body": "str"}
        ).encode()
        assert _parse_device_update(payload) is None

    def test_broker_ack_returns_none(self):
        payload = json.dumps(
            {
                "deviceSn": "SN001",
                "messageType": "DevicePropertyChange",
                "body": {"messageId": 0},
            }
        ).encode()
        assert _parse_device_update(payload) is None

    def test_integer_device_sn_returns_none(self):
        payload = json.dumps(
            {"deviceSn": 12345, "messageType": "DevicePropertyChange", "body": {"oac": 1}}
        ).encode()
        assert _parse_device_update(payload) is None


# ---------------------------------------------------------------------------
# Subscription tests
# ---------------------------------------------------------------------------


class TestRunSubscribeLoop:
    def _device_message(self, body: dict[str, Any], device_sn: str = "SN001") -> bytes:
        return json.dumps(
            {
                "deviceSn": device_sn,
                "messageType": "DevicePropertyChange",
                "body": body,
            }
        ).encode()

    async def test_calls_callback_with_parsed_updates(self):
        messages = [
            self._device_message({"oac": 1}),
            self._device_message({"rb": 85}, device_sn="SN002"),
        ]
        mock_cm, mock_client = _make_mock_mqtt_client(messages)
        received: list[tuple[str, dict[str, object]]] = []
        got_all = asyncio.Event()

        async def callback(sn: str, props: dict[str, object]) -> None:
            received.append((sn, props))
            if len(received) == 2:
                got_all.set()

        client = Client({**MOCK_CREDS})
        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            task = asyncio.create_task(client._run_subscribe_loop(callback))
            await asyncio.wait_for(got_all.wait(), timeout=2)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        assert len(received) == 2
        assert received[0] == ("SN001", {"oac": 1})
        assert received[1] == ("SN002", {"rb": 85})

    async def test_skips_invalid_messages(self):
        messages = [
            b"not json",
            self._device_message({"messageId": 0}),  # broker ACK
            self._device_message({"oac": 1}),
        ]
        mock_cm, mock_client = _make_mock_mqtt_client(messages)
        received: list[tuple[str, dict[str, object]]] = []
        got_one = asyncio.Event()

        async def callback(sn: str, props: dict[str, object]) -> None:
            received.append((sn, props))
            got_one.set()

        client = Client({**MOCK_CREDS})
        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            task = asyncio.create_task(client._run_subscribe_loop(callback))
            await asyncio.wait_for(got_one.wait(), timeout=2)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        assert len(received) == 1
        assert received[0] == ("SN001", {"oac": 1})

    async def test_subscribes_to_device_topic(self):
        mock_cm, mock_client = _make_mock_mqtt_client([])

        async def callback(sn: str, props: dict[str, object]) -> None:
            pass

        client = Client({**MOCK_CREDS})
        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            task = asyncio.create_task(client._run_subscribe_loop(callback))
            await asyncio.sleep(0)  # let the loop subscribe
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        mock_client.subscribe.assert_awaited_once()
        sub_args = mock_client.subscribe.call_args
        assert sub_args[0][0] == "hb/app/U001/device"
        assert sub_args[1]["qos"] == 1

    async def test_uses_standard_client_id(self):
        """Subscription uses the standard client ID (broker ACLs require it)."""
        mock_cm, _ = _make_mock_mqtt_client([])

        async def callback(sn: str, props: dict[str, object]) -> None:
            pass

        client = Client({**MOCK_CREDS})
        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm) as mock_cls:
            task = asyncio.create_task(client._run_subscribe_loop(callback))
            await asyncio.sleep(0)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        call_kwargs = mock_cls.call_args[1]
        assert call_kwargs["identifier"] == "U001@APP"

    async def test_sets_and_clears_active_mqtt(self):
        """_active_mqtt is set while connected and cleared on exit."""
        connected = asyncio.Event()
        mock_cm, mock_client = _make_mock_mqtt_client([])

        # Intercept __aenter__ to capture when the connection is "active"
        original_aenter = mock_cm.__aenter__

        async def patched_aenter(*args: object, **kwargs: object) -> object:
            result = await original_aenter(*args, **kwargs)
            connected.set()
            return result

        mock_cm.__aenter__ = patched_aenter

        async def callback(sn: str, props: dict[str, object]) -> None:
            pass

        client = Client({**MOCK_CREDS})
        assert client._active_mqtt is None

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            task = asyncio.create_task(client._run_subscribe_loop(callback))
            await asyncio.wait_for(connected.wait(), timeout=2)
            assert client._active_mqtt is mock_client
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        assert client._active_mqtt is None

    async def test_resolves_pending_responses(self):
        """Pending futures from _publish_and_wait are resolved via the shared loop."""
        msg = self._device_message({"oac": 1})
        mock_cm, _ = _make_mock_mqtt_client([msg])
        received: list[tuple[str, dict[str, object]]] = []
        got_one = asyncio.Event()

        async def callback(sn: str, props: dict[str, object]) -> None:
            received.append((sn, props))
            got_one.set()

        client = Client({**MOCK_CREDS})
        future: asyncio.Future[tuple[str, dict[str, object]]] = (
            asyncio.get_event_loop().create_future()
        )
        client._pending_responses.append((lambda sn, p: "oac" in p, future))

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            task = asyncio.create_task(client._run_subscribe_loop(callback))
            await asyncio.wait_for(got_one.wait(), timeout=2)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        assert future.done()
        sn, props = future.result()
        assert sn == "SN001"
        assert props == {"oac": 1}
        # User callback still fires for the same message
        assert received == [("SN001", {"oac": 1})]

    async def test_reconnects_on_mqtt_error(self):
        """Should reconnect after an MqttError from the broker."""
        import aiomqtt as _aiomqtt

        call_count = 0
        got_message = asyncio.Event()

        # First call raises MqttError, second succeeds with a message
        def make_client(**kwargs: object) -> AsyncMock:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                cm = AsyncMock()
                cm.__aenter__ = AsyncMock(side_effect=_aiomqtt.MqttError("disconnected"))
                cm.__aexit__ = AsyncMock(return_value=False)
                return cm
            msg_payload = json.dumps(
                {"deviceSn": "SN001", "messageType": "DevicePropertyChange", "body": {"oac": 1}}
            ).encode()
            return _make_mock_mqtt_client([msg_payload])[0]

        received: list[tuple[str, dict[str, object]]] = []

        async def callback(sn: str, props: dict[str, object]) -> None:
            received.append((sn, props))
            got_message.set()

        client = Client({**MOCK_CREDS})
        with (
            patch("socketry.client.aiomqtt.Client", side_effect=make_client),
            patch("socketry.client._RECONNECT_INTERVAL", 0),
        ):
            task = asyncio.create_task(client._run_subscribe_loop(callback))
            await asyncio.wait_for(got_message.wait(), timeout=2)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        assert call_count >= 2
        assert received == [("SN001", {"oac": 1})]


class TestSubscription:
    def _make_client(self) -> Client:
        return Client({**MOCK_CREDS})

    async def test_stop_cancels_task(self):
        """stop() should cancel the background task and return cleanly."""

        async def block_forever() -> None:
            await asyncio.Event().wait()

        task = asyncio.create_task(block_forever())
        sub = Subscription(task, self._make_client())
        await sub.stop()
        assert task.done()

    async def test_stop_handles_failed_task(self):
        """stop() should not raise if the task already failed with an exception."""

        async def fail() -> None:
            raise RuntimeError("connection lost")

        task = asyncio.create_task(fail())
        await asyncio.sleep(0)  # let the task fail
        sub = Subscription(task, self._make_client())
        await sub.stop()  # should not raise
        assert task.done()

    async def test_wait_returns_when_task_completes(self):
        """wait() should return once the background task finishes."""

        async def quick() -> None:
            return

        task = asyncio.create_task(quick())
        sub = Subscription(task, self._make_client())
        await sub.wait()
        assert task.done()

    async def test_is_connected_false_when_no_active_mqtt(self):
        """is_connected returns False when _active_mqtt is None."""

        async def block_forever() -> None:
            await asyncio.Event().wait()

        client = self._make_client()
        assert client._active_mqtt is None
        task = asyncio.create_task(block_forever())
        sub = Subscription(task, client)
        assert sub.is_connected is False
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def test_is_connected_true_when_active_mqtt_set(self):
        """is_connected returns True when _active_mqtt is set to a mock value."""

        async def block_forever() -> None:
            await asyncio.Event().wait()

        client = self._make_client()
        task = asyncio.create_task(block_forever())
        sub = Subscription(task, client)

        mock_mqtt = MagicMock()
        client._active_mqtt = mock_mqtt
        assert sub.is_connected is True

        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def test_is_connected_reflects_realtime_changes(self):
        """is_connected reflects live changes to _active_mqtt."""

        async def block_forever() -> None:
            await asyncio.Event().wait()

        client = self._make_client()
        task = asyncio.create_task(block_forever())
        sub = Subscription(task, client)

        assert sub.is_connected is False

        mock_mqtt = MagicMock()
        client._active_mqtt = mock_mqtt
        assert sub.is_connected is True

        client._active_mqtt = None
        assert sub.is_connected is False

        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


class TestClientSubscribe:
    async def test_returns_subscription_and_receives_updates(self):
        update_msg = json.dumps(
            {
                "deviceSn": "SN001",
                "messageType": "DevicePropertyChange",
                "body": {"oac": 1},
            }
        ).encode()
        mock_cm, _ = _make_mock_mqtt_client([update_msg])
        received: list[tuple[str, dict[str, object]]] = []
        got_message = asyncio.Event()

        async def callback(sn: str, props: dict[str, object]) -> None:
            received.append((sn, props))
            got_message.set()

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            client = Client({**MOCK_CREDS})
            sub = await client.subscribe(callback)
            assert isinstance(sub, Subscription)
            await asyncio.wait_for(got_message.wait(), timeout=2)
            await sub.stop()

        assert received == [("SN001", {"oac": 1})]

    async def test_is_connected_reflects_subscribe_loop_lifecycle(self):
        """is_connected is True while _run_subscribe_loop holds the connection open
        and False after stop() clears _active_mqtt."""
        update_msg = json.dumps(
            {
                "deviceSn": "SN001",
                "messageType": "DevicePropertyChange",
                "body": {"oac": 1},
            }
        ).encode()
        mock_cm, _ = _make_mock_mqtt_client([update_msg])
        connected_during_callback: list[bool] = []
        got_message = asyncio.Event()

        async def callback(sn: str, props: dict[str, object]) -> None:
            # Capture is_connected while the loop is still running.
            connected_during_callback.append(sub.is_connected)
            got_message.set()

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            client = Client({**MOCK_CREDS})
            sub = await client.subscribe(callback)
            await asyncio.wait_for(got_message.wait(), timeout=2)
            # Still connected while the subscription task is alive.
            assert sub.is_connected is True
            await sub.stop()

        # After stop(), _active_mqtt is cleared by the finally block.
        assert sub.is_connected is False
        # Sanity: callback was called with the connection live.
        assert connected_during_callback == [True]


# ---------------------------------------------------------------------------
# Device tests
# ---------------------------------------------------------------------------

MOCK_DEV_INFO: dict[str, Any] = {
    "devSn": "SN001",
    "devId": "DEV001",
    "devName": "My Station",
    "modelCode": 2,
}


class TestDevice:
    def _client(self) -> Client:
        return Client(
            {
                "token": "tok",
                "devices": [MOCK_DEV_INFO],
                **{k: v for k, v in MOCK_CREDS.items() if k != "token"},
            }
        )

    def test_properties(self):
        client = self._client()
        dev = client.device(0)
        assert dev.sn == "SN001"
        assert dev.device_id == "DEV001"
        assert dev.name == "My Station"
        assert dev.model_code == 2

    async def test_get_all_properties(self):
        client = self._client()
        dev = client.device(0)
        mock_data: dict[str, Any] = {"properties": {"rb": 80}}
        with aioresponses() as m:
            m.get(_PROPERTY_URL, payload={"code": 0, "data": mock_data})
            result = await dev.get_all_properties()
        assert result["properties"]["rb"] == 80  # type: ignore[index]

    async def test_get_all_properties_no_device_id(self):
        client = Client({"token": "tok", "devices": [{"devSn": "SN001", "devId": ""}]})
        dev = client.device(0)
        with pytest.raises(ValueError, match="has no deviceId"):
            await dev.get_all_properties()

    async def test_get_property(self):
        client = self._client()
        dev = client.device(0)
        mock_data: dict[str, Any] = {"properties": {"rb": 75}}
        with aioresponses() as m:
            m.get(_PROPERTY_URL, payload={"code": 0, "data": mock_data})
            setting, value = await dev.get_property("battery")
        assert setting.id == "rb"
        assert value == 75

    async def test_get_property_unknown(self):
        client = self._client()
        dev = client.device(0)
        with pytest.raises(KeyError, match="Unknown property"):
            await dev.get_property("nonexistent")

    async def test_set_property_fire_and_forget(self):
        mock_cm, mock_client = _make_mock_mqtt_client()
        client = self._client()
        dev = client.device(0)

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            result = await dev.set_property("ac", "on")

        assert result is None
        mock_client.publish.assert_awaited_once()
        payload = json.loads(mock_client.publish.call_args[0][1])
        assert payload["deviceSn"] == "SN001"

    async def test_set_property_uses_device_sn_not_selected(self):
        """Device.set_property uses the device's own SN, not the selected device."""
        mock_cm, mock_client = _make_mock_mqtt_client()
        # Client has device SN002 selected, but the Device object is for SN001
        client = Client(
            {
                **MOCK_CREDS,
                "deviceSn": "SN002",
                "devices": [MOCK_DEV_INFO],
            }
        )
        dev = client.device("SN001")

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            await dev.set_property("ac", "on")

        payload = json.loads(mock_client.publish.call_args[0][1])
        assert payload["deviceSn"] == "SN001"

    async def test_set_property_wait(self):
        response = json.dumps(
            {
                "deviceSn": "SN001",
                "messageType": "DevicePropertyChange",
                "body": {"oac": 1, "messageId": 1},
            }
        ).encode()
        mock_cm, _ = _make_mock_mqtt_client([response])
        client = self._client()
        dev = client.device(0)

        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            result = await dev.set_property("ac", "on", wait=True)

        assert result == {"oac": 1}

    async def test_set_property_unknown_raises(self):
        client = self._client()
        dev = client.device(0)
        with pytest.raises(KeyError, match="Unknown setting"):
            await dev.set_property("nonexistent", "on")

    async def test_set_property_readonly_raises(self):
        client = self._client()
        dev = client.device(0)
        with pytest.raises(ValueError, match="read-only"):
            await dev.set_property("battery", "50")

    async def test_set_property_mqtt_error_wrapped(self):
        """Device.set_property wraps aiomqtt.MqttError as socketry.MqttError."""
        import aiomqtt as _aiomqtt

        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(side_effect=_aiomqtt.MqttError("broker gone"))
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        client = self._client()
        dev = client.device(0)
        with (
            patch("socketry.client.aiomqtt.Client", return_value=mock_cm),
            pytest.raises(MqttError, match="broker gone"),
        ):
            await dev.set_property("ac", "on")

    async def test_set_property_mqtt_error_chained(self):
        """Device.set_property chains the original aiomqtt.MqttError as __cause__."""
        import aiomqtt as _aiomqtt

        original = _aiomqtt.MqttError("tls handshake failed")
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(side_effect=original)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        client = self._client()
        dev = client.device(0)
        with patch("socketry.client.aiomqtt.Client", return_value=mock_cm):
            try:
                await dev.set_property("ac", "on")
            except MqttError as exc:
                assert exc.__cause__ is original
            else:
                pytest.fail("MqttError not raised")


# ---------------------------------------------------------------------------
# Token auto-refresh tests
# ---------------------------------------------------------------------------


def _make_fake_jwt(exp: int) -> str:
    """Build a minimal unsigned JWT with the given exp claim (for testing only)."""
    import base64 as _b64

    header = _b64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload_bytes = json.dumps({"exp": exp, "sub": "test"}).encode()
    payload = _b64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
    return f"{header}.{payload}.fakesig"


class TestDecodeJwtExp:
    def test_extracts_exp(self):
        future = int(time.time()) + 86400
        token = _make_fake_jwt(future)
        result = _decode_jwt_exp(token)
        assert result == float(future)

    def test_expired_token(self):
        past = int(time.time()) - 1000
        token = _make_fake_jwt(past)
        result = _decode_jwt_exp(token)
        assert result == float(past)

    def test_not_a_jwt(self):
        assert _decode_jwt_exp("not-a-jwt") is None

    def test_malformed_payload(self):
        assert _decode_jwt_exp("a.!!!.c") is None

    def test_missing_exp_claim(self):
        import base64 as _b64

        payload = _b64.urlsafe_b64encode(b'{"sub":"test"}').rstrip(b"=").decode()
        assert _decode_jwt_exp(f"hdr.{payload}.sig") is None


class TestHttpLoginStoresCredentials:
    async def test_stores_password_and_token_exp(self):
        future_exp = int(time.time()) + 86400 * 30
        fake_token = _make_fake_jwt(future_exp)
        login_response = {
            "code": 0,
            "token": fake_token,
            "data": {"userId": "U001", "mqttPassWord": "bXF0dHB3"},
        }
        with aioresponses() as m:
            m.post(_LOGIN_URL, payload=login_response)
            _mock_device_endpoints(m, owned=[MOCK_OWNED_DEVICE])
            creds = await _http_login("me@example.com", "secret")

        assert creds["password"] == "secret"
        assert creds["tokenExp"] == float(future_exp)

    async def test_fetch_devices_false_skips_device_endpoints(self):
        future_exp = int(time.time()) + 86400 * 30
        fake_token = _make_fake_jwt(future_exp)
        login_response = {
            "code": 0,
            "token": fake_token,
            "data": {"userId": "U001", "mqttPassWord": "bXF0dHB3"},
        }
        with aioresponses() as m:
            m.post(_LOGIN_URL, payload=login_response)
            # No device endpoints registered — would fail if called
            creds = await _http_login("me@example.com", "secret", fetch_devices=False)

        assert creds["token"] == fake_token
        assert creds["devices"] == []
        assert creds["deviceSn"] == ""

    async def test_undecodable_token_gives_none_exp(self):
        login_response = {
            "code": 0,
            "token": "opaque-token",
            "data": {"userId": "U001", "mqttPassWord": "bXF0dHB3"},
        }
        with aioresponses() as m:
            m.post(_LOGIN_URL, payload=login_response)
            _mock_device_endpoints(m)
            creds = await _http_login("me@example.com", "secret")

        assert creds["tokenExp"] is None


class TestTokenExpiredErrorRaised:
    async def test_fetch_device_properties_raises_on_10402(self):
        with aioresponses() as m:
            m.get(_PROPERTY_URL, payload={"code": 10402, "msg": "Token expired"})
            async with aiohttp.ClientSession() as session:
                with pytest.raises(TokenExpiredError):
                    await _fetch_device_properties("expired-token", "DEV001", session)

    async def test_fetch_all_devices_raises_on_10402(self):
        with aioresponses() as m:
            m.get(
                f"{API_BASE}/device/bind/list",
                payload={"code": 10402, "msg": "Token expired"},
            )
            async with aiohttp.ClientSession() as session:
                with pytest.raises(TokenExpiredError):
                    await _fetch_all_devices("expired-token", session)


class TestEnsureFreshToken:
    def _creds_with_exp(self, exp: float) -> dict[str, Any]:
        return {
            "token": "old-token",
            "mqttPassWord": "old-pw",
            "tokenExp": exp,
            "email": "me@example.com",
            "password": "secret",
            "userId": "U001",
        }

    async def test_no_refresh_when_token_is_fresh(self):
        far_future = time.time() + 86400 * 29  # 29 days from now
        client = Client(self._creds_with_exp(far_future))

        with patch("socketry.client._http_login") as mock_login:
            await client._ensure_fresh_token()

        mock_login.assert_not_called()

    async def test_refreshes_when_within_buffer(self):
        soon = time.time() + 1800  # 30 min from now (< 1 hour buffer)
        future_exp = time.time() + 86400 * 30
        new_creds = {
            "token": "new-token",
            "mqttPassWord": "new-pw",
            "tokenExp": future_exp,
        }
        client = Client(self._creds_with_exp(soon))

        with patch("socketry.client._http_login", return_value=new_creds) as mock_login:
            await client._ensure_fresh_token()

        mock_login.assert_awaited_once_with("me@example.com", "secret", fetch_devices=False)
        assert client.token == "new-token"
        assert client._creds["mqttPassWord"] == "new-pw"
        assert client._creds["tokenExp"] == future_exp

    async def test_refreshes_when_token_exp_is_none(self):
        """If tokenExp is None (e.g. opaque token), always refresh."""
        new_creds = {"token": "new-tok", "mqttPassWord": "new-pw", "tokenExp": None}
        client = Client(
            {
                "token": "old",
                "mqttPassWord": "old-pw",
                "tokenExp": None,
                "email": "x@x.com",
                "password": "pw",
            }
        )

        with patch("socketry.client._http_login", return_value=new_creds) as mock_login:
            await client._ensure_fresh_token()

        mock_login.assert_awaited_once()
        assert client.token == "new-tok"

    async def test_no_refresh_without_password(self):
        """If no password in creds, skip refresh silently (backwards compat)."""
        client = Client({"token": "tok", "tokenExp": 0.0, "email": "x@x.com"})

        with patch("socketry.client._http_login") as mock_login:
            await client._ensure_fresh_token()

        mock_login.assert_not_called()

    async def test_persists_credentials_after_refresh(self, tmp_path, monkeypatch):
        """After a refresh, from_saved() clients persist new credentials to disk."""
        soon = time.time() + 1800
        new_creds = {
            "token": "new-tok",
            "mqttPassWord": "mpw",
            "tokenExp": time.time() + 86400 * 30,
        }

        cred_dir = tmp_path / "config"
        cred_file = cred_dir / "credentials.json"
        cred_dir.mkdir()
        cred_file.write_text(json.dumps(self._creds_with_exp(soon)))
        cred_file.chmod(0o600)
        monkeypatch.setattr("socketry.client.CRED_DIR", cred_dir)
        monkeypatch.setattr("socketry.client.CRED_FILE", cred_file)

        client = Client.from_saved()
        with patch("socketry.client._http_login", return_value=new_creds):
            await client._ensure_fresh_token()

        saved = json.loads(cred_file.read_text())
        assert saved["token"] == "new-tok"

    async def test_no_persist_for_programmatic_client(self, tmp_path, monkeypatch):
        """Clients constructed directly (not from_saved) do NOT auto-save after refresh."""
        soon = time.time() + 1800
        new_creds = {
            "token": "new-tok",
            "mqttPassWord": "mpw",
            "tokenExp": time.time() + 86400 * 30,
        }

        cred_dir = tmp_path / "config"
        cred_file = cred_dir / "credentials.json"
        cred_dir.mkdir()
        original = json.dumps(self._creds_with_exp(soon))
        cred_file.write_text(original)
        cred_file.chmod(0o600)
        monkeypatch.setattr("socketry.client.CRED_DIR", cred_dir)
        monkeypatch.setattr("socketry.client.CRED_FILE", cred_file)

        # Constructed directly, NOT from_saved()
        client = Client(self._creds_with_exp(soon))
        with patch("socketry.client._http_login", return_value=new_creds):
            await client._ensure_fresh_token()

        # File should be unchanged
        assert cred_file.read_text() == original

    async def test_concurrent_calls_refresh_once(self):
        """Concurrent calls to _ensure_fresh_token only trigger one login."""
        soon = time.time() + 1800
        new_creds = {"token": "new", "mqttPassWord": "mpw", "tokenExp": time.time() + 86400 * 30}
        client = Client(self._creds_with_exp(soon))
        call_count = 0

        async def slow_login(*args: object, **kwargs: object) -> dict[str, Any]:
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.05)
            return new_creds

        with patch("socketry.client._http_login", side_effect=slow_login):
            await asyncio.gather(
                client._ensure_fresh_token(),
                client._ensure_fresh_token(),
                client._ensure_fresh_token(),
            )

        assert call_count == 1


class TestReactiveTokenRefresh:
    """Token refresh triggered by 10402 errors from the API."""

    def _creds_with_password(self) -> dict[str, Any]:
        return {
            **MOCK_CREDS,
            "password": "secret",
            "email": "me@example.com",
            "tokenExp": time.time() + 86400 * 30,  # fresh, proactive won't trigger
        }

    async def test_fetch_devices_retries_on_10402(self):
        new_token_creds = {"token": "new-tok", "mqttPassWord": "mpw", "tokenExp": None}
        client = Client(self._creds_with_password())

        with aioresponses() as m:
            # First call returns 10402
            m.get(f"{API_BASE}/device/bind/list", payload={"code": 10402})
            # Second call (after re-auth) succeeds
            m.get(f"{API_BASE}/device/bind/list", payload={"data": [MOCK_OWNED_DEVICE]})
            m.get(f"{API_BASE}/device/bind/shared", payload={"data": {}})

            with patch("socketry.client._http_login", return_value=new_token_creds):
                devices = await client.fetch_devices()

        assert len(devices) == 1
        assert client.token == "new-tok"

    async def test_get_all_properties_retries_on_10402(self):
        new_token_creds = {"token": "new-tok", "mqttPassWord": "mpw", "tokenExp": None}
        client = Client({**self._creds_with_password(), "deviceId": "DEV001"})
        mock_data: dict[str, Any] = {"properties": {"rb": 80}}

        with aioresponses() as m:
            m.get(_PROPERTY_URL, payload={"code": 10402})
            m.get(_PROPERTY_URL, payload={"code": 0, "data": mock_data})

            with patch("socketry.client._http_login", return_value=new_token_creds):
                result = await client.get_all_properties()

        assert result["properties"]["rb"] == 80  # type: ignore[index]
        assert client.token == "new-tok"

    async def test_device_get_all_properties_retries_on_10402(self):
        new_token_creds = {"token": "new-tok", "mqttPassWord": "mpw", "tokenExp": None}
        client = Client(
            {
                **self._creds_with_password(),
                "devices": [
                    {"devSn": "SN001", "devId": "DEV001", "devName": "Station", "modelCode": 2}
                ],
            }
        )
        dev = client.device(0)
        mock_data: dict[str, Any] = {"properties": {"rb": 77}}

        with aioresponses() as m:
            m.get(_PROPERTY_URL, payload={"code": 10402})
            m.get(_PROPERTY_URL, payload={"code": 0, "data": mock_data})

            with patch("socketry.client._http_login", return_value=new_token_creds):
                result = await dev.get_all_properties()

        assert result["properties"]["rb"] == 77  # type: ignore[index]
        assert client.token == "new-tok"
