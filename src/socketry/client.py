"""Jackery power station API client.

Provides programmatic access to Jackery power stations via their cloud
HTTP API and MQTT broker. The :class:`Client` class is the main entry point::

    import asyncio
    from socketry import Client

    client = await Client.login("email@example.com", "password")
    props = await client.get_all_properties()
    client.set_property("ac", "on", wait=True)
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import ssl
import tempfile
import time

import aiohttp
import paho.mqtt.client as mqtt

from socketry._constants import (
    API_BASE,
    APP_HEADERS,
    CA_CERT_PEM,
    CRED_DIR,
    CRED_FILE,
    MQTT_HOST,
    MQTT_PORT,
    RSA_PUBLIC_KEY_B64,
)
from socketry._crypto import (
    aes_ecb_encrypt,
    derive_mqtt_password,
    get_mac_id,
    rsa_encrypt,
)
from socketry.properties import Setting, resolve


class Client:
    """Jackery power station API client.

    Use :meth:`login` to authenticate, or :meth:`from_saved` to load
    previously saved credentials.
    """

    def __init__(self, credentials: dict[str, object]) -> None:
        self._creds = credentials

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    async def login(cls, email: str, password: str) -> Client:
        """Authenticate with Jackery and return a new client.

        Credentials are **not** saved automatically — call
        :meth:`save_credentials` to persist them.
        """
        creds = await _http_login(email, password)
        return cls(creds)

    @classmethod
    def from_saved(cls) -> Client:
        """Load a client from previously saved credentials.

        Raises :class:`FileNotFoundError` if no credentials file exists.
        """
        if not CRED_FILE.exists():
            raise FileNotFoundError(
                f"No saved credentials at {CRED_FILE}. Call Client.login() first."
            )
        creds = json.loads(CRED_FILE.read_text())
        return cls(creds)

    def save_credentials(self) -> None:
        """Persist credentials to ``~/.config/socketry/credentials.json``."""
        CRED_DIR.mkdir(parents=True, exist_ok=True)
        CRED_FILE.write_text(json.dumps(self._creds, indent=2))
        CRED_FILE.chmod(0o600)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def device_sn(self) -> str:
        """Serial number of the currently selected device."""
        return str(self._creds.get("deviceSn", ""))

    @property
    def device_name(self) -> str:
        """Display name of the currently selected device."""
        return str(self._creds.get("deviceName", self.device_sn))

    @property
    def device_id(self) -> str:
        """Internal device ID (used for HTTP property queries)."""
        return str(self._creds.get("deviceId", ""))

    @property
    def devices(self) -> list[dict[str, object]]:
        """Cached list of all devices (owned + shared)."""
        devs = self._creds.get("devices")
        if isinstance(devs, list):
            return devs
        return []

    @property
    def token(self) -> str:
        """Current JWT auth token."""
        return str(self._creds.get("token", ""))

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    async def fetch_devices(self) -> list[dict[str, object]]:
        """Refresh the device list from the API.

        Updates the internal cache and returns all devices.
        """
        async with aiohttp.ClientSession() as session:
            all_devices = await _fetch_all_devices(self.token, session)
        self._creds["devices"] = all_devices
        return all_devices

    def select_device(self, index: int) -> dict[str, object]:
        """Select the active device by index.

        Raises :class:`IndexError` if the index is out of range.
        """
        devs = self.devices
        if not devs:
            raise IndexError("No cached device list. Call fetch_devices() first.")
        if index < 0 or index >= len(devs):
            raise IndexError(f"Invalid index {index}. Must be 0..{len(devs) - 1}.")
        dev = devs[index]
        self._creds["deviceSn"] = dev["devSn"]
        self._creds["deviceId"] = dev["devId"]
        self._creds["deviceName"] = dev["devName"]
        return dev

    # ------------------------------------------------------------------
    # Status (HTTP)
    # ------------------------------------------------------------------

    async def get_all_properties(self) -> dict[str, object]:
        """Fetch the full property map for the active device.

        Returns the raw ``data`` dict from the HTTP API, containing
        ``device`` metadata and ``properties`` map.
        """
        if not self.device_id:
            raise ValueError("No deviceId. Call login() or select_device() first.")
        async with aiohttp.ClientSession() as session:
            return await _fetch_device_properties(self.token, self.device_id, session)

    async def get_property(self, name: str) -> tuple[Setting, object]:
        """Fetch a single property by slug or raw key.

        Returns ``(setting, raw_value)``.

        Raises :class:`KeyError` if the property is unknown or not
        reported by the device.
        """
        setting = resolve(name)
        if setting is None:
            raise KeyError(f"Unknown property '{name}'.")
        data = await self.get_all_properties()
        props = data.get("properties") or data
        if not isinstance(props, dict) or setting.id not in props:
            raise KeyError(f"Property '{name}' ({setting.id}) not reported by device.")
        return setting, props[setting.id]

    # ------------------------------------------------------------------
    # Control (MQTT)
    # ------------------------------------------------------------------

    def set_property(
        self,
        name: str,
        value: str | int,
        *,
        wait: bool = False,
        verbose: bool = False,
    ) -> dict[str, object] | None:
        """Change a device setting via MQTT.

        Args:
            name: Setting slug or raw key (e.g. ``"ac"``, ``"oac"``).
            value: Named value (``"on"``, ``"off"``) or integer.
            wait: If ``True``, wait for device confirmation.
            verbose: If ``True``, log MQTT traffic.

        Returns:
            The device response body if *wait* is ``True`` and the device
            responds, otherwise ``None``.

        Raises:
            KeyError: If the setting is unknown.
            ValueError: If the setting is read-only or the value is invalid.
        """
        setting = resolve(name)
        if setting is None:
            raise KeyError(f"Unknown setting '{name}'.")
        if not setting.writable:
            raise ValueError(f"Property '{name}' is read-only.")

        int_value = _resolve_value(setting, value)
        body: dict[str, object] = {setting.prop_key: int_value}
        assert setting.action_id is not None

        if wait:
            result = _publish_and_wait(self._creds, setting.action_id, body, verbose=verbose)
            if result is not None:
                resp = result.get("body")
                if isinstance(resp, dict):
                    return resp
            return None
        else:
            _publish_command(self._creds, setting.action_id, body)
            return None


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _resolve_value(setting: Setting, value: str | int) -> int:
    """Convert a user-facing value to the integer used in MQTT commands."""
    if isinstance(value, int):
        return value
    if setting.values is not None:
        if value not in setting.values:
            raise ValueError(
                f"Invalid value '{value}' for {setting.slug}. "
                f"Expected: {' | '.join(setting.values)}"
            )
        return setting.values.index(value)
    try:
        return int(value)
    except ValueError:
        raise ValueError(
            f"Invalid value '{value}' for {setting.slug}. Expected an integer."
        ) from None


async def _http_login(email: str, password: str) -> dict[str, object]:
    """Perform the encrypted HTTP login and return credentials."""
    mac_id = get_mac_id()
    login_bean = json.dumps(
        {
            "account": email,
            "password": password,
            "loginType": 2,
            "registerAppId": "com.hbxn.jackery",
            "macId": mac_id,
        },
        separators=(",", ":"),
    )

    # Generate random AES key: 16 bytes -> base64 -> 24-char string.
    # The app uses this base64 STRING's bytes (24 bytes, AES-192) as the actual
    # AES key material for encrypting the body AND as the RSA plaintext.
    aes_key_str = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    aes_key_bytes = aes_key_str.encode("utf-8")  # 24 bytes

    encrypted_body = aes_ecb_encrypt(login_bean.encode("utf-8"), aes_key_bytes)
    aes_encrypt_data = base64.b64encode(encrypted_body).decode("ascii")

    encrypted_key = rsa_encrypt(aes_key_bytes, RSA_PUBLIC_KEY_B64)
    rsa_for_aes_key = base64.b64encode(encrypted_key).decode("ascii")

    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{API_BASE}/auth/login",
            params={"aesEncryptData": aes_encrypt_data, "rsaForAesKey": rsa_for_aes_key},
            headers=APP_HEADERS,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            resp.raise_for_status()
            body = await resp.json()

        if body.get("code") != 0:
            msg = body.get("msg", "unknown error")
            raise RuntimeError(f"Login failed: {msg}")

        data = body["data"]
        token = body["token"]

        all_devices = await _fetch_all_devices(token, session)

    creds: dict[str, object] = {
        "userId": data["userId"],
        "mqttPassWord": data["mqttPassWord"],
        "token": token,
        "deviceSn": "",
        "deviceId": "",
        "deviceName": "",
        "email": email,
        "macId": mac_id,
        "devices": all_devices,
    }

    if all_devices:
        device = all_devices[0]
        creds["deviceSn"] = device["devSn"]
        creds["deviceId"] = device["devId"]
        creds["deviceName"] = device["devName"]

    return creds


async def _fetch_all_devices(token: str, session: aiohttp.ClientSession) -> list[dict[str, object]]:
    """Fetch all devices (owned + shared) using the given auth token."""
    auth_headers = {**APP_HEADERS, "token": token}
    all_devices: list[dict[str, object]] = []
    timeout = aiohttp.ClientTimeout(total=15)

    # Owned devices
    async with session.get(
        f"{API_BASE}/device/bind/list", headers=auth_headers, timeout=timeout
    ) as dev_resp:
        dev_resp.raise_for_status()
        dev_body = await dev_resp.json()
    for d in dev_body.get("data") or []:
        all_devices.append(
            {
                "devSn": d["devSn"],
                "devName": d.get("devNickname") or d.get("devName") or d["devSn"],
                "devId": d.get("devId", ""),
                "modelCode": d.get("modelCode", 0),
                "shared": False,
            }
        )

    # Shared devices
    async with session.get(
        f"{API_BASE}/device/bind/shared", headers=auth_headers, timeout=timeout
    ) as shared_resp:
        shared_resp.raise_for_status()
        shared_body = await shared_resp.json()
    shared_data = shared_body.get("data") or {}
    seen_sns: set[object] = {d["devSn"] for d in all_devices}

    for share in shared_data.get("receive", []):
        async with session.post(
            f"{API_BASE}/device/bind/share/list",
            data={
                "bindUserId": str(share["bindUserId"]),
                "level": str(share["level"]),
            },
            headers=auth_headers,
            timeout=timeout,
        ) as mgr_resp:
            mgr_resp.raise_for_status()
            mgr_body = await mgr_resp.json()
        for d in mgr_body.get("data") or []:
            sn = d["devSn"]
            if sn not in seen_sns:
                seen_sns.add(sn)
                all_devices.append(
                    {
                        "devSn": sn,
                        "devName": d.get("devNickname") or d.get("devName") or sn,
                        "devId": d.get("devId", ""),
                        "modelCode": d.get("modelCode", 0),
                        "shared": True,
                        "sharedBy": share.get("userName", ""),
                    }
                )

    return all_devices


async def _fetch_device_properties(
    token: str, device_id: str, session: aiohttp.ClientSession
) -> dict[str, object]:
    """Fetch full property map for a device via HTTP API."""
    auth_headers = {**APP_HEADERS, "token": token}
    async with session.get(
        f"{API_BASE}/device/property",
        params={"deviceId": device_id},
        headers=auth_headers,
        timeout=aiohttp.ClientTimeout(total=15),
    ) as resp:
        resp.raise_for_status()
        body = await resp.json()
    if body.get("code") != 0:
        msg = body.get("msg", "unknown error")
        raise RuntimeError(f"Property fetch failed: {msg}")
    return body.get("data") or {}


# ---------------------------------------------------------------------------
# MQTT
# ---------------------------------------------------------------------------


def _make_mqtt_client(creds: dict[str, object]) -> tuple[mqtt.Client, str]:
    """Create a configured MQTT client. Returns (client, ca_temp_path)."""
    user_id = creds["userId"]
    mac_id = str(creds.get("macId") or get_mac_id())
    mqtt_pw_b64 = str(creds["mqttPassWord"])

    client_id = f"{user_id}@APP"
    username = f"{user_id}@{mac_id}"
    password = derive_mqtt_password(username, mqtt_pw_b64)

    ca_fd, ca_path = tempfile.mkstemp(suffix=".pem")
    os.write(ca_fd, CA_CERT_PEM.encode())
    os.close(ca_fd)

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,  # type: ignore[attr-defined]
        client_id=client_id,
        protocol=mqtt.MQTTv311,
    )
    client.username_pw_set(username, password)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(ca_path)
    client.tls_set_context(ctx)

    return client, ca_path


def _connect_and_wait(client: mqtt.Client, timeout: float = 5) -> None:
    """Connect to the MQTT broker and block until connected."""
    client.connect(MQTT_HOST, MQTT_PORT, keepalive=10)
    client.loop_start()
    deadline = time.time() + timeout
    while not client.is_connected() and time.time() < deadline:
        time.sleep(0.05)
    if not client.is_connected():
        raise ConnectionError("Failed to connect to MQTT broker.")


def _build_command_payload(device_sn: str, action_id: int, body: dict[str, object] | str) -> str:
    """Build the JSON command payload for MQTT publish."""
    ts = int(time.time() * 1000)
    return json.dumps(
        {
            "deviceSn": device_sn,
            "id": ts,
            "version": 0,
            "messageType": "DevicePropertyChange",
            "actionId": action_id,
            "timestamp": ts,
            "body": body,
        },
        separators=(",", ":"),
    )


def _publish_command(creds: dict[str, object], action_id: int, body: dict[str, object]) -> None:
    """Connect to the MQTT broker and publish a device command."""
    user_id = creds["userId"]
    device_sn = str(creds["deviceSn"])
    topic = f"hb/app/{user_id}/command"
    payload = _build_command_payload(device_sn, action_id, body)

    client, ca_path = _make_mqtt_client(creds)
    try:
        _connect_and_wait(client)
        info = client.publish(topic, payload, qos=1)
        info.wait_for_publish(timeout=5)
        client.disconnect()
        client.loop_stop()
    finally:
        os.unlink(ca_path)


def _publish_and_wait(
    creds: dict[str, object],
    action_id: int,
    body: dict[str, object],
    timeout: float = 10,
    verbose: bool = False,
) -> dict[str, object] | None:
    """Publish a command and wait for a DevicePropertyChange response."""
    user_id = creds["userId"]
    device_sn = str(creds["deviceSn"])
    cmd_topic = f"hb/app/{user_id}/command"
    dev_topic = f"hb/app/{user_id}/device"
    payload = _build_command_payload(device_sn, action_id, body)

    result: dict[str, object] | None = None
    done = False

    def on_connect(
        client: mqtt.Client,
        _ud: object,
        _flags: object,
        rc: int,
        _props: object = None,
    ) -> None:
        if rc == 0:
            client.subscribe(dev_topic, qos=1)

    def on_message(
        client: mqtt.Client,
        _ud: object,
        msg: mqtt.MQTTMessage,
    ) -> None:
        nonlocal result, done
        try:
            data = json.loads(msg.payload)
        except json.JSONDecodeError:
            return
        if data.get("deviceSn") != device_sn:
            return
        msg_type = data.get("messageType", "")
        if msg_type == "DevicePropertyChange" and isinstance(data.get("body"), dict):
            resp_body = data["body"]
            if list(resp_body.keys()) == ["messageId"]:
                return
            result = data
            done = True

    client, ca_path = _make_mqtt_client(creds)
    client.on_connect = on_connect
    client.on_message = on_message
    try:
        _connect_and_wait(client)
        time.sleep(0.2)
        client.publish(cmd_topic, payload, qos=1)
        deadline = time.time() + timeout
        while not done and time.time() < deadline:
            time.sleep(0.1)
        client.disconnect()
        client.loop_stop()
    finally:
        os.unlink(ca_path)

    return result
