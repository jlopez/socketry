"""Jackery power station API client.

Provides programmatic access to Jackery power stations via their cloud
HTTP API and MQTT broker.  The :class:`Client` class is the main entry
point; use :meth:`~Client.device` to obtain :class:`Device` objects for
per-device operations::

    import asyncio
    from socketry import Client

    client = await Client.login("email@example.com", "password")
    devices = await client.fetch_devices()

    device = client.device(0)
    props = await device.get_all_properties()
    await device.set_property("ac", "on", wait=True)

    # Subscribe to real-time updates for all devices
    sub = await client.subscribe(lambda sn, props: print(sn, props))
    await sub.wait()
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import secrets
import ssl
import time
from collections.abc import Awaitable, Callable

import aiohttp
import aiomqtt

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

_TOKEN_EXPIRY_BUFFER = 3600  # seconds before expiry to trigger proactive refresh


class TokenExpiredError(RuntimeError):
    """Raised when the Jackery API returns error code 10402 (token expired)."""


class MqttError(ConnectionError):
    """Raised when an MQTT operation fails.

    Wraps :class:`aiomqtt.MqttError` so callers do not need to import
    ``aiomqtt`` to catch MQTT-related failures from :meth:`Client.set_property`
    or :meth:`Device.set_property`.
    """


class Device:
    """A specific Jackery device.

    Obtained via :meth:`Client.device`.  Provides per-device operations
    without changing the global selected device on the parent
    :class:`Client`.

    Example::

        device = client.device(0)
        props = await device.get_all_properties()
        await device.set_property("ac", "on")
    """

    def __init__(self, client: Client, dev_info: dict[str, object]) -> None:
        self._client = client
        self._sn = str(dev_info["devSn"])
        self._id = str(dev_info.get("devId", ""))
        self._name = str(dev_info.get("devName", self._sn))
        self._model_code = int(str(dev_info.get("modelCode", 0) or 0))

    @property
    def sn(self) -> str:
        """Serial number of this device."""
        return self._sn

    @property
    def device_id(self) -> str:
        """Internal device ID (used for HTTP property queries)."""
        return self._id

    @property
    def name(self) -> str:
        """Display name of this device."""
        return self._name

    @property
    def model_code(self) -> int:
        """Jackery model code."""
        return self._model_code

    async def get_all_properties(self) -> dict[str, object]:
        """Fetch the full property map for this device.

        Returns the raw ``data`` dict from the HTTP API, containing
        ``device`` metadata and ``properties`` map.
        """
        if not self._id:
            raise ValueError(f"Device {self._sn} has no deviceId.")
        await self._client._ensure_fresh_token()
        async with aiohttp.ClientSession() as session:
            try:
                return await _fetch_device_properties(self._client.token, self._id, session)
            except TokenExpiredError:
                self._client._creds["tokenExp"] = 0
                await self._client._ensure_fresh_token()
                return await _fetch_device_properties(self._client.token, self._id, session)

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

    async def set_property(
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
            verbose: Reserved for future debug logging.

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

        try:
            if wait:
                result = await self._client._publish_and_wait(
                    self._sn,
                    setting.action_id,
                    body,
                    expected_keys=set(body.keys()),
                    verbose=verbose,
                )
                if result is not None:
                    resp = result.get("body")
                    if isinstance(resp, dict):
                        return resp
                return None
            else:
                await self._client._publish_command(self._sn, setting.action_id, body)
                return None
        except aiomqtt.MqttError as e:
            raise MqttError(str(e)) from e


class Client:
    """Jackery power station API client.

    Use :meth:`login` to authenticate, or :meth:`from_saved` to load
    previously saved credentials.

    For multi-device use, obtain :class:`Device` objects via
    :meth:`device` rather than the single-device selection pattern.
    """

    def __init__(self, credentials: dict[str, object], *, auto_save: bool = False) -> None:
        self._creds = credentials
        self._auto_save = auto_save
        self._active_mqtt: aiomqtt.Client | None = None
        self._pending_responses: list[
            tuple[
                Callable[[str, dict[str, object]], bool],
                asyncio.Future[tuple[str, dict[str, object]]],
            ]
        ] = []
        self._refresh_lock = asyncio.Lock()

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
        return cls(creds, auto_save=True)

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

    @property
    def user_id(self) -> str:
        """Authenticated user ID."""
        return str(self._creds.get("userId", ""))

    # ------------------------------------------------------------------
    # Token refresh
    # ------------------------------------------------------------------

    async def _ensure_fresh_token(self) -> None:
        """Proactively re-authenticate if the token is within the expiry buffer.

        Reads ``email`` and ``password`` from stored credentials and calls
        :func:`_http_login` without fetching devices.  Only the auth fields
        (``token``, ``mqttPassWord``, ``tokenExp``) are updated so that the
        device selection is preserved.

        No-ops silently when credentials lack an email/password (e.g. a client
        built from a credentials dict that predates this feature).
        """
        exp = self._creds.get("tokenExp")
        if exp is not None and time.time() < float(str(exp)) - _TOKEN_EXPIRY_BUFFER:
            return

        email = str(self._creds.get("email", ""))
        password = str(self._creds.get("password", ""))
        if not email or not password:
            return

        async with self._refresh_lock:
            # Re-check after acquiring the lock: another task may have already
            # refreshed while we were waiting.
            exp = self._creds.get("tokenExp")
            if exp is not None and time.time() < float(str(exp)) - _TOKEN_EXPIRY_BUFFER:
                return

            new_creds = await _http_login(email, password, fetch_devices=False)
            self._creds["token"] = new_creds["token"]
            self._creds["mqttPassWord"] = new_creds["mqttPassWord"]
            self._creds["tokenExp"] = new_creds.get("tokenExp")
            # Persist immediately so the next process doesn't re-login unnecessarily.
            # Only auto-save for clients that were loaded from disk (from_saved()).
            if self._auto_save:
                self.save_credentials()

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    async def fetch_devices(self) -> list[dict[str, object]]:
        """Refresh the device list from the API.

        Updates the internal cache and returns all devices.
        """
        await self._ensure_fresh_token()
        async with aiohttp.ClientSession() as session:
            try:
                all_devices = await _fetch_all_devices(self.token, session)
            except TokenExpiredError:
                self._creds["tokenExp"] = 0
                await self._ensure_fresh_token()
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

    def device(self, index_or_sn: int | str) -> Device:
        """Return a :class:`Device` for the given index or serial number.

        Args:
            index_or_sn: Zero-based index into :attr:`devices`, or the
                device serial number string.

        Raises:
            IndexError: If an integer index is out of range, or no
                devices are cached (integer lookup only).
            KeyError: If a serial-number string is not found, or no
                devices are cached (string lookup only).
        """
        devs = self.devices
        if not devs:
            if isinstance(index_or_sn, str):
                raise KeyError(
                    f"No device with SN '{index_or_sn}': device list is empty. "
                    "Call fetch_devices() first."
                )
            raise IndexError("No cached device list. Call fetch_devices() first.")
        if isinstance(index_or_sn, int):
            if index_or_sn < 0 or index_or_sn >= len(devs):
                raise IndexError(f"Invalid index {index_or_sn}. Must be 0..{len(devs) - 1}.")
            return Device(self, devs[index_or_sn])
        for dev in devs:
            if dev["devSn"] == index_or_sn:
                return Device(self, dev)
        raise KeyError(f"No device with SN '{index_or_sn}'.")

    # ------------------------------------------------------------------
    # Status (HTTP)
    # ------------------------------------------------------------------

    async def get_all_properties(self) -> dict[str, object]:
        """Fetch the full property map for the selected device.

        Returns the raw ``data`` dict from the HTTP API, containing
        ``device`` metadata and ``properties`` map.
        """
        if not self.device_id:
            raise ValueError("No deviceId. Call login() or select_device() first.")
        await self._ensure_fresh_token()
        async with aiohttp.ClientSession() as session:
            try:
                return await _fetch_device_properties(self.token, self.device_id, session)
            except TokenExpiredError:
                self._creds["tokenExp"] = 0
                await self._ensure_fresh_token()
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
    # Subscription (MQTT)
    # ------------------------------------------------------------------

    async def subscribe(
        self,
        callback: Callable[[str, dict[str, object]], Awaitable[None]],
        *,
        on_disconnect: Callable[[], Awaitable[None]] | None = None,
    ) -> Subscription:
        """Subscribe to real-time property updates from all devices.

        The *callback* is invoked with ``(device_sn, properties)`` for
        every ``DevicePropertyChange`` message received on the device
        topic.  Messages are **not** filtered by device — the consumer
        receives updates for all devices on the account.

        If *on_disconnect* is provided it is called whenever the broker
        disconnects and the loop is about to reconnect.

        While a subscription is active, :meth:`set_property` and
        :meth:`Device.set_property` publish commands through the shared
        connection instead of opening a new one, avoiding broker
        kick-offs.

        Returns a :class:`Subscription` whose :meth:`~Subscription.stop`
        method cancels the background listener.
        """
        task = asyncio.create_task(self._run_subscribe_loop(callback, on_disconnect=on_disconnect))
        return Subscription(task, self)

    # ------------------------------------------------------------------
    # Control (MQTT)
    # ------------------------------------------------------------------

    async def set_property(
        self,
        name: str,
        value: str | int,
        *,
        wait: bool = False,
        verbose: bool = False,
    ) -> dict[str, object] | None:
        """Change the selected device's setting via MQTT.

        Args:
            name: Setting slug or raw key (e.g. ``"ac"``, ``"oac"``).
            value: Named value (``"on"``, ``"off"``) or integer.
            wait: If ``True``, wait for device confirmation.
            verbose: Reserved for future debug logging.

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

        try:
            if wait:
                result = await self._publish_and_wait(
                    self.device_sn,
                    setting.action_id,
                    body,
                    expected_keys=set(body.keys()),
                    verbose=verbose,
                )
                if result is not None:
                    resp = result.get("body")
                    if isinstance(resp, dict):
                        return resp
                return None
            else:
                await self._publish_command(self.device_sn, setting.action_id, body)
                return None
        except aiomqtt.MqttError as e:
            raise MqttError(str(e)) from e

    # ------------------------------------------------------------------
    # Private MQTT methods
    # ------------------------------------------------------------------

    async def _publish_command(
        self, device_sn: str, action_id: int, body: dict[str, object]
    ) -> None:
        """Publish a device command, reusing the active connection if available."""
        user_id = self._creds["userId"]
        topic = f"hb/app/{user_id}/command"
        payload = _build_command_payload(device_sn, action_id, body)

        if self._active_mqtt is not None:
            await self._active_mqtt.publish(topic, payload, qos=1)
        else:
            async with aiomqtt.Client(**_mqtt_params(self._creds)) as client:  # type: ignore[arg-type]
                await client.publish(topic, payload, qos=1)

    async def _publish_and_wait(
        self,
        device_sn: str,
        action_id: int,
        body: dict[str, object],
        *,
        expected_keys: set[str],
        timeout: float = 10,
        verbose: bool = False,
    ) -> dict[str, object] | None:
        """Publish a command and wait for the device to echo the commanded keys.

        *expected_keys* is the set of property keys present in *body*.
        Only a ``DevicePropertyChange`` message that contains at least
        one of those keys (and matches *device_sn*) is accepted as the
        confirmation — unrelated periodic status updates are ignored.

        When a subscription is active the shared connection is used for
        both publish and response dispatch; otherwise a short-lived
        connection is opened.
        """
        user_id = self._creds["userId"]
        cmd_topic = f"hb/app/{user_id}/command"
        payload = _build_command_payload(device_sn, action_id, body)

        def predicate(sn: str, props: dict[str, object]) -> bool:
            return sn == device_sn and bool(expected_keys & props.keys())

        if self._active_mqtt is not None:
            # Shared connection path: register a pending response then publish.
            future: asyncio.Future[tuple[str, dict[str, object]]] = (
                asyncio.get_running_loop().create_future()
            )
            self._pending_responses.append((predicate, future))
            await self._active_mqtt.publish(cmd_topic, payload, qos=1)
            try:
                async with asyncio.timeout(timeout):
                    sn, props = await future
                    return {
                        "deviceSn": sn,
                        "messageType": "DevicePropertyChange",
                        "body": props,
                    }
            except TimeoutError:
                self._pending_responses = [
                    (p, f) for p, f in self._pending_responses if f is not future
                ]
                return None
        else:
            # No active subscription: open a short-lived connection.
            dev_topic = f"hb/app/{user_id}/device"
            async with aiomqtt.Client(**_mqtt_params(self._creds)) as mqtt_client:  # type: ignore[arg-type]
                await mqtt_client.subscribe(dev_topic, qos=1)
                await mqtt_client.publish(cmd_topic, payload, qos=1)
                try:
                    async with asyncio.timeout(timeout):
                        async for message in mqtt_client.messages:
                            parsed = _parse_device_update(message.payload)
                            if parsed is None:
                                continue
                            msg_sn, props = parsed
                            if predicate(msg_sn, props):
                                return {
                                    "deviceSn": msg_sn,
                                    "messageType": "DevicePropertyChange",
                                    "body": props,
                                }
                except TimeoutError:
                    pass
            return None

    async def _run_subscribe_loop(
        self,
        callback: Callable[[str, dict[str, object]], Awaitable[None]],
        *,
        on_disconnect: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        """Persistent MQTT listener that sets ``_active_mqtt`` while connected.

        Uses the standard client ID (``{userId}@APP``) because the Jackery
        broker enforces ACLs tied to this identifier.  The shared
        connection allows :meth:`_publish_command` and
        :meth:`_publish_and_wait` to reuse it rather than opening a new
        connection that would kick this subscription off.

        Pending one-shot responses (from ``_publish_and_wait``) are
        resolved before the user *callback* is invoked.
        """
        user_id = self._creds["userId"]
        dev_topic = f"hb/app/{user_id}/device"

        while True:
            await self._ensure_fresh_token()
            try:
                params = _mqtt_params(self._creds)
                async with aiomqtt.Client(**params) as mqtt_client:  # type: ignore[arg-type]
                    self._active_mqtt = mqtt_client
                    try:
                        await mqtt_client.subscribe(dev_topic, qos=1)
                        async for message in mqtt_client.messages:
                            parsed = _parse_device_update(message.payload)
                            if parsed is None:
                                continue
                            msg_sn, props = parsed
                            # Resolve any pending _publish_and_wait futures first.
                            for i, (pred, fut) in enumerate(self._pending_responses):
                                if not fut.done() and pred(msg_sn, props):
                                    fut.set_result((msg_sn, props))
                                    self._pending_responses.pop(i)
                                    break
                            await callback(msg_sn, props)
                    finally:
                        self._active_mqtt = None
            except aiomqtt.MqttError:
                pass
            # Notify and retry whether the disconnect was an error or a clean
            # broker close (e.g. another client took the same MQTT client ID).
            # CancelledError is NOT caught above, so stop() still works.
            if on_disconnect is not None:
                await on_disconnect()
            await asyncio.sleep(_RECONNECT_INTERVAL)


class Subscription:
    """Handle for a persistent MQTT subscription.

    Returned by :meth:`Client.subscribe`.  Call :meth:`stop` to cancel
    the background listener, or :meth:`wait` to block until the
    subscription ends (e.g. via cancellation or error).
    """

    def __init__(self, task: asyncio.Task[None], client: Client) -> None:
        self._task = task
        self._client = client

    @property
    def is_connected(self) -> bool:
        """True when the MQTT broker connection is currently established."""
        return self._client._active_mqtt is not None

    async def stop(self) -> None:
        """Cancel the subscription and wait for cleanup."""
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await self._task

    async def wait(self) -> None:
        """Wait until the subscription ends.

        Raises :class:`asyncio.CancelledError` if the task is cancelled
        externally (e.g. by *Ctrl-C*).
        """
        await self._task


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _decode_jwt_exp(token: str) -> float | None:
    """Extract the ``exp`` claim from a JWT without verifying the signature.

    Returns the expiry as a Unix timestamp (float), or ``None`` if the token
    cannot be decoded (e.g. not a JWT, malformed base64, missing claim).
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        # base64url padding: length must be a multiple of 4
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        return float(payload["exp"])
    except Exception:
        return None


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


async def _http_login(
    email: str, password: str, *, fetch_devices: bool = True
) -> dict[str, object]:
    """Perform the encrypted HTTP login and return credentials.

    When *fetch_devices* is ``False`` the device list is not fetched —
    ``devices`` will be an empty list and the device selection fields will
    be empty strings.  This is used by :meth:`Client._ensure_fresh_token`
    to avoid redundant API calls when only the auth token needs refreshing.
    """
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

        all_devices = await _fetch_all_devices(token, session) if fetch_devices else []

    creds: dict[str, object] = {
        "userId": data["userId"],
        "mqttPassWord": data["mqttPassWord"],
        "token": token,
        "tokenExp": _decode_jwt_exp(token),
        "email": email,
        "password": password,
        "macId": mac_id,
        "deviceSn": "",
        "deviceId": "",
        "deviceName": "",
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
    if dev_body.get("code") == 10402:
        raise TokenExpiredError("Token expired (10402)")
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
    if body.get("code") == 10402:
        raise TokenExpiredError("Token expired (10402)")
    if body.get("code") != 0:
        msg = body.get("msg", "unknown error")
        raise RuntimeError(f"Property fetch failed: {msg}")
    return body.get("data") or {}


# ---------------------------------------------------------------------------
# MQTT
# ---------------------------------------------------------------------------


def _make_tls_context() -> ssl.SSLContext:
    """Create an SSL context using the embedded Jackery CA certificate."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cadata=CA_CERT_PEM)
    return ctx


def _mqtt_params(creds: dict[str, object]) -> dict[str, object]:
    """Derive aiomqtt.Client constructor kwargs from stored credentials."""
    user_id = creds["userId"]
    mac_id = str(creds.get("macId") or get_mac_id())
    mqtt_pw_b64 = str(creds["mqttPassWord"])

    username = f"{user_id}@{mac_id}"
    password = derive_mqtt_password(username, mqtt_pw_b64)

    return {
        "hostname": MQTT_HOST,
        "port": MQTT_PORT,
        "identifier": f"{user_id}@APP",
        "username": username,
        "password": password,
        "tls_context": _make_tls_context(),
        "keepalive": 10,
    }


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


def _parse_device_update(
    payload: bytes | bytearray,
) -> tuple[str, dict[str, object]] | None:
    """Parse an MQTT message into ``(device_sn, properties)`` or ``None``.

    Returns ``None`` for non-JSON payloads, non-``DevicePropertyChange``
    messages, non-dict bodies, and broker ACKs (body with only
    ``messageId``).  The ``messageId`` key is always stripped from the
    returned properties since it is protocol metadata, not a device
    property.
    """
    try:
        data: dict[str, object] = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return None
    device_sn = data.get("deviceSn")
    if not isinstance(device_sn, str):
        return None
    if data.get("messageType") != "DevicePropertyChange":
        return None
    body = data.get("body")
    if not isinstance(body, dict):
        return None
    # Strip protocol-level messageId — it's not a device property
    props = {k: v for k, v in body.items() if k != "messageId"}
    if not props:
        return None
    return device_sn, props


_RECONNECT_INTERVAL = 5  # seconds between reconnection attempts
