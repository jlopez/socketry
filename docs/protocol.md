# Jackery Communication Protocol

Reverse-engineered from Jackery Android APK v1.0.7 (`com.hbxn.jackery`,
decompiled with jadx) and iOS app v1.2.0.

## Architecture

```
App ──HTTP──> iot.jackeryapp.com/v1  (login, device list, properties)
App ──MQTT──> emqx.jackeryapp.com:8883  (device control, real-time status updates)
```

The app does a few unauthenticated HTTP calls on launch (version check, banners), then
login via encrypted HTTP POST. After login, device **control** is via MQTT, while **status
polling** uses the HTTP property endpoint. The app subscribes to MQTT topics for real-time
push updates (property changes, online/offline events).

**Important**: The MQTT "query all" command (actionId 254) is BLE-only in the app — the
`ia.c.m()` method only calls the BLE encoder `a()`, never the MQTT JSON builder `v()`.
For status over the network, use `GET /device/property?deviceId={devId}` instead.

## HTTP API

**Base**: `https://iot.jackeryapp.com/v1`
**Common headers**: `platform: 2`, `app_version: 1.2.0`, `token: {jwt}` (post-login)

**Note**: The app's HTTP client (`mh.k`) uses POST for all API calls. Fields on the API
object are serialized as form-encoded body params. Endpoints with no request fields (like
`device/bind/list` and `device/bind/shared`) also accept GET.

### Login: `POST /auth/login`

Encrypted data is sent as query params `aesEncryptData` + `rsaForAesKey`:

1. Generate random 16-byte AES key via `KeyGenerator.getInstance("AES").init(128)`
2. Base64-encode the 16 bytes → 24-character string (this is the key material)
3. JSON-serialize LoginBean: `{"account","password","loginType":2,"registerAppId":"com.hbxn.jackery","macId"}`
4. AES/ECB/PKCS5Padding encrypt JSON using **the 24-byte base64 string as AES-192 key** → base64 → `aesEncryptData`
5. RSA/ECB/PKCS1Padding encrypt **the same 24-byte base64 string** with hardcoded RSA pubkey → base64 → `rsaForAesKey`

**Important**: The AES key is NOT the raw 16 bytes. The app base64-encodes the 16 bytes
to get a 24-char string, then uses that string's UTF-8 bytes (24 bytes) as AES-192 key
material for both encryption and as the RSA plaintext. This is how `ub/f.java:b()` and
`LoginApi.LoginBean` work together — `f.b()` returns `Base64.encodeToString(keyBytes)`
and both `LoginBean.a()` (AES) and `LoginBean.b()` (RSA) operate on `str.getBytes(UTF_8)`.

**RSA public key** (1024-bit, from `ub.b.f25402a`):
```
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCVmzgJy/4XolxPnkfu32YtJqYGFLYqf9/rnVgURJED+8J9J3Pccd6+9L97/+7COZE5OkejsgOkqeLNC9C3r5mhpE4zk/HStss7Q8/5DqkGD1annQ+eoICo3oi0dITZ0Qll56Dowb8lXi6WHViVDdih/oeUwVJY89uJNtTWrz7t7QIDAQAB
```

**Response** contains: `userId`, `mqttPassWord` (base64, 32 bytes = AES-256 key), `token` (JWT)

### Device Endpoints (all require `token` header)

#### Owned Devices

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/device/bind/list` | GET | List owned/bound devices (returns `devSn`, `devId`, `modelCode`, etc.) |
| `/device/property?deviceId={devId}` | GET | Full property map (see Property API Response below) |
| `/device/stat/today?deviceSn=X` | GET | Today's stats |
| `/device/battery/pack/list?deviceSn=X` | GET | Battery pack info |

**Note**: `/device/bind/list` may return `"data": null` instead of an empty array when
there are no owned devices. Always use `or []` / null-coalescing when iterating.

#### Property API Response

`GET /device/property?deviceId={devId}` returns a nested structure:

```json
{
  "code": 0,
  "data": {
    "device": {
      "id": 100000000000000000,
      "modelCode": 12,
      "modelName": "HTE1172000A",
      "deviceSn": "000000000000000",
      "onlineStatus": 1,
      "onlineTime": 1700000000000,
      "offlineTime": 1700000000000,
      "timezoneOffset": -420
    },
    "properties": {
      "rb": 100, "bt": 160, "bs": 0, "ip": 0, "op": 1,
      "it": 0, "ot": 999, "oac": 0, "odc": 0, "lm": 1,
      "cs": 1, "ast": 0, "pm": 0, "lps": 0, "sfc": 0,
      "sltb": 1, "acip": 0, "cip": 0, "acov": 1200,
      "acohz": 60, "acpss": 0, "acpsp": 0, "ec": 0,
      "ta": 0, "pal": 0, "pmb": 0
    }
  }
}
```

The `device` object contains metadata (model, online status, timestamps).
The `properties` object contains the actual device state — same keys as MQTT property changes.

#### Shared Devices

When a device is shared with you (not owned), `/device/bind/list` returns empty.
You need a two-step lookup:

| Endpoint | Method | Params | Purpose |
|----------|--------|--------|---------|
| `/device/bind/shared` | GET | none | Get share relationships. Response: `{share: [...], receive: [...]}` |
| `/device/bind/share/list` | POST | `bindUserId`, `level` (form body) | List devices in a share relationship |
| `/device/bind/remove` | POST | `bindUserId`, `devId` | Remove one device from share |
| `/device/bind/removeAll` | POST | `bindUserId`, `level` | Remove all devices from share |
| `/device/accept_bind` | POST | | Accept a sharing invitation |
| `/device/bind/qrcode` | | | QR code for sharing |
| `/device/bind/nickname` | | | Change device nickname |

**Share relationship response** (`GET /device/bind/shared`):
```json
{
  "data": {
    "receive": [
      {
        "bindUserId": 100000000000000000,
        "level": 2,
        "count": 1,
        "userName": "alice",
        "account": "ali***.com",
        "avatar": null
      }
    ],
    "share": []
  }
}
```

- `receive` = devices others shared WITH you
- `share` = devices YOU shared with others
- `level` 2 = full control, `level` 3 = read-only

**Shared device list response** (`POST /device/bind/share/list`):
Returns array of `{devId, devSn, devModel, devName, devNickname, icon}`.

#### Auth Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/auth/verificationCode?email=X&method=modify` | POST | Request verification code |
| `/auth/modifyPassword?...` | POST | Change password |
| `/auth/generatedJwt` | GET | Get Zendesk JWT for support chat |

## MQTT Protocol

### Connection (from `db.f.java`)

| Parameter | Value |
|-----------|-------|
| Broker | `emqx.jackeryapp.com` |
| Port | `8883` (TLS 1.2) |
| CA cert | Self-signed `ca.jackery.com` (bundled in APK `res/raw/ca.crt`) |
| Client ID | `{userId}@APP` |
| Username | `{userId}@{macId}` |
| Password | `base64(AES/CBC/PKCS5Padding(username_bytes, key=b64decode(mqttPassWord), iv=key[:16]))` |
| Keep alive | 10s |

The key is 32 bytes (AES-256-CBC). IV = first 16 bytes of key.

### Topics

**Subscribe** (status from device):
- `hb/app/{userId}/notice` — notifications
- `hb/app/{userId}/alert` — alerts
- `hb/app/{userId}/config` — config changes
- `hb/app/{userId}/device` — device property changes (main one)

**Publish** (commands to device):
- `hb/app/{userId}/command` — all commands, QoS 1

### Message Types (from `la.a` enum)

- `DevicePropertyChange` — property update / command
- `SubDevicePropertyChange` — battery pack changes
- `DeviceOnlineChange` — online/offline (body: `{"online": 0|1}`)
- `DeviceUnbind` — device unbound
- `DeviceUpgradeProgress` — firmware OTA progress

### Command Payload Format (from `ia.c.java`)

The MQTT JSON builder (`ia.c.v()`) uses `String.format` with the body embedded as a **raw
JSON value** (not a string). The format string is:

```
{"deviceSn":"%s","id":%s,"version":%s,"messageType":"%s","actionId":%s,"timestamp":%s,"body":%s}
```

Example (light low):
```json
{
  "deviceSn": "000000000000000",
  "id": 1700000000000,
  "version": 0,
  "messageType": "DevicePropertyChange",
  "actionId": 7,
  "timestamp": 1700000000000,
  "body": {"lm": 1}
}
```

### Broker Acknowledgment

When a command is published, the broker immediately responds on the device topic with an
ack containing `"body": {"messageId": 0}`. This is NOT the device's response — it's the
broker confirming it accepted the command. The device (if online) responds separately with
a full property change message.

### Action IDs and Body Keys (from `ia.c.java` + `controller/j.java`)

| Action | ID | Body | Description |
|--------|----|------|-------------|
| DC output | 1 | `{"odc": 0\|1}` | DC output on/off |
| USB output | 2 | `{"odcu": 0\|1}` | USB output on/off |
| Car output | 3 | `{"odcc": 0\|1}` | Car (12V) output on/off |
| AC output | 4 | `{"oac": 0\|1}` | AC output on/off |
| AC input | 5 | `{"iac": 0\|1}` | AC input on/off |
| DC input | 6 | `{"idc": 0\|1}` | DC input on/off |
| Light mode | 7 | `{"lm": n}` | 0=off, 1=low, 2=high, 3=SOS |
| Screen timeout | 8 | `{"slt": n}` | Screen timeout value |
| Auto shutdown | 9 | `{"ast": n}` | Auto shutdown time |
| Charge speed | 10 | `{"cs": n}` | Charge speed mode (0=fast, 1=mute) |
| Battery protection | 11 | `{"lps": n}` | Low-power shutdown (0=full, 1=save/eco) |
| Energy saving | 12 | `{"pm": n}` | Power mode / energy saving timeout |
| Super fast charge | 13 | `{"sfc": n}` | Super fast charge on/off |
| UPS mode | 14 | `{"ups": n}` | UPS mode (0=off, 1=on) |
| Wi-Fi setup | 253 | `{"s":"ssid","p":"pass"}` | Wi-Fi credentials (MQTT: 100s timeout) |
| Query all (BLE only) | 254 | `""` | Request full status (30s timeout) |
| Heartbeat (BLE only) | 249 | `""` | Keep-alive ping |

**Note on actionId 254 (Query All)**: This is BLE-only. In the APK, `ia.c.m()` calls
`a("", 254, 1)` which is the BLE RC4 encoder — it never calls the MQTT JSON builder `v()`.
For network-based status polling, use `GET /device/property?deviceId={devId}` instead.

### Device Properties

All values are integers. Some require scaling (noted below).

```json
{
  "rb": 100,      // remaining battery % (0-100)
  "bt": 160,      // battery temp (divide by 10 → 16.0°C)
  "bs": 0,        // battery status (0=idle, 1=charging, 2=discharging)
  "ip": 0,        // input power (W)
  "op": 1,        // output power (W)
  "it": 0,        // input time remaining (divide by 10 → hours, 0=N/A)
  "ot": 999,      // output time remaining (divide by 10 → 99.9h)
  "oac": 0,       // AC output state (0=off, 1=on)
  "odc": 0,       // DC output state (0=off, 1=on)
  "odcu": 0,      // USB output state (0=off, 1=on)
  "odcc": 0,      // car output state (0=off, 1=on)
  "iac": 0,       // AC input state (0=off, 1=on)
  "idc": 0,       // DC input state (0=off, 1=on)
  "lm": 1,        // light mode (0=off, 1=low, 2=high, 3=SOS)
  "cs": 1,        // charge speed (0=fast, 1=mute)
  "ast": 0,       // auto shutdown time
  "pm": 0,        // energy saving mode / power mode timeout
  "lps": 0,       // battery protection (0=full, 1=save/eco)
  "sfc": 0,       // super fast charge (0=off, 1=on)
  "ups": 0,       // UPS mode (0=off, 1=on)
  "sltb": 1,      // screen lock timeout
  "acip": 0,      // AC input power (W)
  "cip": 0,       // car input power (W)
  "acov": 1200,   // AC output voltage (divide by 10 → 120.0V)
  "acohz": 60,    // AC output frequency (Hz)
  "acps": 0,      // AC power (W)
  "acpss": 0,     // AC power socket state (secondary)
  "acpsp": 0,     // AC power socket power (W)
  "wss": 0,       // wireless charging state (0=off, 1=on)
  "ec": 0,        // error/exception code
  "ta": 0,        // temperature alarm
  "pal": 0,       // power alarm / protection level
  "pmb": 0        // power mode battery threshold
}
```

### Battery Pack Properties (SubDevicePropertyChange)

For devices with expansion battery packs, property changes come as `SubDevicePropertyChange`
with a `subDevices` array in the body:

```json
{
  "messageType": "SubDevicePropertyChange",
  "deviceSn": "000000000000000",
  "body": {
    "subDevices": [
      {
        "deviceSn": "JE-BP-...",
        "rb": 80,
        "ip": 0,
        "op": 60,
        "ec": 0,
        "it": 25,
        "ot": 26
      }
    ]
  }
}
```

## Device Models (from `ha/c.java`)

| Model Code | Enum | Name |
|------------|------|------|
| 1 | `PORTABLE_097` | Explorer 3000 Pro |
| 2 | `PORTABLE_099` | Explorer 2000 Plus |
| 4 | `PORTABLE_095` | Explorer 300 Plus |
| 5 | `PORTABLE_103` | Explorer 1000 Plus |
| 6 | `PORTABLE_102` | Explorer 700 Plus |
| 7 | `PORTABLE_280` | Explorer 280 Plus |
| 8 | `PORTABLE_109` | Explorer 1000 Pro2 |
| 9 | `PORTABLE_112` | Explorer 600 Plus |
| 10 | `PORTABLE_110` | Explorer 240 |
| 12 | `PORTABLE_117` | Explorer 2000 |

### Model Capabilities (from `ja.b` interface, per-model `ka.*` classes)

Not all models support all features. Capability flags per model:

| Capability | Method | Models with it |
|------------|--------|----------------|
| Battery expansion pack | `b()` | 2000 Plus, 1000 Plus, 3000 Pro |
| Battery protection (lps) | `c()` | Most models |
| Energy saving time (pm) | `e()` | Most models |
| Charge speed (cs) | `f()` | Most models |
| Extended energy saving | `g()` | Varies |
| Sub-device support | `h()` | 2000 Plus, 1000 Plus, 3000 Pro |
| Auto shutdown (ast) | `j()` | Most models |
| BLE query | `k()` | All models |
| UPS mode (ups) | `l()` | 2000, 2000 Plus, 1000 Plus, 3000 Pro |

## Implementation Notes

### AES Key Format Mismatch (error 10400)

The login encryption has a subtle key format issue. The app generates 16 random bytes,
base64-encodes them to a 24-character string, then uses **the string's UTF-8 bytes**
(24 bytes = AES-192) as the key material for both AES body encryption and RSA key
encryption. An implementation that uses the raw 16 bytes for AES but base64's
them for RSA will cause error 10400 (server-side decryption failure) because the server
decrypts the RSA to get the 24-byte string, then uses those 24 bytes as AES-192 to
decrypt the body.

**Key source files**: `ub/f.java:b()` (key generation), `LoginApi.LoginBean.a()` (AES),
`LoginApi.LoginBean.b()` (RSA), `eb/b.java:s1()` (caller that passes same `strB` to both).

### Shared Device Lookup

`GET /device/bind/list` only returns **owned** devices. For shared devices (device owned
by another user who granted access), requires two API calls:
1. `GET /device/bind/shared` → get `receive` array with share relationships
2. `POST /device/bind/share/list` with form body `{bindUserId, level}` → get actual devices

The second endpoint MUST be POST with form-encoded body (not GET with query params) —
the app's HTTP framework (`mh.k`) sends all API requests as POST with `FormBody`.

### Null Data in API Responses

Several API endpoints return `"data": null` instead of empty arrays/objects when there are
no results. Always use `or []` / `or {}` instead of `.get("data", [])` — the latter returns
`None` when the key exists with a null value.

### Query All (actionId 254) is BLE-Only

The app's `ia.c.m()` for query-all only calls `a("", 254, 1)` — the BLE RC4 encoder. It
never routes through `b()` (the transport-aware dispatcher) or `v()` (the MQTT JSON builder).
This means the app literally cannot query-all over MQTT — it's a BLE-only operation. The
app gets initial device state from `GET /device/property` and relies on MQTT push for
real-time updates after that.

## Key Source Files in Decompiled APK

| File | Content |
|------|---------|
| `sources/db/f.java` | **MQTT client** — connection, auth, subscribe, publish, reconnect. `q()` dispatches incoming messages. |
| `sources/ia/b.java` | **Command format strings** — JSON templates for all commands |
| `sources/ia/c.java` | **Command builder** — `a()` = BLE encoder, `b()` = transport dispatcher, `v()` = MQTT JSON builder. `m()` = query-all (BLE-only bug) |
| `sources/com/hbxn/jackery/controller/j.java` | **Device controller** — all control methods: `c0()` light, `d0()` AC out, `e0()` DC out, etc. `z()` = query-all |
| `sources/com/hbxn/jackery/controller/g.java` | **Base controller** — `V()` BLE/MQTT dispatch, topic setup |
| `sources/com/hbxn/jackery/controller/DeviceControllerManager.java` | **Singleton** — one active device controller at a time |
| `sources/fa/f.java` | **Device adapter** — `b(Map)` handles MQTT property changes, `c(Map)` handles BLE. Delta-merges into `PortableBean` |
| `sources/com/hbxn/control/device/bean/body/PortableBody.java` | **Full property model** — all int fields matching the property keys |
| `sources/com/hbxn/control/device/bean/body/BatteryPackBody.java` | **Battery pack model** — sub-device properties |
| `sources/ha/c.java` | **Device models enum** — model codes to names |
| `sources/ka/*.java` | **Per-model capability classes** — which features each model supports |
| `sources/com/hbxn/jackery/http/api/LoginApi.java` | **Login API** — AES+RSA encryption, `mqttPassWord` in response |
| `sources/com/hbxn/jackery/http/api/DeviceSharedListApi.java` | **Shared device list** — share/receive relationships |
| `sources/com/hbxn/jackery/http/api/DeviceSharedManagerListApi.java` | **Shared device details** — devices in a share |
| `sources/com/hbxn/jackery/http/api/UserDeviceListApi.java` | **Owned device list** — bound devices. `Bean` has all device fields |
| `sources/com/hbxn/jackery/ui/activity/mine/SharedActivity.java` | **Shared UI** — displays share/receive tabs |
| `sources/com/hbxn/jackery/ui/activity/mine/SharedManagerActivity.java` | **Share manager UI** — manage devices in a share |
| `sources/eb/b.java` | **Login flow** — calls `f.b()` for key, then `LoginBean.a()` + `LoginBean.b()` |
| `sources/ub/f.java` | **AES key generation** — `b()` returns base64 of 16 random bytes. Also stores device list in MMKV |
| `sources/mh/k.java` | **HTTP client** — always POST, form-encoded body |
| `sources/mh/c.java` | **HTTP request builder** — `FormBody` serialization of API fields |
| `sources/com/blankj/utilcode/util/c0.java` | **Crypto utils** — AES/RSA encrypt/decrypt |
| `sources/com/blankj/utilcode/util/b0.java` | **Base64 utils** — encode/decode wrappers |
| `sources/xa/a.java` | **Build config** — API base URL, MQTT host/port, app key |
| `sources/ub/b.java` | **Constants** — RSA public key, API URLs, storage keys |
| `sources/oa/a.java` | **Command topic** — `hb/app/%s/command` |
| `sources/la/a.java` | **Message types enum** — DevicePropertyChange, SubDevicePropertyChange, etc. |
| `sources/ma/a.java` | **Action ID constants** — `f20034a` through `f20052s` |
| `sources/com/hbxn/control/device/protocol/MqttBean.java` | MQTT message wrapper (body + deviceSn) |
| `sources/com/hbxn/control/device/protocol/MqttBody.java` | MQTT body (online, status, expireTimestamp, subDevices) |
| `sources/com/hbxn/jackery/ui/activity/portable/PortablePanelActivity.java` | **Panel UI** — light values: line 811 (low=1), 817 (high=2), 823 (SOS=3) |
| `resources/res/raw/ca.crt` | Self-signed CA cert for `ca.jackery.com` (PEM) |
