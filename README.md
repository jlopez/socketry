# socketry

[![CI](https://github.com/jlopez/socketry/actions/workflows/ci.yml/badge.svg)](https://github.com/jlopez/socketry/actions/workflows/ci.yml)
![Coverage](https://img.shields.io/badge/coverage-59%25-orange)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)

Python API and CLI for controlling Jackery portable power stations.

Reverse-engineered from the Jackery Android APK (v1.0.7) and iOS app (v1.2.0).
Communicates via Jackery's cloud MQTT broker and HTTP API — no modifications to
the device or its firmware.

## Quick start

```bash
uvx socketry login --email you@example.com --password 'yourpass'
uvx socketry get
```

Or install it once and use `socketry` directly:

```bash
uv tool install socketry
socketry login --email you@example.com --password 'yourpass'
socketry get
```

## Supported devices

All 10 models in the current Jackery app share the same protocol:

| Model | Code |
|-------|------|
| Explorer 3000 Pro | 1 |
| Explorer 2000 Plus | 2 |
| Explorer 300 Plus | 4 |
| Explorer 1000 Plus | 5 |
| Explorer 700 Plus | 6 |
| Explorer 280 Plus | 7 |
| Explorer 1000 Pro2 | 8 |
| Explorer 600 Plus | 9 |
| Explorer 240 | 10 |
| Explorer 2000 | 12 |

Properties and MQTT action IDs are exhaustive for this APK version. Unknown
properties returned by newer firmware are displayed as raw key/value pairs.

## Install

```bash
# Install as a CLI tool
uv tool install socketry

# Or run directly without installing
uvx socketry --help

# Or install as a library
pip install socketry
```

## CLI usage

### Login

```bash
# Authenticates and discovers all devices (owned + shared with you)
socketry login --email you@example.com --password 'yourpass'

# List devices and select the active one
socketry devices
socketry select 0
```

Credentials are saved to `~/.config/socketry/credentials.json` (mode 0600).

### Reading properties (`get`)

```bash
# All properties (colored + grouped on a TTY)
socketry get

# Single property — by CLI name or raw protocol key
socketry get battery          # Battery: 85%
socketry get rb               # Battery: 85% (same thing)
socketry get ac               # AC output: ON

# JSON output (indented on TTY, compact when piped)
socketry get --json
socketry get ac --json        # {"oac": 1}
socketry get --json | jq .rb  # pipe-friendly
```

Available properties:

| Group | Names |
|-------|-------|
| Battery & Power | `battery`, `battery-temp`, `battery-state`, `input-power`, `output-power`, `input-time`, `output-time` |
| I/O State | `ac`, `dc`, `usb`, `car`, `ac-in`, `dc-in`, `light`, `wireless` |
| Settings | `charge-speed`, `auto-shutdown`, `energy-saving`, `battery-protection`, `sfc`, `ups`, `screen-timeout` |
| AC / Power Detail | `ac-input-power`, `car-input-power`, `ac-voltage`, `ac-freq`, `ac-power`, `ac-power-2`, `ac-socket-power` |
| Other / Alarms | `error-code`, `temp-alarm`, `power-alarm`, `power-mode-battery`, `total-temp`, `system-status`, `power-capacity` |

Raw protocol keys (`rb`, `oac`, `bt`, ...) are also accepted.

### Changing settings (`set`)

```bash
# I/O toggles
socketry set ac on
socketry set dc off
socketry set usb on
socketry set car off

# Light
socketry set light high       # off | low | high | sos

# Device settings
socketry set charge-speed mute      # fast | mute
socketry set battery-protection eco # full | eco
socketry set ups on
socketry set sfc on

# Integer settings
socketry set screen-timeout 30
socketry set auto-shutdown 60
socketry set energy-saving 30

# Wait for device confirmation
socketry set ac on --wait

# Show available settings
socketry set
socketry set light            # "expects a value: off | low | high | sos"
```

Writable settings:

| Setting | Values | Description |
|---------|--------|-------------|
| `ac` | on / off | AC output |
| `dc` | on / off | DC output |
| `usb` | on / off | USB output |
| `car` | on / off | Car (12V) output |
| `ac-in` | on / off | AC input |
| `dc-in` | on / off | DC input |
| `light` | off / low / high / sos | Light mode |
| `screen-timeout` | integer | Screen timeout |
| `auto-shutdown` | integer | Auto shutdown timer |
| `charge-speed` | fast / mute | Charge speed mode |
| `battery-protection` | full / eco | Battery protection level |
| `energy-saving` | integer | Energy saving timeout |
| `sfc` | on / off | Super fast charge |
| `ups` | on / off | UPS mode |

## Library usage

```python
import asyncio
from socketry import Client

async def main():
    # Authenticate (or load saved credentials)
    client = await Client.login("email@example.com", "password")
    client.save_credentials()

    # Or load previously saved credentials
    client = Client.from_saved()

    # List and select devices
    devices = await client.fetch_devices()
    client.select_device(0)

    # Read properties
    props = await client.get_all_properties()
    setting, value = await client.get_property("battery")
    print(f"{setting.name}: {setting.format_value(value)}")

    # Control
    await client.set_property("ac", "on")
    result = await client.set_property("light", "high", wait=True)

asyncio.run(main())
```

## How it works

```
socketry ──HTTP──> iot.jackeryapp.com    (login, device list, properties)
socketry ──MQTT──> emqx.jackeryapp.com  (device control via encrypted TLS)
```

Login uses AES-192/ECB + RSA-1024 encrypted HTTP POST. Device control commands
are published over MQTT (TLS 1.2 with a self-signed CA). Status polling uses the
HTTP property endpoint. See [docs/protocol.md](docs/protocol.md) for the full
protocol specification.

## Roadmap

- [ ] MQTT real-time monitor (subscribe to live property changes)
- [ ] Token auto-refresh (JWT expires ~30 days)

## License

MIT
