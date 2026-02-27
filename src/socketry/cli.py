"""Thin CLI wrapper over :class:`socketry.Client`."""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys
from datetime import datetime

import typer

from socketry.client import Client
from socketry.properties import GROUP_TITLES, MODEL_NAMES, PROPERTIES, Setting, resolve

app = typer.Typer(help="Control Jackery power stations.", invoke_without_command=True)

_by_id: dict[str, Setting] = {s.id: s for s in PROPERTIES}


@app.callback()
def main(ctx: typer.Context) -> None:
    """Control Jackery power stations."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(0)


def _print_json(obj: object) -> None:
    """Print JSON — syntax-highlighted when stdout is a TTY, compact otherwise."""
    if sys.stdout.isatty():
        try:
            from rich.console import Console
            from rich.syntax import Syntax

            Console().print(Syntax(json.dumps(obj, indent=2), "json"))
        except ImportError:
            typer.echo(json.dumps(obj, indent=2))
    else:
        typer.echo(json.dumps(obj))


def _ensure_client() -> Client:
    """Load saved credentials or exit with an error."""
    try:
        return Client.from_saved()
    except FileNotFoundError:
        typer.echo("No saved credentials. Run `socketry login` first.", err=True)
        raise typer.Exit(1) from None


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def login(
    email: str = typer.Option(..., prompt=True, help="Jackery account email"),
    password: str = typer.Option(
        ..., prompt=True, hide_input=True, help="Jackery account password"
    ),
) -> None:
    """Authenticate with Jackery and save credentials locally."""
    typer.echo(f"Logging in as {email}...")
    client = asyncio.run(Client.login(email, password))
    client.save_credentials()
    n = len(client.devices)
    if n == 0:
        typer.echo(
            "Logged in, but no devices found. Run `socketry debug` to troubleshoot.",
            err=True,
        )
    else:
        typer.echo(
            f"Logged in. {n} device(s) found."
            f" Selected: {client.device_name} (SN: {client.device_sn})"
        )


@app.command()
def devices() -> None:
    """List all devices (owned and shared). Refreshes from API."""
    client = _ensure_client()
    typer.echo("Fetching devices...")
    all_devices = asyncio.run(client.fetch_devices())
    if not all_devices:
        typer.echo("No devices found.", err=True)
        raise typer.Exit(1)

    client.save_credentials()

    selected_sn = client.device_sn
    for i, dev in enumerate(all_devices):
        marker = "*" if dev["devSn"] == selected_sn else " "
        model = MODEL_NAMES.get(int(str(dev.get("modelCode", 0) or 0)), "Unknown model")
        shared = f" (shared by {dev['sharedBy']})" if dev.get("shared") else ""
        typer.echo(f"  {marker} [{i}] {dev['devName']} — {model}{shared}")
        typer.echo(f"        SN: {dev['devSn']}")

    typer.echo("\n  * = selected.  Use `socketry select <index>` to change.")


@app.command()
def select(index: int) -> None:
    """Select the active device by index (see ``devices`` for the list)."""
    client = _ensure_client()
    try:
        dev = client.select_device(index)
    except IndexError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1) from None
    client.save_credentials()
    model = MODEL_NAMES.get(int(str(dev.get("modelCode", 0) or 0)), "Unknown model")
    typer.echo(f"Selected: {dev['devName']} — {model} (SN: {dev['devSn']})")


@app.command()
def debug() -> None:
    """Dump raw API responses for troubleshooting device access."""
    asyncio.run(_debug_async())


async def _debug_async() -> None:
    """Async implementation of the debug command."""
    import aiohttp

    from socketry._constants import API_BASE, APP_HEADERS

    client = _ensure_client()
    auth_headers = {**APP_HEADERS, "token": client.token}
    timeout = aiohttp.ClientTimeout(total=15)

    async with aiohttp.ClientSession() as session:
        typer.echo("=== GET /device/bind/list (owned devices) ===")
        try:
            async with session.get(
                f"{API_BASE}/device/bind/list",
                headers=auth_headers,
                timeout=timeout,
            ) as resp:
                typer.echo(f"Status: {resp.status}")
                _print_json(await resp.json())
        except Exception as e:
            typer.echo(f"Error: {e}")

        typer.echo("\n=== GET /device/bind/shared (share relationships) ===")
        try:
            async with session.get(
                f"{API_BASE}/device/bind/shared",
                headers=auth_headers,
                timeout=timeout,
            ) as resp:
                typer.echo(f"Status: {resp.status}")
                _print_json(await resp.json())
        except Exception as e:
            typer.echo(f"Error: {e}")

        devs = client.devices
        if devs:
            dev = devs[0]
            dev_id = dev.get("devId", "")
            if dev_id:
                typer.echo(f"\n=== GET /device/property?deviceId={dev_id} (first device) ===")
                try:
                    async with session.get(
                        f"{API_BASE}/device/property",
                        params={"deviceId": str(dev_id)},
                        headers=auth_headers,
                        timeout=timeout,
                    ) as resp:
                        typer.echo(f"Status: {resp.status}")
                        _print_json(await resp.json())
                except Exception as e:
                    typer.echo(f"Error: {e}")
            else:
                typer.echo(f"\n(!) First device has empty devId: {json.dumps(dev)}")


@app.command("get", context_settings={"help_option_names": ["-h", "--help"]})
def get_property(
    ctx: typer.Context,
    name: str | None = typer.Argument(None, help="Property name or raw key"),
    as_json: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
) -> None:
    """Query device properties.

    \b
    Without arguments, shows all properties grouped.
    With a property name, shows just that value.
    Accepts CLI names (battery, ac) and raw keys (rb, oac).
    """
    client = _ensure_client()

    try:
        data = asyncio.run(client.get_all_properties())
    except (ValueError, RuntimeError) as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1) from None

    if not data:
        typer.echo("No properties returned.", err=True)
        raise typer.Exit(1)

    props = data.get("properties") or data
    if not isinstance(props, dict):
        typer.echo("Unexpected response format.", err=True)
        raise typer.Exit(1)

    # Single property query
    if name is not None:
        s = resolve(name)
        if s is None:
            typer.echo(f"Unknown property '{name}'.", err=True)
            raise typer.Exit(1)
        if s.id not in props:
            typer.echo(f"Property '{name}' ({s.id}) not reported by device.", err=True)
            raise typer.Exit(1)
        raw = props[s.id]
        if as_json:
            _print_json({s.id: raw})
        else:
            typer.echo(f"{s.name}: {s.format_value(raw)}")
        return

    # All properties
    if as_json:
        _print_json(props)
        return

    is_tty = sys.stdout.isatty()

    if is_tty:
        typer.echo(typer.style(client.device_name, bold=True))
    else:
        typer.echo(client.device_name)

    device_meta = data.get("device")
    if isinstance(device_meta, dict):
        online = device_meta.get("onlineStatus")
        if online is not None:
            typer.echo(f"  Online: {'yes' if online == 1 else 'no'}")

    shown: set[str] = set()
    for group in ("battery", "io", "settings", "power"):
        group_settings = [s for s in PROPERTIES if s.group == group and s.id in props]
        if not group_settings:
            continue
        title = GROUP_TITLES[group]
        if is_tty:
            typer.echo(f"\n  {typer.style(title, bold=True)}")
        else:
            typer.echo(f"\n  {title}")
        for s in group_settings:
            raw = props[s.id]
            formatted = s.format_value(raw)
            if is_tty:
                typer.echo(f"    {typer.style(f'{s.name} ({s.slug})', fg='cyan')}: {formatted}")
            else:
                typer.echo(f"    {s.name} ({s.slug}): {formatted}")
            shown.add(s.id)

    # Remaining unknown keys
    remaining = {k: v for k, v in props.items() if k not in shown}
    if remaining:
        if is_tty:
            typer.echo(f"\n  {typer.style('Other', bold=True)}")
        else:
            typer.echo("\n  Other")
        for k, v in remaining.items():
            s = _by_id.get(k)
            if s:
                label = f"{s.name} ({s.slug})"
                formatted = s.format_value(v)
            else:
                label = k
                formatted = str(v)
            if is_tty:
                typer.echo(f"    {typer.style(label, fg='cyan')}: {formatted}")
            else:
                typer.echo(f"    {label}: {formatted}")


@app.command("set", context_settings={"help_option_names": ["-h", "--help"]})
def set_setting(
    ctx: typer.Context,
    setting: str | None = typer.Argument(None, help="Setting name"),
    value: str | None = typer.Argument(None, help="Value to set"),
    wait: bool = typer.Option(False, "--wait", "-w", help="Wait for device confirmation"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show MQTT traffic"),
) -> None:
    """Change a device setting via MQTT.

    \b
    Settings (named values):
      ac, dc, usb, car, ac-in, dc-in    on | off
      light                              off | low | high | sos
      charge-speed                       fast | mute
      battery-protection                 full | eco
      sfc, ups                           on | off

    \b
    Settings (integer values):
      screen-timeout, auto-shutdown, energy-saving
    """
    if setting is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(0)

    s = resolve(setting)
    if s is None or not s.writable:
        writable = [p for p in PROPERTIES if p.writable]
        names = ", ".join(p.slug for p in writable)
        if s and not s.writable:
            typer.echo(f"Property '{setting}' is read-only. Writable: {names}", err=True)
        else:
            typer.echo(f"Unknown setting '{setting}'. Available: {names}", err=True)
        raise typer.Exit(1)

    if value is None:
        if s.values:
            typer.echo(f"Setting '{s.slug}' expects a value: {' | '.join(s.values)}")
        else:
            typer.echo(f"Setting '{s.slug}' expects a value: <integer>")
        raise typer.Exit(0)

    client = _ensure_client()
    typer.echo(f"Setting {s.slug} to {value}...")

    try:
        result = asyncio.run(client.set_property(setting, value, wait=wait, verbose=verbose))
    except (KeyError, ValueError) as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1) from None

    if wait:
        if result and isinstance(result, dict):
            for k, v in result.items():
                rs = _by_id.get(k)
                if rs:
                    typer.echo(f"  {rs.name}: {rs.format_value(v)}")
                else:
                    typer.echo(f"  {k}: {v}")
        else:
            typer.echo("No response from device (timeout).", err=True)
    else:
        typer.echo(f"Command sent to {client.device_name}.")


@app.command()
def watch(
    name: str | None = typer.Argument(None, help="Property name to filter (optional)"),
) -> None:
    """Watch real-time property updates from the device via MQTT.

    \b
    Without arguments, shows all property changes.
    With a property name, shows only that property.
    Press Ctrl+C to stop.
    """
    client = _ensure_client()

    setting: Setting | None = None
    if name is not None:
        setting = resolve(name)
        if setting is None:
            typer.echo(f"Unknown property '{name}'.", err=True)
            raise typer.Exit(1)

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_watch_async(client, setting))


async def _watch_async(client: Client, setting: Setting | None) -> None:
    """Async implementation of the watch command."""
    is_tty = sys.stdout.isatty()
    if setting:
        typer.echo(f"Watching {setting.name} ({setting.slug})... (Ctrl+C to stop)")
    else:
        typer.echo("Watching for property updates... (Ctrl+C to stop)")

    async def on_update(device_sn: str, properties: dict[str, object]) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        for key, value in properties.items():
            if setting and key != setting.id:
                continue
            s = _by_id.get(key)
            if s:
                label = f"{s.name} ({s.slug})"
                formatted = s.format_value(value)
            else:
                label = key
                formatted = str(value)
            if is_tty:
                typer.echo(
                    f"[{ts}] {typer.style(device_sn, bold=True)} "
                    f"{typer.style(label, fg='cyan')}: {formatted}"
                )
            else:
                typer.echo(f"[{ts}] {device_sn} {label}: {formatted}")

    async def on_disconnect() -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        if is_tty:
            typer.echo(typer.style(f"[{ts}] Disconnected, reconnecting...", fg="yellow"))
        else:
            typer.echo(f"[{ts}] Disconnected, reconnecting...")

    subscription = await client.subscribe(on_update, on_disconnect=on_disconnect)
    try:
        await subscription.wait()
    finally:
        await subscription.stop()
