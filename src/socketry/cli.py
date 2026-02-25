"""Thin CLI wrapper over :class:`socketry.Client`."""

from __future__ import annotations

import json
import sys

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
    client = Client.login(email, password)
    client.save_credentials()
    n = len(client.devices)
    typer.echo(
        f"Logged in. {n} device(s) found. Selected: {client.device_name} (SN: {client.device_sn})"
    )


@app.command()
def devices() -> None:
    """List all devices (owned and shared). Refreshes from API."""
    client = _ensure_client()
    typer.echo("Fetching devices...")
    all_devices = client.fetch_devices()
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
        data = client.get_all_properties()
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
        result = client.set_property(setting, value, wait=wait, verbose=verbose)
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
