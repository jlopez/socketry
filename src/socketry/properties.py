"""Device property definitions — single source of truth for Jackery protocol keys."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Setting:
    """A device property definition.

    Maps between raw protocol keys (e.g. ``oac``), CLI-friendly slugs
    (e.g. ``ac``), and human-readable labels (e.g. ``AC output``).
    """

    id: str
    """Raw key from the API (``oac``, ``rb``, ``sltb``)."""

    slug: str
    """CLI name (``ac``, ``battery``, ``screen-timeout``)."""

    name: str
    """Human-readable label."""

    group: str
    """Display group (``battery``, ``io``, ``settings``, ``power``, ``other``)."""

    action_id: int | None = None
    """MQTT action ID; ``None`` = read-only."""

    values: list[str] | None = None
    """Enum values (index = int value); ``None`` = integer."""

    unit: str = ""
    """Suffix for display (``%``, ``W``, ``Hz``, ``C``, ``h``)."""

    scale: float = 1.0
    """Divide raw value by this for display."""

    decimals: int = 1
    """Decimal places when *scale* != 1."""

    write_id: str | None = None
    """Override property key for MQTT writes (e.g. ``slt`` for ``sltb``)."""

    @property
    def writable(self) -> bool:
        """Whether this property can be set via MQTT."""
        return self.action_id is not None

    @property
    def prop_key(self) -> str:
        """The property key to use in MQTT command bodies."""
        return self.write_id or self.id

    def format_value(self, raw: object) -> str:
        """Format a raw property value for human display."""
        if self.values is not None:
            try:
                idx = int(str(raw))
                if 0 <= idx < len(self.values):
                    label: str = self.values[idx]
                    if set(self.values) == {"on", "off"}:
                        return label.upper()
                    return label
            except (ValueError, TypeError):
                pass
            return str(raw)
        if isinstance(raw, (int, float)):
            if self.unit == "h" and raw == 0:
                return "--"
            if self.scale != 1:
                return f"{raw / self.scale:.{self.decimals}f}{self.unit}"
            if self.unit:
                return f"{raw}{self.unit}"
        return str(raw)


# Model code -> human-readable name (from ha/c.java)
MODEL_NAMES: dict[int, str] = {
    1: "Explorer 3000 Pro",
    2: "Explorer 2000 Plus",
    4: "Explorer 300 Plus",
    5: "Explorer 1000 Plus",
    6: "Explorer 700 Plus",
    7: "Explorer 280 Plus",
    8: "Explorer 1000 Pro2",
    9: "Explorer 600 Plus",
    10: "Explorer 240",
    12: "Explorer 2000",
}

GROUP_TITLES: dict[str, str] = {
    "battery": "Battery & Power",
    "io": "I/O State",
    "settings": "Settings",
    "power": "AC / Power Detail",
    "other": "Other",
}


PROPERTIES: list[Setting] = [
    # Battery & Power
    Setting("rb", "battery", "Battery", "battery", unit="%"),
    Setting("bt", "battery-temp", "Battery temp", "battery", unit="C", scale=10),
    Setting("bs", "battery-state", "Battery state", "battery"),
    Setting("ip", "input-power", "Input power", "battery", unit="W"),
    Setting("op", "output-power", "Output power", "battery", unit="W"),
    Setting("it", "input-time", "Input time remaining", "battery", unit="h", scale=10),
    Setting("ot", "output-time", "Output time remaining", "battery", unit="h", scale=10),
    # I/O State
    Setting("oac", "ac", "AC output", "io", action_id=4, values=["off", "on"]),
    Setting("odc", "dc", "DC output", "io", action_id=1, values=["off", "on"]),
    Setting("odcu", "usb", "USB output", "io", action_id=2, values=["off", "on"]),
    Setting("odcc", "car", "Car output", "io", action_id=3, values=["off", "on"]),
    Setting("iac", "ac-in", "AC input", "io", action_id=5, values=["off", "on"]),
    Setting("idc", "dc-in", "DC input", "io", action_id=6, values=["off", "on"]),
    Setting("lm", "light", "Light mode", "io", action_id=7, values=["off", "low", "high", "sos"]),
    Setting("wss", "wireless", "Wireless charging", "io", values=["off", "on"]),
    # Settings
    Setting(
        "cs", "charge-speed", "Charge speed", "settings", action_id=10, values=["fast", "mute"]
    ),
    Setting("ast", "auto-shutdown", "Auto shutdown", "settings", action_id=9),
    Setting("pm", "energy-saving", "Energy saving", "settings", action_id=12),
    Setting(
        "lps",
        "battery-protection",
        "Battery protection",
        "settings",
        action_id=11,
        values=["full", "eco"],
    ),
    Setting("sfc", "sfc", "Super fast charge", "settings", action_id=13, values=["off", "on"]),
    Setting("ups", "ups", "UPS mode", "settings", action_id=14, values=["off", "on"]),
    Setting("sltb", "screen-timeout", "Screen timeout", "settings", action_id=8, write_id="slt"),
    # AC / Power Detail
    Setting("acip", "ac-input-power", "AC input power", "power", unit="W"),
    Setting("cip", "car-input-power", "Car input power", "power", unit="W"),
    Setting("acov", "ac-voltage", "AC output voltage", "power", unit="V", scale=10, decimals=0),
    Setting("acohz", "ac-freq", "AC output freq", "power", unit="Hz"),
    Setting("acps", "ac-power", "AC power", "power", unit="W"),
    Setting("acpss", "ac-power-2", "AC power (secondary)", "power", unit="W"),
    Setting("acpsp", "ac-socket-power", "AC socket power", "power", unit="W"),
    # Other / Alarms
    Setting("ec", "error-code", "Error code", "other"),
    Setting("ta", "temp-alarm", "Temp alarm", "other"),
    Setting("pal", "power-alarm", "Power alarm", "other"),
    Setting("pmb", "power-mode-battery", "Power mode battery", "other"),
    Setting("tt", "total-temp", "Total temp", "other"),
    Setting("ss", "system-status", "System status", "other"),
    Setting("pc", "power-capacity", "Power capacity", "other"),
]

_by_slug: dict[str, Setting] = {s.slug: s for s in PROPERTIES}
_by_id: dict[str, Setting] = {s.id: s for s in PROPERTIES}


def resolve(name: str) -> Setting | None:
    """Look up a Setting by slug or raw property key."""
    return _by_slug.get(name) or _by_id.get(name)
