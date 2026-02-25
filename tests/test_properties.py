"""Tests for socketry.properties."""

from socketry.properties import PROPERTIES, Setting, resolve


class TestSetting:
    def test_writable_with_action_id(self):
        s = Setting("oac", "ac", "AC output", "io", action_id=4, values=["off", "on"])
        assert s.writable is True

    def test_not_writable_without_action_id(self):
        s = Setting("rb", "battery", "Battery", "battery", unit="%")
        assert s.writable is False

    def test_prop_key_default(self):
        s = Setting("oac", "ac", "AC output", "io", action_id=4)
        assert s.prop_key == "oac"

    def test_prop_key_override(self):
        s = Setting(
            "sltb",
            "screen-timeout",
            "Screen timeout",
            "settings",
            action_id=8,
            write_id="slt",
        )
        assert s.prop_key == "slt"

    def test_format_value_enum_on_off(self):
        s = Setting("oac", "ac", "AC output", "io", action_id=4, values=["off", "on"])
        assert s.format_value(0) == "OFF"
        assert s.format_value(1) == "ON"

    def test_format_value_enum_named(self):
        s = Setting(
            "lm",
            "light",
            "Light mode",
            "io",
            action_id=7,
            values=["off", "low", "high", "sos"],
        )
        assert s.format_value(0) == "off"
        assert s.format_value(1) == "low"
        assert s.format_value(3) == "sos"

    def test_format_value_enum_out_of_range(self):
        s = Setting("oac", "ac", "AC output", "io", action_id=4, values=["off", "on"])
        assert s.format_value(99) == "99"

    def test_format_value_with_unit(self):
        s = Setting("rb", "battery", "Battery", "battery", unit="%")
        assert s.format_value(85) == "85%"

    def test_format_value_with_scale(self):
        s = Setting("bt", "battery-temp", "Battery temp", "battery", unit="C", scale=10)
        assert s.format_value(160) == "16.0C"

    def test_format_value_hours_zero(self):
        s = Setting("it", "input-time", "Input time remaining", "battery", unit="h", scale=10)
        assert s.format_value(0) == "--"

    def test_format_value_hours_nonzero(self):
        s = Setting("ot", "output-time", "Output time remaining", "battery", unit="h", scale=10)
        assert s.format_value(999) == "99.9h"

    def test_format_value_plain_int(self):
        s = Setting("ec", "error-code", "Error code", "other")
        assert s.format_value(42) == "42"

    def test_format_value_scale_no_decimals(self):
        s = Setting(
            "acov",
            "ac-voltage",
            "AC output voltage",
            "power",
            unit="V",
            scale=10,
            decimals=0,
        )
        assert s.format_value(1200) == "120V"


class TestResolve:
    def test_resolve_by_slug(self):
        s = resolve("battery")
        assert s is not None
        assert s.id == "rb"

    def test_resolve_by_id(self):
        s = resolve("rb")
        assert s is not None
        assert s.slug == "battery"

    def test_resolve_unknown(self):
        assert resolve("nonexistent") is None


class TestPropertiesList:
    def test_all_properties_have_unique_ids(self):
        ids = [s.id for s in PROPERTIES]
        assert len(ids) == len(set(ids))

    def test_all_properties_have_unique_slugs(self):
        slugs = [s.slug for s in PROPERTIES]
        assert len(slugs) == len(set(slugs))

    def test_writable_properties_have_action_ids(self):
        for s in PROPERTIES:
            if s.writable:
                assert s.action_id is not None

    def test_has_expected_count(self):
        assert len(PROPERTIES) >= 28
