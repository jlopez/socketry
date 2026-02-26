# socketry

## Coverage Badge

When coverage changes, update the badge in README.md:
- 90%+ → `brightgreen`, 80-89% → `green`, 70-79% → `yellowgreen`
- 60-69% → `yellow`, 50-59% → `orange`, <50% → `red`

Format: `![Coverage](https://img.shields.io/badge/coverage-XX%25-COLOR)`

## Running Commands

- Always use `uv run` to ensure the virtualenv is used
- Examples: `uv run pytest`, `uv run mypy .`, `uv run python script.py`

## Manual Testing

When the user requests manual testing, run these commands to exercise the system
end-to-end against the real Jackery cloud. Requires saved credentials
(`~/.config/socketry/credentials.json`).

```bash
# HTTP: device listing and property reads
uv run socketry devices
uv run socketry get
uv run socketry get battery

# MQTT fire-and-forget: send command, confirm via HTTP
uv run socketry set light low
uv run socketry get light

# MQTT subscribe+wait: send command and wait for device confirmation
uv run socketry set light high --wait

# Cycle through values to confirm round-trip
uv run socketry set light sos
uv run socketry get light
uv run socketry set light off
```
