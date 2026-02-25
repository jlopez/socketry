"""Internal constants extracted from the decompiled Jackery APK."""

from __future__ import annotations

from pathlib import Path

API_BASE = "https://iot.jackeryapp.com/v1"

MQTT_HOST = "emqx.jackeryapp.com"
MQTT_PORT = 8883

RSA_PUBLIC_KEY_B64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCVmzgJy/4XolxPnkfu32YtJqYG"
    "FLYqf9/rnVgURJED+8J9J3Pccd6+9L97/+7COZE5OkejsgOkqeLNC9C3r5mhpE4z"
    "k/HStss7Q8/5DqkGD1annQ+eoICo3oi0dITZ0Qll56Dowb8lXi6WHViVDdih/oeU"
    "wVJY89uJNtTWrz7t7QIDAQAB"
)

# Self-signed CA cert for emqx.jackeryapp.com (from APK res/raw/ca.crt)
CA_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIIDtTCCAp2gAwIBAgIJAPvYSRLMmPACMA0GCSqGSIb3DQEBCwUAMHAxCzAJBgNV
BAYTAkNOMRIwEAYDVQQIDAlHdWFuZ2RvbmcxETAPBgNVBAcMCFNoZW56aGVuMRQw
EgYDVQQKDAtqYWNrZXJ5LmNvbTELMAkGA1UECwwCY2ExFzAVBgNVBAMMDmNhLmph
Y2tlcnkuY29tMCAXDTIyMTIyMzEwMTc0N1oYDzIwNzcwOTI1MTAxNzQ3WjBwMQsw
CQYDVQQGEwJDTjESMBAGA1UECAwJR3Vhbmdkb25nMREwDwYDVQQHDAhTaGVuemhl
bjEUMBIGA1UECgwLamFja2VyeS5jb20xCzAJBgNVBAsMAmNhMRcwFQYDVQQDDA5j
YS5qYWNrZXJ5LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOrf
QltVp+PDphQ20tfQbCh/YlqIAK8VkIcYXq7DlVsX1HGl5x+6UkEahzLRtZFaWRkH
HiHSvol8I+cvq6BHte0VsjKAzl7Mae7P/UyQXwpgNa+hliZHoEqflghzYvxjlZeP
eOGGcHxg1p2M8+PeNWkX5VkVTSYi/abDz86+D5y1gq7S8n+tYk1WhKFHvIrfX3nN
4QXfDO7vAQMd1uc6YdDqRanWjxIgOSDk9B+Mblz0TxCR+hnuDDQpAE4ONjByjArS
MC/QS8BIq/TL6nixzA8y0vOHySmuOLfuhFpNoO2mujhBGN/Dmq/pZwmsKSK91PxE
dn3YO8N8q7flHd/Qw4UCAwEAAaNQME4wHQYDVR0OBBYEFL/rQk0x4WclVgw3WLsl
YH3k0dvgMB8GA1UdIwQYMBaAFL/rQk0x4WclVgw3WLslYH3k0dvgMAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBALZM+xA4bUnO/7/0giZ3xUPEKzwFDp4G
5UPI/5grLYxp38t2M84tlJ94W/HKH+f1CYbJ6m28dSZfWtnRzQ3Tgq0whrsmYiK9
1Txcl3HPBiL7yAn3yE8DjHV+S2eSnN0o26/rcXCe+9bghSqqGaVDOJyk+Fm4l17e
Hzx99PvPGkpGUglun3UEp/Vp5ZUl9uDYT813HJ9jK80i1MDlzBJWmg7gzh27/Qls
UJLtYvgsxiBKAnK8YkAyu51Jm8uLz1BZ1RANf22vv0QUTW+SGdgc5Q1h610G9N1i
4BaijfWnto9ka32QKgZA0gHXsT3wiwdbEow0lp7y40aiXq4kazDT7ws=
-----END CERTIFICATE-----
"""

CRED_DIR = Path.home() / ".config" / "socketry"
CRED_FILE = CRED_DIR / "credentials.json"

APP_HEADERS: dict[str, str] = {
    "platform": "2",
    "app_version": "1.2.0",
    "Content-Type": "application/x-www-form-urlencoded",
}
