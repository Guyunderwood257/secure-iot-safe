# -------------------- Local Configuration --------------------

# Submission date: 05.05.26

# Notes:
# - This file contains sensitive credentials and is stored locally on the ESP32
# - Real credentials and cryptographic keys are stored only on the local ESP32

# -------------------- Wi-Fi --------------------

WIFI_SSID = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
WIFI_PASSWORD = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"


# -------------------- ThingSpeak --------------------
#My Keys
THINGSPEAK_CHANNEL_ID = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
THINGSPEAK_WRITE_KEY = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"


# -------------------- Security Keys --------------------

# TOTP secret (Base32 encoded)
VERIFICATION_CODE_SECRET = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

# Telemetry encryption key (used for XOR stream cipher)
TELEMETRY_CIPHER_KEY = b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

# AES key (must be 16 bytes for AES-128)
LOCAL_AES_KEY = b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"