# -------------------- Local Configuration --------------------

# Submission date: 05.05.26

# Notes:
# - This file contains sensitive credentials and is stored locally on the ESP32
# - Real credentials and cryptographic keys are stored only on the local ESP32

# -------------------- Wi-Fi --------------------

WIFI_SSID = "ESPTEST"
WIFI_PASSWORD = "12345678"


# -------------------- ThingSpeak --------------------
#My Keys
THINGSPEAK_CHANNEL_ID = 3325981
THINGSPEAK_WRITE_KEY = "BZW22T2TB9GT6B92"


# -------------------- Security Keys --------------------

# TOTP secret (Base32 encoded)
VERIFICATION_CODE_SECRET = "JBSWY3DPEHPK3PXP"

# Telemetry encryption key (used for XOR stream cipher)
TELEMETRY_CIPHER_KEY = b"SafeCipherKey01"

# AES key (must be 16 bytes for AES-128)
LOCAL_AES_KEY = b"SafeLocalAESKey1"