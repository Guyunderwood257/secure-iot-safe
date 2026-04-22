# -------------------- Secure System Boot and Telemetry Initialisation --------------------
# Submission date: 05.05.26
# ESP32-C3 system boot and telemetry initialisation
#
# Responsibilities:
# - Connect to Wi-Fi in a controlled and predictable way
# - Synchronise system time for verification-code generation
# - Manage queued, rate-limited ThingSpeak telemetry
# - Launch the secured application runtime
#
# Design principles:
# - Fail secure by requiring successful network initialisation
# - Prevent the system from running if Wi-Fi is unavailable
# - Keep startup simple and deterministic
# - Free RAM before larger allocations on the ESP32-C3
# - Ensure telemetry runs in the background without blocking the system
#
# Notes:
# - Telemetry events are queued and sent one at a time
# - Network initialisation must complete before access control begins
# - The system will not start if Wi-Fi connection fails
#
# Sensitive credentials are stored in a separate local configuration file
# (mykeys_config.py) which is excluded from submission for security reasons.

import gc


# -------------------- Wi-Fi Settings --------------------

from mykeys_config import WIFI_SSID, WIFI_PASSWORD


# -------------------- ThingSpeak Settings --------------------

from mykeys_config import THINGSPEAK_WRITE_KEY

THINGSPEAK_UPDATE_URL = "https://api.thingspeak.com/update"

# ThingSpeak requires a delay between uploads
THINGSPEAK_MIN_POST_SECONDS = 20
MAX_TELEMETRY_QUEUE         = 10


# -------------------- Output --------------------

SHOW_WIFI = True


# -------------------- Helpers --------------------

def wifi_log(*args, **kwargs):
    # Print Wi-Fi debug messages only when enabled
    if SHOW_WIFI:
        print(*args, **kwargs)


# -------------------- Wi-Fi Telemetry --------------------
# Events are queued locally and transmitted in the background so
# network delays do not interrupt the authentication process.

class ThingSpeakTelemetry:
    # Handles Wi-Fi connection state and queued telemetry uploads

    def __init__(self, ssid, password, write_key):
        self.ssid      = ssid
        self.password  = password
        self.write_key = write_key

        self.wifi      = None
        self.connected = False

        self.queue          = []
        self.last_post_time = 0
        self.last_tick_time = 0

    def connect_wifi(self, timeout_s=15):
        # Connect to Wi-Fi using a clean startup sequence
        import network
        import time

        # Free memory before creating the WLAN interface
        gc.collect()
        wifi_log("Free RAM before WLAN:", gc.mem_free())

        if self.wifi is None:
            try:
                self.wifi = network.WLAN(network.STA_IF)
                wifi_log("WLAN init OK")
            except Exception as e:
                raise OSError("WLAN init failed: {}".format(e))

        # Reset interface before connecting
        try:
            self.wifi.active(False)
            time.sleep(0.5)
            gc.collect()
            self.wifi.active(True)
            time.sleep(0.8)
        except Exception as e:
            raise OSError("WiFi activate failed: {}".format(e))

        # Reuse connection if already active
        if self.wifi.isconnected():
            self.connected = True
            wifi_log("IP config:", self.wifi.ifconfig())
            return True

        # Attempt connection
        wifi_log("Connecting to WiFi.", end="")
        self.wifi.connect(self.ssid, self.password)

        start = time.time()
        while not self.wifi.isconnected():
            wifi_log(".", end="")
            time.sleep(0.25)

            if (time.time() - start) > timeout_s:
                try:
                    status = self.wifi.status()
                except Exception:
                    status = "unknown"
                raise OSError("WiFi connect timeout/status={}".format(status))

        wifi_log(" Connected")

        # Print connection details if available
        try:
            wifi_log("ESSID:    ", self.wifi.config("essid"))
            wifi_log("Channel:  ", self.wifi.config("channel"))
            wifi_log("TX Power: ", self.wifi.config("txpower"), "dBm")
            wifi_log("Hostname: ", self.wifi.config("hostname"))
            wifi_log("IP config:", self.wifi.ifconfig())
        except Exception:
            pass

        self.connected = True
        return True

    def sync_time(self):
        # Synchronise time after Wi-Fi is connected (required for 2FA)
        if not self.connected or self.wifi is None:
            return False

        try:
            import ntptime
            ntptime.settime()
            wifi_log("NTP sync OK")
            return True
        except Exception as e:
            wifi_log("NTP sync failed:", e)
            return False

    def queue_event(self, event_code, failed_attempts, fingerprint_score,
                    lock_state, auth_result, status_text,
                    risk_score=0, lockout_count=0, fp_failures=0):
        # Queue events so networking never blocks security logic
        payload = {
            "api_key": self.write_key,
            "field1": str(int(event_code)),
            "field2": str(int(failed_attempts)),
            "field3": str(int(fingerprint_score)),
            "field4": str(int(lock_state)),
            "field5": str(int(auth_result)),
            "field6": str(int(risk_score)),
            "field7": str(int(lockout_count)),
            "field8": str(int(fp_failures)),
            "status": str(status_text)
        }

        # Keep queue size bounded to avoid memory issues
        if len(self.queue) >= MAX_TELEMETRY_QUEUE:
            self.queue.pop(0)

        self.queue.append(payload)

    def send_next_if_allowed(self):
        # Send one queued event when the rate limit allows it
        import time

        if not self.connected or self.wifi is None:
            return

        if not self.wifi.isconnected():
            self.connected = False
            return

        if not self.queue:
            return

        now = time.time()
        if (now - self.last_post_time) < THINGSPEAK_MIN_POST_SECONDS:
            return

        upload_data = dict(self.queue[0])
        response = None

        try:
            import urequests

            # Encode payload for MicroPython-compatible HTTP POST
            encoded = "&".join(
                "{}={}".format(key, value) for key, value in upload_data.items()
            )

            response = urequests.post(
                THINGSPEAK_UPDATE_URL,
                data=encoded.encode()
            )

            try:
                result = response.text.strip()
            except Exception:
                result = None

            # ThingSpeak returns a non-zero entry ID on success
            if response.status_code == 200 and result not in ("0", "", None):
                self.queue.pop(0)
            else:
                wifi_log("ThingSpeak post failed:", response.status_code, result)

        except Exception as e:
            wifi_log("ThingSpeak post error:", e)

        finally:
            self.last_post_time = now
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass

    def tick(self):
        # Background tick to process queued telemetry
        import time

        now = time.time()
        if (now - self.last_tick_time) >= 1:
            self.last_tick_time = now
            self.send_next_if_allowed()


telemetry = ThingSpeakTelemetry(WIFI_SSID, WIFI_PASSWORD, THINGSPEAK_WRITE_KEY)


# -------------------- Boot Flow --------------------

def start_wifi():
    # Connect Wi-Fi and sync time before starting the main system
    gc.collect()
    print("Free RAM at startup:", gc.mem_free())

    try:
        telemetry.connect_wifi()

        # Time sync is required for verification-code generation
        if not telemetry.sync_time():
            raise RuntimeError("Time sync required")

        print("WiFi connected:", telemetry.connected)

        if telemetry.wifi is not None and telemetry.wifi.isconnected():
            print("IP config:", telemetry.wifi.ifconfig())

    except Exception as e:
        print("WiFi startup failed:", e)
        print("System halted - WiFi required for operation")

        # Fail-secure: system must not run without network
        raise RuntimeError("WiFi connection required")

    return telemetry


def main():
    # Start networking first, then launch the secured runtime
    try:
        start_wifi()
    except Exception as e:
        print("Boot sequence aborted:", e)
        return

    gc.collect()

    try:
        import application_runtime
        application_runtime.run_app(telemetry)
    except Exception as e:
        print("Runtime initialisation failed:", e)


main()