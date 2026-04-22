# -------------------- Embedded Hardware Control Module --------------------
# Submission date: 05.05.26
# ESP32-C3 hardware control module
#
# Provides hardware support for:
# - LCD display control (16x2 I2C)
# - Servo-based lock movement
# - Matrix keypad input through PCF8574
# - Fingerprint sensor communication over UART
#
# Responsibilities:
# - Keep hardware handling separate from the main security logic
# - Provide stable and reusable device control
# - Keep hardware behaviour predictable and easier to maintain
#
# Design principles:
# - Keep hardware access modular and self-contained
# - Avoid unnecessary blocking where possible
# - Stay compatible with background telemetry processing
# - Present a clean and simple interface to the runtime system

from machine import Pin, UART, PWM
from time import sleep, sleep_ms
import time


# -------------------- Device Timing --------------------

LCD_INFO_DELAY   = 3
LCD_ACTION_DELAY = 2
LCD_ERROR_DELAY  = 4
LCD_ENROL_DELAY  = 4

SERVO_STEP_DELAY = 0.03
SERVO_ANGLE_STEP = 1


# -------------------- Display Manager --------------------
# Handles all LCD messages shown to the user
# Keeps wording and formatting consistent across the system

class DisplayManager:
    # LCD output interface
    def __init__(self, lcd_device):
        self.lcd = lcd_device

    def show(self, line1="", line2=""):
        # Each LCD line is limited to 16 characters to match the display width
        self.lcd.clear()
        self.lcd.move_to(0, 0)
        self.lcd.putstr(str(line1)[:16])
        self.lcd.move_to(0, 1)
        self.lcd.putstr(str(line2)[:16])

    # Lock / boot
    def boot(self):             self.show("System Booting",  "Please wait")
    def locked(self):           self.show("System Secured",  "Await Input")
    def system_error(self):     self.show("System Error",    " Safe Locked")

    # PIN
    def pin_entry(self, p=""):  self.show("Enter PIN:", p)
    def pin_ok(self):           self.show("PIN Verified",    "Scan Finger")
    def denied(self):           self.show("Access Denied",   "Auth Failed")

    # Fingerprint flow
    def place_finger(self):          self.show("Place Finger",     "On Scanner")
    def scanning(self):              self.show("Capturing Sample", "Please wait")
    def remove_finger(self):         self.show("Remove Finger",    "Please wait")
    def image_unclear(self):         self.show("Sample unclear",  "Rescan Required")
    def finger_flatter(self):        self.show("Adjust Pressure",  "On Scanner")
    def finger_retry(self):          self.show("Rescan Required",  "Place Finger")
    def finger_read_failed(self):    self.show("Extraction Fail",  "Rescan Required")
    def fingerprint_positive(self):  self.show("Template Match",   "User Verified")
    def fingerprint_negative(self):  self.show("User invalid",    "No Match Found")
    def sensor_error(self):          self.show("Sensor Error",    "Check Wiring")

    # Safe / system state
    def unlocking(self):             self.show("Access Granted",   "Unlocking...")
    def unlocked(self):              self.show("Safe Unlocked",    "Relocking soon..")
    def lockout(self, s):            self.show("LOCKOUT ACTIVE",   "{} sec left".format(s))

    # Risk feedback
    def risk_suspicious(self):       self.show("Suspicious",       "Monitoring")
    def risk_high(self):             self.show("HIGH RISK",        "Extended delay")

    # Admin menu
    def admin_menu(self):            self.show("1:Auth 2:Enrol",   "3:Clear")
    def enter_id(self):              self.show("Enter ID",         "#=OK *=Clear")
    def cannot_clear_admin(self):    self.show("Admin Protected",  "Cannot clear")
    def invalid_id(self):            self.show("Invalid ID",       "Try again")

    # Enrol / clear
    def enrol_first(self):           self.show("Enrol Sample 1",     "Place Finger")
    def enrol_second(self):          self.show("Enrol Sample 2",     "Place Again")
    def enrol_done(self, t):         self.show("Template Stored",   "ID {}".format(t))
    def enrol_failed(self):          self.show("Enrol Aborted",     "Try again")
    def clear_done(self, t):         self.show("Template clear",   "ID {}".format(t))
    def clear_failed(self):          self.show("Clear failed",     "Try again")

    # Verification code
    def enter_verification_code(self, masked=""):
        self.show("Enter TOTP Code", str(masked)[:16])

    def verification_code_ok(self):
        self.show("TOTP Verified", "Please wait")

    def verification_code_retry(self, tries_left):
        word = "Attempt" if tries_left == 1 else "Attempts"
        self.show("TOTP Rejected", "{} {} Left".format(tries_left, word)[:16])

    def time_error(self):
        self.show("Time not synced", "TOTP Unavailable")


# -------------------- RGB Status Indicator --------------------
# Controls the onboard NeoPixel LED for system status feedback

class StatusLED:
    # Onboard RGB LED on GPIO 8
    def __init__(self, pin_number=8, led_count=1):
        from neopixel import NeoPixel
        self.np = NeoPixel(Pin(pin_number), led_count)
        self.off()

    def set(self, r, g, b):
        self.np[0] = (int(r), int(g), int(b))
        self.np.write()

    def off(self):
        self.set(0, 0, 0)

    def boot(self):
        self.set(0, 0, 25)

    def locked(self):
        self.set(0, 0, 10)

    def pin_ok(self):
        self.set(20, 20, 0)

    def access_granted(self):
        self.set(0, 25, 0)

    def access_denied(self):
        self.set(25, 0, 0)

    def warning(self):
        self.set(25, 18, 0)

    def high_risk(self):
        self.set(25, 0, 12)

    def admin(self):
        self.set(18, 0, 25)

    def error(self):
        self.set(25, 0, 0)


# -------------------- Servo Lock --------------------
# Controls the physical locking mechanism using PWM with smooth stepped movement

class ServoLock:
    # Servo-driven lock control
    def __init__(self, pwm_pin, freq, locked_angle, unlocked_angle,
                 step_delay=SERVO_STEP_DELAY, angle_step=SERVO_ANGLE_STEP):
        self.pwm            = PWM(Pin(pwm_pin), freq=freq)
        self.locked_angle   = locked_angle
        self.unlocked_angle = unlocked_angle
        self.step_delay     = step_delay
        self.angle_step     = angle_step
        self.current_angle  = locked_angle

        # Start in the locked position to support fail-secure behaviour
        self.pwm.duty_u16(self.angle_to_duty_u16(self.locked_angle))
        sleep(0.5)

    @staticmethod
    def angle_to_duty_u16(angle):
        # Convert a servo angle in degrees to a 16-bit PWM duty value
        angle    = max(0, min(180, int(angle)))
        min_duty = 1600
        max_duty = 8050
        return int(min_duty + ((max_duty - min_duty) * angle / 180))

    def move_smooth(self, target_angle):
        # Move the servo in small steps for smooth, controlled motion
        target_angle = max(0, min(180, int(target_angle)))
        if target_angle == self.current_angle:
            return

        step = self.angle_step if target_angle > self.current_angle else -self.angle_step

        for angle in range(self.current_angle, target_angle, step):
            self.pwm.duty_u16(self.angle_to_duty_u16(angle))
            time.sleep(self.step_delay)

        self.pwm.duty_u16(self.angle_to_duty_u16(target_angle))
        self.current_angle = target_angle
        time.sleep(0.2)

    def lock(self):
        self.move_smooth(self.locked_angle)

    def unlock(self):
        self.move_smooth(self.unlocked_angle)


# -------------------- Keypad Interface --------------------
# Handles 4x3 keypad input through the PCF8574 with simple debouncing

class Keypad:
    # 4x3 keypad over PCF8574
    KEY_VALUES = ("123", "456", "789", "*0#")

    def __init__(self, pcf_device):
        self.pcf            = pcf_device
        self._shadow_output = 0xFF
        self._last_key      = None
        self.pcf.port       = self._shadow_output

    def _set_all_columns_high(self):
        # Release all column lines
        self._shadow_output |= (1 << 4) | (1 << 5) | (1 << 6)
        self.pcf.port = self._shadow_output

    def _drive_column_low(self, col_index):
        # Pull one column low while scanning
        self._set_all_columns_high()
        self._shadow_output &= ~(1 << (4 + col_index))
        self.pcf.port = self._shadow_output

    def _read_rows(self):
        # Read the keypad row inputs from the PCF8574
        try:
            return self.pcf.port & 0x0F
        except Exception:
            return 0x0F

    def scan_key(self):
        # Scan all columns once and return the active key, if there is one
        for col in range(3):
            self._drive_column_low(col)
            sleep_ms(2)
            rows = self._read_rows()

            for row in range(4):
                if (rows & (1 << row)) == 0:
                    self._set_all_columns_high()
                    return Keypad.KEY_VALUES[row][col]

        self._set_all_columns_high()
        return None

    def wait_release(self):
        while self.scan_key() is not None:
            sleep_ms(10)

    def poll(self):
        # Return one debounced key event for each physical press
        key = self.scan_key()

        if key is None:
            self._last_key = None
            return None

        # Debouncing helps one real press produce one logical key event
        if key != self._last_key:
            sleep_ms(25)
            if self.scan_key() == key:
                self._last_key = key
                self.wait_release()
                return key

        return None


# -------------------- Fingerprint Sensor --------------------
# Handles UART communication for fingerprint matching, enrolment, and template deletion

class FingerprintSensor:
    # Fingerprint sensor driver over UART

    HEADER      = b'\xEF\x01'
    ADDRESS     = b'\xFF\xFF\xFF\xFF'
    PID_COMMAND = 0x01

    def __init__(self, uart_id, baudrate, tx_pin, rx_pin, touch_pin, telemetry=None):
        self.uart      = UART(uart_id, baudrate=baudrate, tx=Pin(tx_pin), rx=Pin(rx_pin))
        self.touch     = Pin(touch_pin, Pin.IN)
        self.telemetry = telemetry

    def build_packet(self, command, params=b""):
        length   = len(params) + 3
        body     = bytes([self.PID_COMMAND]) + length.to_bytes(2, "big") + bytes([command]) + params
        checksum = sum(body).to_bytes(2, "big")
        return self.HEADER + self.ADDRESS + body + checksum

    def read_packet(self, timeout_ms=1500):
        start  = time.ticks_ms()
        buffer = b""

        while time.ticks_diff(time.ticks_ms(), start) < timeout_ms:
            if self.uart.any():
                chunk = self.uart.read()
                if chunk:
                    buffer += chunk
                    if len(buffer) >= 9:
                        packet_length = (buffer[7] << 8) | buffer[8]
                        if len(buffer) >= (9 + packet_length):
                            return buffer[:9 + packet_length]
            time.sleep_ms(10)

        return None

    def send_packet(self, command, params=b"", timeout_ms=1500):
        # Send one command and wait for the reply
        # Clear any old UART data first so previous packets do not interfere
        while self.uart.any():
            self.uart.read()

        self.uart.write(self.build_packet(command, params))
        return self.read_packet(timeout_ms)

    @staticmethod
    def ack_code(response):
        if response is None or len(response) < 10:
            return None
        return response[9]

    # Sensor commands
    def verify_password(self):   return self.send_packet(0x13, b"\x00\x00\x00\x00")
    def get_image(self):         return self.send_packet(0x01, timeout_ms=1000)
    def image_to_tz(self, buf):  return self.send_packet(0x02, bytes([buf]), timeout_ms=1200)
    def create_model(self):      return self.send_packet(0x05, timeout_ms=1500)

    def search_model(self, buffer_id=1, start_page=0, page_num=1000):
        params = bytes([buffer_id]) + start_page.to_bytes(2, "big") + page_num.to_bytes(2, "big")
        return self.send_packet(0x04, params, timeout_ms=1500)

    def store_model(self, buffer_id, location_id):
        params = bytes([buffer_id]) + location_id.to_bytes(2, "big")
        return self.send_packet(0x06, params, timeout_ms=1500)

    def delete_model(self, location_id, count=1):
        params = location_id.to_bytes(2, "big") + count.to_bytes(2, "big")
        return self.send_packet(0x0C, params, timeout_ms=1500)

    def sensor_ready(self):
        return self.ack_code(self.verify_password()) == 0

    def wait_for_touch(self, display):
        # Wait until a finger is placed on the sensor
        display.place_finger()
        sleep(LCD_INFO_DELAY)

        while self.touch.value() == 0:
            if self.telemetry:
                self.telemetry.tick()
            time.sleep(0.05)

        # Short pause helps stabilise the initial touch before capture
        time.sleep(0.15)

    def wait_for_capture(self, display):
        # Wait until a usable fingerprint image has been captured
        display.scanning()
        sleep(LCD_ACTION_DELAY)

        while True:
            if self.telemetry:
                self.telemetry.tick()

            code = self.ack_code(self.get_image())

            if code == 0x00:
                return True
            elif code == 0x02:
                time.sleep(0.15)
            else:
                if code == 0x03:
                    display.image_unclear()
                elif code == 0x06:
                    display.finger_flatter()
                else:
                    display.finger_retry()

                sleep(LCD_INFO_DELAY)
                display.scanning()
                sleep(LCD_ACTION_DELAY)

    def wait_remove_finger(self, display):
        # Wait until the finger is removed from the sensor
        display.remove_finger()
        sleep(LCD_INFO_DELAY)

        while self.touch.value() == 1:
            if self.telemetry:
                self.telemetry.tick()
            time.sleep(0.05)

        # Confirm the sensor has fully returned to the no-finger state
        while True:
            if self.telemetry:
                self.telemetry.tick()

            if self.ack_code(self.get_image()) == 0x02:
                break

            time.sleep(0.1)

    def identify(self, display):
        # Identify a fingerprint and return (matched, score, id)
        # The score is returned so the runtime can apply a confidence threshold
        if not self.sensor_ready():
            display.sensor_error()
            sleep(LCD_ERROR_DELAY)
            return False, 0, 0

        self.wait_for_touch(display)
        self.wait_for_capture(display)

        if self.ack_code(self.image_to_tz(1)) != 0:
            display.finger_read_failed()
            self.wait_remove_finger(display)
            sleep(LCD_ERROR_DELAY)
            return False, 0, 0

        response = self.search_model()
        code     = self.ack_code(response)
        self.wait_remove_finger(display)

        if code == 0 and response is not None and len(response) >= 14:
            match_id = (response[10] << 8) | response[11]
            score    = (response[12] << 8) | response[13]
            display.fingerprint_positive()
            sleep(LCD_INFO_DELAY)
            return True, score, match_id

        display.fingerprint_negative()
        sleep(LCD_INFO_DELAY)
        return False, 0, 0

    def enrol(self, display, template_id):
        # Enrol a new fingerprint template using two scans
        # Two separate captures are used to build a more stable fingerprint model
        if not self.sensor_ready():
            display.sensor_error()
            sleep(LCD_ERROR_DELAY)
            return False

        display.enrol_first()
        sleep(LCD_ENROL_DELAY)
        self.wait_for_touch(display)
        self.wait_for_capture(display)

        if self.ack_code(self.image_to_tz(1)) != 0:
            self.wait_remove_finger(display)
            display.enrol_failed()
            sleep(LCD_ERROR_DELAY)
            return False

        self.wait_remove_finger(display)

        display.enrol_second()
        sleep(LCD_ENROL_DELAY)
        self.wait_for_touch(display)
        self.wait_for_capture(display)

        if self.ack_code(self.image_to_tz(2)) != 0:
            self.wait_remove_finger(display)
            display.enrol_failed()
            sleep(LCD_ERROR_DELAY)
            return False

        self.wait_remove_finger(display)

        if self.ack_code(self.create_model()) != 0:
            display.enrol_failed()
            sleep(LCD_ERROR_DELAY)
            return False

        if self.ack_code(self.store_model(1, template_id)) != 0:
            display.enrol_failed()
            sleep(LCD_ERROR_DELAY)
            return False

        display.enrol_done(template_id)
        sleep(LCD_INFO_DELAY)
        return True

    def clear_one(self, template_id):
        return self.ack_code(self.delete_model(template_id)) == 0