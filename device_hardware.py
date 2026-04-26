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
LCD_INFO_DELAY = 3
LCD_ACTION_DELAY = 2
LCD_ERROR_DELAY = 4
LCD_ENROL_DELAY = 4
SERVO_STEP_DELAY = 0.03
SERVO_ANGLE_STEP = 1
# -------------------- Display Manager --------------------
# Handles all LCD messages shown to the user
# Keeps wording and formatting consistent across the system
class DisplayManager:
    # LCD output interface
    def __init__(self, lcd_device):
        """
        Initialize display manager with LCD device reference.
        
        Args:
            lcd_device: I2cLcd instance for 16x2 character display
        """
        self.lcd = lcd_device
    def show(self, line1="", line2=""):
        """
        Display two lines of text on LCD.
        
        Automatically truncates to 16 characters per line to match display width.
        Clears display before writing to prevent ghosting.
        
        Args:
            line1 (str): Top line text
            line2 (str): Bottom line text
        """
        self.lcd.clear()
        self.lcd.move_to(0, 0)
        self.lcd.putstr(str(line1)[:16])
        self.lcd.move_to(0, 1)
        self.lcd.putstr(str(line2)[:16])
    # Lock / boot
    def boot(self): self.show("System Booting", "Please wait")
    def locked(self): self.show("System Secured", "Await Input")
    def system_error(self): self.show("System Error", " Safe Locked")
    # PIN
    def pin_entry(self, p=""): self.show("Enter PIN:", p)
    def pin_ok(self): self.show("PIN Verified", "Scan Finger")
    def denied(self): self.show("Access Denied", "Auth Failed")
    # Fingerprint flow
    def place_finger(self): self.show("Place Finger", "On Scanner")
    def scanning(self): self.show("Capturing Sample", "Please wait")
    def remove_finger(self): self.show("Remove Finger", "Please wait")
    def image_unclear(self): self.show("Sample unclear", "Rescan Required")
    def finger_flatter(self): self.show("Adjust Pressure", "On Scanner")
    def finger_retry(self): self.show("Rescan Required", "Place Finger")
    def finger_read_failed(self): self.show("Extraction Fail", "Rescan Required")
    def fingerprint_positive(self): self.show("Template Match", "User Verified")
    def fingerprint_negative(self): self.show("User invalid", "No Match Found")
    def sensor_error(self): self.show("Sensor Error", "Check Wiring")
    # Safe / system state
    def unlocking(self): self.show("Access Granted", "Unlocking...")
    def unlocked(self): self.show("Safe Unlocked", "Relocking soon..")
    def lockout(self, s): self.show("LOCKOUT ACTIVE", "{} sec left".format(s))
    # Risk feedback
    def risk_suspicious(self): self.show("Suspicious", "Monitoring")
    def risk_high(self): self.show("HIGH RISK", "Extended delay")
    # Admin menu
    def admin_menu(self): self.show("1:Auth 2:Enrol", "3:Clear")
    def enter_id(self): self.show("Enter ID", "#=OK *=Clear")
    def cannot_clear_admin(self): self.show("Admin Protected", "Cannot clear")
    def invalid_id(self): self.show("Invalid ID", "Try again")
    # Enrol / clear
    def enrol_first(self): self.show("Enrol Sample 1", "Place Finger")
    def enrol_second(self): self.show("Enrol Sample 2", "Place Again")
    def enrol_done(self, t): self.show("Template Stored", "ID {}".format(t))
    def enrol_failed(self): self.show("Enrol Aborted", "Try again")
    def clear_done(self, t): self.show("Template clear", "ID {}".format(t))
    def clear_failed(self): self.show("Clear failed", "Try again")
    # Verification code
    def enter_verification_code(self, masked=""): self.show("Enter TOTP Code", str(masked)[:16])
    def verification_code_ok(self): self.show("TOTP Verified", "Please wait")
    def verification_code_retry(self, tries_left):
        word = "Attempt" if tries_left == 1 else "Attempts"
        self.show("TOTP Rejected", "{} {} Left".format(tries_left, word)[:16])
    def time_error(self): self.show("Time not synced", "TOTP Unavailable")
# -------------------- RGB Status Indicator --------------------
# Controls the onboard NeoPixel LED for system status feedback
class StatusLED:
    # Onboard RGB LED on GPIO 8
    def __init__(self, pin_number=8, led_count=1):
        """
        Initialize NeoPixel LED controller.
        
        Args:
            pin_number (int): GPIO pin number for NeoPixel data line
            led_count (int): Number of LEDs in chain (default 1 for ESP32-C3 onboard)
        """
        from neopixel import NeoPixel
        self.np = NeoPixel(Pin(pin_number), led_count)
        self.off()
    def set(self, r, g, b):
        """
        Set LED color with RGB values.
        
        Args:
            r (int): Red intensity 0-255
            g (int): Green intensity 0-255
            b (int): Blue intensity 0-255
        """
        self.np[0] = (int(r), int(g), int(b))
        self.np.write()
    def off(self): self.set(0, 0, 0)
    def boot(self): self.set(0, 0, 25)
    def locked(self): self.set(0, 0, 10)
    def pin_ok(self): self.set(20, 20, 0)
    def access_granted(self): self.set(0, 25, 0)
    def access_denied(self): self.set(25, 0, 0)
    def warning(self): self.set(25, 18, 0)
    def high_risk(self): self.set(25, 0, 12)
    def admin(self): self.set(18, 0, 25)
    def error(self): self.set(25, 0, 0)
# -------------------- Servo Lock --------------------
# Controls the physical locking mechanism using PWM with smooth stepped movement
class ServoLock:
    """
    Servo-driven lock mechanism with smooth motion control.
    
    Uses stepped movement to prevent jerky motion and reduce mechanical stress.
    PWM duty cycle calculated for standard 50Hz servo control signal.
    """
    def __init__(self, pwm_pin, freq, locked_angle, unlocked_angle, step_delay=SERVO_STEP_DELAY, angle_step=SERVO_ANGLE_STEP):
        """
        Initialize servo lock controller.
        
        Args:
            pwm_pin (int): GPIO pin number for PWM servo control
            freq (int): PWM frequency in Hz (50Hz standard for servos)
            locked_angle (int): Servo angle in degrees for locked position
            unlocked_angle (int): Servo angle in degrees for unlocked position
            step_delay (float): Delay in seconds between movement steps
            angle_step (int): Degrees to move per step for smooth motion
        """
        self.pwm = PWM(Pin(pwm_pin), freq=freq)
        self.locked_angle = locked_angle
        self.unlocked_angle = unlocked_angle
        self.step_delay = step_delay
        self.angle_step = angle_step
        self.current_angle = locked_angle
        # Start in the locked position to support fail-secure behaviour
        self.pwm.duty_u16(self.angle_to_duty_u16(self.locked_angle))
        sleep(0.5)
    @staticmethod
    def angle_to_duty_u16(angle):
        """
        Convert servo angle to 16-bit PWM duty cycle.
        
        Standard servo PWM: 1ms pulse = 0°, 2ms pulse = 180°
        At 50Hz (20ms period): duty range 1600-8050 for 16-bit resolution
        
        Args:
            angle (int): Desired angle in degrees (0-180)
            
        Returns:
            int: 16-bit duty cycle value
        """
        angle = max(0, min(180, int(angle)))
        # Duty values empirically determined for SG90 servo at 50Hz
        min_duty = 1600
        max_duty = 8050
        return int(min_duty + ((max_duty - min_duty) * angle / 180))
    def move_smooth(self, target_angle):
        """
        Move servo to target angle with smooth stepped motion.
        
        Stepped movement prevents jerky motion and reduces mechanical stress
        on locking mechanism compared to instant position changes.
        
        Args:
            target_angle (int): Target position in degrees (0-180)
        """
        target_angle = max(0, min(180, int(target_angle)))
        if target_angle == self.current_angle:
            return
        # Determine step direction based on target
        step = self.angle_step if target_angle > self.current_angle else -self.angle_step
        for angle in range(self.current_angle, target_angle, step):
            self.pwm.duty_u16(self.angle_to_duty_u16(angle))
            time.sleep(self.step_delay)
        self.pwm.duty_u16(self.angle_to_duty_u16(target_angle))
        self.current_angle = target_angle
        time.sleep(0.2)
    def lock(self): self.move_smooth(self.locked_angle)
    def unlock(self): self.move_smooth(self.unlocked_angle)
# -------------------- Keypad Interface --------------------
# Handles 4x3 keypad input through the PCF8574 with simple debouncing
class Keypad:
    """
    4x3 matrix keypad scanner via PCF8574 I2C expander.
    
    Implements column scanning with debouncing to provide reliable single-press
    key events from mechanical switches.
    """
    KEY_VALUES = ("123", "456", "789", "*0#")
    def __init__(self, pcf_device):
        """
        Initialize keypad scanner.
        
        Args:
            pcf_device: PCF8574 I2C expander instance
        """
        self.pcf = pcf_device
        self._shadow_output = 0xFF
        self._last_key = None
        self.pcf.port = self._shadow_output
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
        """
        Scan keypad matrix and return active key if pressed.
        
        Implements column scanning: drive each column low sequentially and
        read row inputs to detect key matrix intersection.
        
        Returns:
            str or None: Key character if pressed, None if no key active
        """
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
        """Wait for key release to prevent repeat detection."""
        while self.scan_key() is not None:
            sleep_ms(10)
    def poll(self):
        """
        Return one debounced key event per physical press.
        
        Debouncing ensures one press produces one logical event, filtering
        mechanical switch bounce and preventing duplicate key detection.
        
        Returns:
            str or None: Key character on new press, None otherwise
        """
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
    """
    ZFM fingerprint sensor driver via UART communication.
    
    Implements proprietary packet protocol for fingerprint capture, template
    storage, and biometric matching operations.
    """
    # Protocol constants for ZFM sensor communication
    HEADER = b'\xEF\x01'
    ADDRESS = b'\xFF\xFF\xFF\xFF'
    PID_COMMAND = 0x01
    def __init__(self, uart_id, baudrate, tx_pin, rx_pin, touch_pin, telemetry=None):
        """
        Initialize fingerprint sensor interface.
        
        Args:
            uart_id (int): UART peripheral number
            baudrate (int): Serial baud rate (57600 for ZFM sensors)
            tx_pin (int): GPIO pin for UART TX
            rx_pin (int): GPIO pin for UART RX
            touch_pin (int): GPIO pin for capacitive touch detection
            telemetry: Optional telemetry manager for background processing
        """
        self.uart = UART(uart_id, baudrate=baudrate, tx=Pin(tx_pin), rx=Pin(rx_pin))
        self.touch = Pin(touch_pin, Pin.IN)
        self.telemetry = telemetry
    def build_packet(self, command, params=b""):
        """
        Build ZFM protocol packet with checksum.
        
        Packet format: HEADER + ADDRESS + PID + LENGTH + COMMAND + PARAMS + CHECKSUM
        
        Args:
            command (int): Command byte
            params (bytes): Command parameters
            
        Returns:
            bytes: Complete packet ready for transmission
        """
        length = len(params) + 3
        body = bytes([self.PID_COMMAND]) + length.to_bytes(2, "big") + bytes([command]) + params
        checksum = sum(body).to_bytes(2, "big")
        return self.HEADER + self.ADDRESS + body + checksum
    def read_packet(self, timeout_ms=1500):
        """
        Read complete packet from sensor with timeout.
        
        Accumulates bytes until full packet received based on length field.
        
        Args:
            timeout_ms (int): Maximum wait time in milliseconds
            
        Returns:
            bytes or None: Complete packet or None on timeout
        """
        start = time.ticks_ms()
        buffer = b""
        # Read until complete packet received or timeout
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
        """
        Send command packet and receive response.
        
        Clears UART buffer before sending to prevent stale data interference.
        
        Args:
            command (int): Command byte
            params (bytes): Command parameters
            timeout_ms (int): Response timeout in milliseconds
            
        Returns:
            bytes or None: Response packet or None on timeout
        """
        # Clear any old UART data first so previous packets do not interfere
        while self.uart.any():
            self.uart.read()
        self.uart.write(self.build_packet(command, params))
        return self.read_packet(timeout_ms)
    @staticmethod
    def ack_code(response):
        """
        Extract acknowledgment code from response packet.
        
        Args:
            response (bytes): Packet from sensor
            
        Returns:
            int or None: ACK code or None if invalid packet
        """
        if response is None or len(response) < 10:
            return None
        return response[9]
    # Sensor commands
    def verify_password(self): return self.send_packet(0x13, b"\x00\x00\x00\x00")
    def get_image(self): return self.send_packet(0x01, timeout_ms=1000)
    def image_to_tz(self, buf): return self.send_packet(0x02, bytes([buf]), timeout_ms=1200)
    def create_model(self): return self.send_packet(0x05, timeout_ms=1500)
    def search_model(self, buffer_id=1, start_page=0, page_num=1000):
        params = bytes([buffer_id]) + start_page.to_bytes(2, "big") + page_num.to_bytes(2, "big")
        return self.send_packet(0x04, params, timeout_ms=1500)
    def store_model(self, buffer_id, location_id):
        params = bytes([buffer_id]) + location_id.to_bytes(2, "big")
        return self.send_packet(0x06, params, timeout_ms=1500)
    def delete_model(self, location_id, count=1):
        params = location_id.to_bytes(2, "big") + count.to_bytes(2, "big")
        return self.send_packet(0x0C, params, timeout_ms=1500)
    def sensor_ready(self): return self.ack_code(self.verify_password()) == 0
    def wait_for_touch(self, display):
        """
        Wait for finger placement on sensor.
        
        Monitors capacitive touch pin and processes telemetry during wait
        to keep network active.
        
        Args:
            display: DisplayManager instance for user prompts
        """
        display.place_finger()
        sleep(LCD_INFO_DELAY)
        while self.touch.value() == 0:
            if self.telemetry:
                self.telemetry.tick()
            time.sleep(0.05)
        # Short pause helps stabilise the initial touch before capture
        time.sleep(0.15)
    def wait_for_capture(self, display):
        """
        Wait for successful fingerprint image capture.
        
        Retries on common failures (no finger, unclear image, pressure issues)
        with user feedback via LCD.
        
        Args:
            display: DisplayManager instance for user feedback
            
        Returns:
            bool: True when valid image captured
        """
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
        """
        Wait for finger removal from sensor.
        
        Confirms sensor has returned to idle state before proceeding.
        
        Args:
            display: DisplayManager instance for user prompts
        """
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
        """
        Identify fingerprint against stored templates.
        
        Returns confidence score to allow runtime threshold adjustment
        based on risk level.
        
        Args:
            display: DisplayManager instance for user feedback
            
        Returns:
            tuple: (matched, score, id) where:
                matched (bool): True if template match found
                score (int): Confidence score 0-255
                id (int): Matched template ID or 0 if no match
        """
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
        code = self.ack_code(response)
        self.wait_remove_finger(display)
        if code == 0 and response is not None and len(response) >= 14:
            match_id = (response[10] << 8) | response[11]
            score = (response[12] << 8) | response[13]
            display.fingerprint_positive()
            sleep(LCD_INFO_DELAY)
            return True, score, match_id
        display.fingerprint_negative()
        sleep(LCD_INFO_DELAY)
        return False, 0, 0
    def enrol(self, display, template_id):
        """
        Enrol new fingerprint template using two captures.
        
        Two separate captures build a more stable fingerprint model and
        reduce false reject rate during authentication.
        
        Args:
            display: DisplayManager instance for user feedback
            template_id (int): Storage location for new template
            
        Returns:
            bool: True if enrolment successful
        """
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
        """
        Delete single fingerprint template.
        
        Args:
            template_id (int): Template storage location to clear
            
        Returns:
            bool: True if deletion successful
        """
        return self.ack_code(self.delete_model(template_id)) == 0
