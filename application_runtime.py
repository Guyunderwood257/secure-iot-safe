# -------------------- Secure Multi-Layer Biometric Authentication Runtime --------------------
# Submission date: 05.05.26
# ESP32-C3 secured multi-layer biometric control runtime
#
# Features:
# - Student ID digit PIN entry
# - Fingerprint verification
# - Time-based verification code (2FA)
# - LCD user feedback
# - Servo lock control
# - Failed-attempt lockout
# - Per-attempt shell logging
# - Admin fingerprint menu (unlock / enrol / clear)
# - ESP32-C3 NeoPixel status updates
#
# Anti-spoofing and identity-impersonation resistance:
# - Fingerprint confidence threshold enforcement
# - Fingerprint repeated-failure limiting
# - Repeated session-failure monitoring
# - Staged security escalation from behaviour
#
# Machine learning (ML):
# - Embedded risk scoring model
# - Online weight updates after each outcome
# - Behaviour-driven risk classification
#
# Cybersecurity:
# - SHA-256 salted PIN hashing
# - Constant-time hash comparison
# - Honeypot decoy PIN detection
# - Capture-the-Flag style deception / trap response
# - Fingerprint brute-force resistance
# - Tamper-evident SHA-256 chained logs
# - Staged lockout escalation
#
# Data protection:
# - XOR stream cipher for cloud status
# - HMAC-SHA1 keystream generation
# - AES protection for selected local records
#
# Wi-Fi telemetry:
# - ThingSpeak cloud logging
# - Background queued event upload
# - Automatic retry through the boot telemetry service
#
# Design principles:
# - Fail secure
# - Multi-layered authentication
# - Behaviour-driven security decisions
# - Maintain local autonomy
#
# Sensitive credentials are stored in a separate local configuration file
# (mykeys_config.py) which is excluded from submission for security reasons.
from machine import Pin, I2C
from time import sleep, sleep_ms
import ubinascii
import struct
import time
import uhashlib
from device_hardware import DisplayManager, StatusLED, ServoLock, Keypad, FingerprintSensor
# -------------------- Hardware --------------------
I2C_BUS_ID = 0
I2C_SCL_PIN = 6
I2C_SDA_PIN = 7
I2C_FREQ = 100000
LCD_I2C_ADDR = 0x27
LCD_ROWS = 2
LCD_COLS = 16
PCF8574_ADDR = 0x20
FP_UART_ID = 1
FP_BAUDRATE = 57600
FP_TX_PIN = 4
FP_RX_PIN = 5
FP_TOUCH_PIN = 3
SERVO_PIN = 10
SERVO_FREQ = 50
LOCKED_ANGLE = 180
UNLOCKED_ANGLE = 90
SERVO_STEP_DELAY = 0.02
SERVO_ANGLE_STEP = 1
AUTO_RELOCK_SECONDS = 60
# -------------------- Security Settings --------------------
# Student number PIN entry is stored only as a salted SHA-256 hash
MASTER_PIN_HASH = ubinascii.unhexlify("d35258b5938aa832236fea9dcae1ddd0f6094afac9dd5aef037f4ae4ed006c31")
# 3 attempts balances security vs usability - prevents brute force while allowing human error
MAX_FAILED_ATTEMPTS = 3
BASE_LOCKOUT_TIME_SECONDS = 10
MAX_LOCKOUT_TIME_SECONDS = 30
PIN_SALT = "ESP32SAFE01"
# -------------------- Sensitive Configuration --------------------
# Secrets are stored in mykeys_config.py (not included in submission)
from mykeys_config import (VERIFICATION_CODE_SECRET, TELEMETRY_CIPHER_KEY, LOCAL_AES_KEY)
# Decoy PIN used for deception-based trap behaviour
HONEYPOT_PIN_HASH = ubinascii.unhexlify("26f3cc2b30060fa74871aad1ae08332cf14383e2674352ae2f2814d603a3a860")
# Fingerprint brute-force and spoof-resistance settings
ADMIN_FINGERPRINT_ID = 1
MIN_USER_FINGERPRINT_ID = 2
MAX_USER_FINGERPRINT_ID = 20
# 5 attempts per session prevents sensor brute-force while tolerating poor placement
FP_MAX_ATTEMPTS = 5
# Score of 50 balances false accept rate vs false reject rate for ZFM sensors
FP_MIN_SCORE = 50
# Verification code settings
VERIFICATION_CODE_ENABLED = True
VERIFICATION_CODE_DIGITS = 6
# 30-second window standard for TOTP per RFC 6238
VERIFICATION_CODE_INTERVAL = 30
MAX_VERIFICATION_CODE_ATTEMPTS = 3
# Final escalation settings
# 3 final attempts before admin intervention balances security vs false lockout
FINAL_HIGH_RISK_ATTEMPTS = 3
# -------------------- LCD Timing --------------------
LCD_BOOT_DELAY = 2
LCD_INFO_DELAY = 1
LCD_ACTION_DELAY = 1
LCD_ERROR_DELAY = 2
LCD_WARNING_DELAY = 3
LCD_ADMIN_PROTECT_DELAY = 3
LCD_ENROL_DELAY = 2
# -------------------- Output --------------------
SHOW_ATTEMPT_LOG = True
LOG_LABEL_WIDTH = 16
# -------------------- Event Codes --------------------
EVENT_SYSTEM_ARMED = 1
EVENT_PIN_ACCEPTED = 2
EVENT_FINGERPRINT_VERIFIED = 3
EVENT_SYSTEM_UNLOCKED = 4
EVENT_SYSTEM_RELOCKED = 5
EVENT_FAILED_ATTEMPT = 6
EVENT_LOCKOUT = 7
EVENT_ADMIN_ACTION = 8
EVENT_VERIFICATION_CODE_VERIFIED = 9
REASON_NONE = "none"
REASON_WRONG_PIN = "wrong_pin"
REASON_FINGERPRINT_FAILED = "fingerprint_failed"
REASON_LOCKOUT = "lockout"
REASON_ENROL = "enrol"
REASON_CLEAR = "clear"
REASON_VERIFICATION_CODE_FAILED = "verification_code_failed"
REASON_ADMIN_ALERT = "admin_alert"
RISK_NORMAL = "normal"
RISK_SUSPICIOUS = "suspicious"
RISK_HIGH = "high_risk"
# Thresholds empirically chosen - 20% triggers observation, 40% triggers alert
RISK_THRESHOLD_SUSPICIOUS = 20
RISK_THRESHOLD_HIGH = 40
# Time windows for behavioural analysis - balance responsiveness vs noise
RISK_FAIL_WINDOW_SECONDS = 60
RISK_LOCKOUT_WINDOW_SECONDS = 300
telemetry = None
# -------------------- Helpers --------------------
def clean_text(value):
    # Remove characters that would break simple shell log formatting
    return str(value).replace(",", ";").replace("\n", " ").replace("\r", " ")
def base32_decode(text):
    """
    Decode Base32-encoded TOTP secret per RFC 4648.
    
    Args:
        text (str): Base32-encoded secret string
        
    Returns:
        bytes: Decoded binary secret for HMAC-SHA1
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    text = text.replace(" ", "").replace("=", "").upper()
    bits = 0
    value = 0
    output = bytearray()
    for ch in text:
        idx = alphabet.find(ch)
        if idx == -1:
            continue
        value = (value << 5) | idx
        bits += 5
        while bits >= 8:
            bits -= 8
            output.append((value >> bits) & 0xFF)
    return bytes(output)
def sha1_digest(data):
    return uhashlib.sha1(data).digest()
def hmac_sha1(key, msg):
    """
    Compute HMAC-SHA1 for TOTP and telemetry encryption per RFC 2104.
    
    Args:
        key (bytes): Secret key
        msg (bytes): Message to authenticate
        
    Returns:
        bytes: 20-byte HMAC-SHA1 digest
    """
    block_size = 64
    if len(key) > block_size:
        key = sha1_digest(key)
    if len(key) < block_size:
        key = key + b"\x00" * (block_size - len(key))
    o_key_pad = bytes([b ^ 0x5C for b in key])
    i_key_pad = bytes([b ^ 0x36 for b in key])
    return sha1_digest(o_key_pad + sha1_digest(i_key_pad + msg))
# -------------------- Security Helpers --------------------
# Cybersecurity controls:
# - Salted SHA-256 prevents plaintext PIN storage
# - Constant-time comparison reduces timing-attack leakage
# - Honeypot PIN introduces deception-based intrusion detection
# - Lockout escalation mitigates brute-force attacks
# - Hash-chained logs provide tamper evidence for forensic analysis
def hash_pin(pin):
    # Hash the PIN with a salt so plaintext credentials are never stored
    return uhashlib.sha256((PIN_SALT + pin).encode()).digest()
def constant_time_compare(a, b):
    """
    Constant-time comparison to prevent timing side-channel attacks.
    
    Standard equality (==) can leak information through execution time variations.
    This implementation ensures all code paths take equal time regardless of
    where the mismatch occurs in the byte sequence.
    
    Args:
        a (bytes): First value
        b (bytes): Second value
        
    Returns:
        bool: True if values match, False otherwise
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= (x ^ y)
    return result == 0
# -------------------- Data Protection --------------------
def encrypt_status(text):
    # Encrypt cloud status text using an XOR keystream derived from HMAC-SHA1
    data = text.encode()
    stream = b""
    block = 0
    while len(stream) < len(data):
        stream += hmac_sha1(TELEMETRY_CIPHER_KEY, struct.pack(">I", block))
        block += 1
    encrypted = bytes([d ^ k for d, k in zip(data, stream)])
    return ubinascii.hexlify(encrypted).decode()
def pad16(data):
    # Pad data to a 16-byte boundary for AES
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len
def unpad16(data):
    # Remove 16-byte PKCS-style padding
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data
    return data[:-pad_len]
def aes_encrypt_local(text, key=LOCAL_AES_KEY):
    # Encrypt a local record with AES-CBC before sealing it
    import ucryptolib
    data = pad16(text.encode())
    iv = b"\x00" * 16
    cipher = ucryptolib.aes(key, 2, iv)
    return ubinascii.hexlify(cipher.encrypt(data)).decode()
def aes_decrypt_local(hex_text, key=LOCAL_AES_KEY):
    # Decrypt a sealed local record when needed
    import ucryptolib
    iv = b"\x00" * 16
    data = ubinascii.unhexlify(hex_text)
    cipher = ucryptolib.aes(key, 2, iv)
    plain = cipher.decrypt(data)
    return unpad16(plain).decode()
def unix_time_now():
    """
    Convert MicroPython epoch to Unix time for TOTP compatibility.
    
    MicroPython uses 2000-01-01 as epoch, Unix uses 1970-01-01.
    The offset of 946684800 seconds accounts for this difference.
    
    Returns:
        int: Current Unix timestamp
    """
    now = int(time.time())
    return now + 946684800 if time.gmtime(0)[0] == 2000 else now
# Telemetry is processed in small background ticks so network delays
# do not interfere with time-critical authentication logic.
def telemetry_tick():
    global telemetry
    if telemetry is not None:
        telemetry.tick()
# -------------------- Machine Learning --------------------
# A lightweight logistic regression model is used to estimate behavioural risk.
# It operates on-device using scaled features such as:
# - wrong PIN attempts
# - fingerprint failures
# - lockout frequency
# - rapid retries
#
# The model is updated online after each authentication attempt,
# allowing adaptive security behaviour without external dependencies.
class RiskEngine:
    """
    On-device logistic regression for behavioural risk scoring.
    
    Uses online learning to adapt security response based on attack patterns.
    Features are normalized to [0,1] range for numerical stability.
    Sigmoid output is scaled to [0,100] percentage for interpretability.
    """
    def __init__(self, learning_rate=0.12):
        """
        Initialize risk model with conservative bias.
        
        Args:
            learning_rate (float): Gradient descent step size (0.12 chosen empirically)
        """
        self.learning_rate = learning_rate
        # Negative bias makes model pessimistic - requires positive evidence for low risk
        self.bias = -2.0
        self.weights = {"wrong_pin_count": 0.0, "fingerprint_fail_count": 0.0, "lockout_count": 0.0, "rapid_retry_flag": 0.0, "repeated_session_fail_flag": 0.0}
    def _sigmoid(self, z):
        """
        Sigmoid activation with clamping to prevent overflow.
        
        Args:
            z (float): Weighted input sum
            
        Returns:
            float: Probability in range [0,1]
        """
        # Clamp at ±20 to prevent exp() overflow on resource-constrained ESP32-C3
        if z < -20:
            return 0.0
        if z > 20:
            return 1.0
        return 1.0 / (1.0 + (2.718281828 ** -z))
    def _features(self, wrong_pin, fp_fail, lockout, rapid, repeated):
        """
        Normalize behavioural features to [0,1] range.
        
        Normalization denominators chosen based on system thresholds:
        - 5 PINs: MAX_FAILED_ATTEMPTS + margin
        - 5 fingerprints: FP_MAX_ATTEMPTS
        - 3 lockouts: escalation stages before final warning
        
        Args:
            wrong_pin (int): Wrong PIN count in time window
            fp_fail (int): Fingerprint failure count in time window
            lockout (int): Lockout count in time window
            rapid (int): Binary flag for rapid retry pattern
            repeated (int): Binary flag for repeated session failures
            
        Returns:
            dict: Normalized features
        """
        return {"wrong_pin_count": min(wrong_pin / 5.0, 1.0), "fingerprint_fail_count": min(fp_fail / 5.0, 1.0), "lockout_count": min(lockout / 3.0, 1.0), "rapid_retry_flag": float(rapid), "repeated_session_fail_flag": float(repeated)}
    def _compute_z(self, features):
        # Calculate the weighted input sum including the model bias
        z = self.bias
        for name, value in features.items():
            z += self.weights[name] * value
        return z
    def evaluate(self, wrong_pin, fp_fail, lockout, rapid, repeated):
        """
        Compute current risk score from behavioural features.
        
        Args:
            wrong_pin (int): Wrong PIN count in time window
            fp_fail (int): Fingerprint failure count in time window
            lockout (int): Lockout count in time window
            rapid (int): Binary flag for ≥3 failures in 60s
            repeated (int): Binary flag for ≥2 consecutive session failures
            
        Returns:
            tuple: (score, level) where score is 0-100 and level is normal/suspicious/high_risk
        """
        features = self._features(wrong_pin, fp_fail, lockout, rapid, repeated)
        score = int(self._sigmoid(self._compute_z(features)) * 100)
        if score >= RISK_THRESHOLD_HIGH:
            level = RISK_HIGH
        elif score >= RISK_THRESHOLD_SUSPICIOUS:
            level = RISK_SUSPICIOUS
        else:
            level = RISK_NORMAL
        return score, level
    def train(self, wrong_pin, fp_fail, lockout, rapid, repeated, label):
        """
        Update model weights using gradient descent.
        
        Online learning allows the model to adapt to attack patterns specific
        to this deployment without requiring pre-training on labeled data.
        
        Args:
            wrong_pin (int): Wrong PIN count in time window
            fp_fail (int): Fingerprint failure count in time window
            lockout (int): Lockout count in time window
            rapid (int): Binary flag for rapid retry pattern
            repeated (int): Binary flag for repeated session failures
            label (int): Ground truth (0=legitimate, 1=failed attempt)
            
        Returns:
            tuple: (prediction, error) for logging and analysis
        """
        features = self._features(wrong_pin, fp_fail, lockout, rapid, repeated)
        prediction = self._sigmoid(self._compute_z(features))
        error = label - prediction
        self.bias += self.learning_rate * error
        for name, value in features.items():
            self.weights[name] += self.learning_rate * error * value
        return prediction, error
# -------------------- Main System --------------------
class SecurityControlSystem:
    # Main security controller for the safe, covering authentication,
    # locking, logging, and risk handling
    def __init__(self, display, status_led, keypad, fingerprint, servo_lock):
        self.display = display
        self.status_led = status_led
        self.keypad = keypad
        self.fingerprint = fingerprint
        self.servo_lock = servo_lock
        # Access state
        self.failed_attempts = 0
        self.total_failed_attempts = 0
        # Risk state
        self.risk_engine = RiskEngine()
        self.current_risk_score = 0
        self.current_risk_level = RISK_NORMAL
        # Risk counters
        self.recent_fail_times = []
        self.recent_lockout_times = []
        self.wrong_pin_times = []
        self.fingerprint_fail_times = []
        self.consecutive_failed_sessions = 0
        # TOTP key decoded once during startup
        self._totp_key = base32_decode(VERIFICATION_CODE_SECRET)
        # Fingerprint session state
        self.fp_session_failures = 0
        # Tamper-evident hash chain used across shell logs
        self.log_chain_hash = bytes(32)
        # Lockout counter
        self.total_lockout_count = 0
        # Escalation state
        self.lockout_stage = 0
        self.final_warning_mode = False
        self.high_risk_attempts_left = FINAL_HIGH_RISK_ATTEMPTS
        self.permanent_lockdown = False
        # Attempt log
        self.attempt_number = 0
        self.attempt_log_lines = []
    def start_new_attempt(self):
        # Reset the current log buffer and move to the next attempt number
        self.attempt_number += 1
        self.attempt_log_lines = []
    # Each attempt is recorded and linked via a SHA-256 hash chain,
    # making modification of past logs detectable.
    def add_attempt_log(self, label, message):
        text = clean_text(message)
        chain_input = self.log_chain_hash + str(label).encode() + b":" + text.encode()
        self.log_chain_hash = uhashlib.sha256(chain_input).digest()
        self.attempt_log_lines.append((str(label), text))
    def print_attempt_log(self):
        # Print the full attempt block to the shell
        if not SHOW_ATTEMPT_LOG:
            return
        print("")
        print("================ ATTEMPT {} ================".format(self.attempt_number))
        last_label = None
        for label, message in self.attempt_log_lines:
            if last_label and label != last_label:
                print("")
            print("{:<{}} {}".format(label, LOG_LABEL_WIDTH, message))
            last_label = label
        print("{:<{}} {}".format("CHAIN", LOG_LABEL_WIDTH, ubinascii.hexlify(self.log_chain_hash).decode()))
        print("===========================================")
        print("")
    def _seal_local_record(self, text):
        # Seal important local records using AES before logging a shortened reference
        sealed = aes_encrypt_local(text)
        self.add_attempt_log("SEALED", sealed[:48] + "...")
    def _build_status_text(self, event_text, reason, fp, lock, access_result, extra=""):
        # Build a readable status line for ThingSpeak status-telemetry previous event display.
        # This is kept separate from the encrypted telemetry payload so the
        # MATLAB event-log widget can show human-readable recent events.
        # Extract short label from event_text
        if "method=pin" in event_text:
            parts = ["PIN VERIFIED"]
        elif "method=fingerprint" in event_text:
            parts = ["FINGERPRINT VERIFIED"]
        elif "method=2fa_code" in event_text:
            parts = ["2FA VERIFIED"]
        elif "access_granted" in event_text:
            parts = ["ACCESS GRANTED"]
        elif "system_secured" in event_text:
            parts = ["SYSTEM LOCKED"]
        else:
            parts = ["EVENT"]
        if reason != REASON_NONE:
            parts.append("reason={}".format(reason))
        parts.append("risk={}".format(self.current_risk_level))
        parts.append("score={}".format(self.current_risk_score))
        if access_result == 1:
            parts.append("ACCESS GRANTED")
        else:
            parts.append("ACCESS DENIED")
        if lock == 0:
            parts.append("UNLOCKED")
        else:
            parts.append("LOCKED")
        if extra:
            # Reformat semicolon-separated extra metadata into readable style
            parts.append(str(extra).replace(";", " | "))
        return " | ".join(parts)
    def _log_event(self, event_code, event_text, reason=REASON_NONE, extra="", fp=0, lock=1, access_result=0, fa=None):
        """
        Log event to both cloud telemetry and local chain.
        
        Args:
            event_code (int): Numeric event type for ThingSpeak field1
            event_text (str): Event description for encryption
            reason (str): Failure reason if applicable
            extra (str): Additional semicolon-separated metadata
            fp (int): Fingerprint confidence score 0-255
            lock (int): Lock state (0=unlocked, 1=locked)
            access_result (int): Access decision (0=denied, 1=granted)
            fa (int): Override for failed_attempts count (defaults to self.failed_attempts)
        """
        base = "{};reason={};risk={};score={};total_failed={}".format(event_text, reason, self.current_risk_level, self.current_risk_score, self.total_failed_attempts)
        stealth_flag = ""
        if self.current_risk_level == RISK_SUSPICIOUS:
            stealth_flag = ";stealth=observe"
        elif self.current_risk_level == RISK_HIGH:
            stealth_flag = ";stealth=alert"
        status = base + stealth_flag
        if extra:
            status += ";{}".format(extra)
        status_text = self._build_status_text(event_text, reason, fp, lock, access_result, extra)
        if telemetry is not None:
            telemetry.queue_event(event_code, self.failed_attempts if fa is None else fa, fp, lock, access_result, encrypt_status(status), risk_score=self.current_risk_score, lockout_count=self.total_lockout_count, fp_failures=self.fp_session_failures, status_text=status_text)
        self.add_attempt_log("TELEMETRY", status_text)
    def add_mllog_summary(self, result_text, reason_text, fp_score=0):
        # Add one summary line showing the overall ML outcome for the attempt
        text = "attempt={};result={};reason={};risk={};score={};fp_score={};total_failed={}".format(self.attempt_number, result_text, reason_text, self.current_risk_level, self.current_risk_score, fp_score, self.total_failed_attempts)
        self.add_attempt_log("MLLOG", text)
    def train_risk_model(self, label):
        # Let the risk model adapt gradually based on recent labelled outcomes
        rapid = 1 if len(self.recent_fail_times) >= 3 else 0
        repeated = 1 if self.consecutive_failed_sessions >= 2 else 0
        prediction, error = self.risk_engine.train(len(self.wrong_pin_times), len(self.fingerprint_fail_times), len(self.recent_lockout_times), rapid, repeated, label)
        self.add_attempt_log("MLTRAIN", "label={} pred={:.2f} err={:.2f}".format(label, prediction, error))
    # Behavioural anti-impersonation:
    # User behaviour is monitored across repeated failures, retry patterns,
    # and lockouts so the system can adapt to suspicious behaviour.
    def update_risk(self, reason=REASON_NONE, lockout_started=False):
        now = int(time.time())
        # Prune timestamps outside analysis windows
        self.recent_fail_times = [t for t in self.recent_fail_times if (now - t) <= RISK_FAIL_WINDOW_SECONDS]
        self.recent_lockout_times = [t for t in self.recent_lockout_times if (now - t) <= RISK_LOCKOUT_WINDOW_SECONDS]
        self.wrong_pin_times = [t for t in self.wrong_pin_times if (now - t) <= RISK_FAIL_WINDOW_SECONDS]
        self.fingerprint_fail_times = [t for t in self.fingerprint_fail_times if (now - t) <= RISK_FAIL_WINDOW_SECONDS]
        # Record new failure timestamp
        if reason == REASON_WRONG_PIN:
            self.wrong_pin_times.append(now)
            self.recent_fail_times.append(now)
        if reason == REASON_FINGERPRINT_FAILED:
            self.fingerprint_fail_times.append(now)
            self.recent_fail_times.append(now)
        if reason == REASON_VERIFICATION_CODE_FAILED:
            self.recent_fail_times.append(now)
        if lockout_started:
            self.recent_lockout_times.append(now)
        # Compute derived features for ML model
        rapid = 1 if len(self.recent_fail_times) >= 3 else 0
        repeated = 1 if self.consecutive_failed_sessions >= 2 else 0
        self.current_risk_score, self.current_risk_level = self.risk_engine.evaluate(len(self.wrong_pin_times), len(self.fingerprint_fail_times), len(self.recent_lockout_times), rapid, repeated)
        self.add_attempt_log("RISK", "score={} level={} failed_attempts={} total_failed_attempts={}".format(self.current_risk_score, self.current_risk_level, self.failed_attempts, self.total_failed_attempts))
        if self.current_risk_level == RISK_SUSPICIOUS:
            self.add_attempt_log("STEALTH", "Observation mode active")
        elif self.current_risk_level == RISK_HIGH:
            self.add_attempt_log("STEALTH", "Silent alert mode active")
    def show_risk_feedback_if_needed(self):
        # Keep visible risk feedback short and generic so it does not reveal too much
        if self.current_risk_level == RISK_HIGH or self.final_warning_mode or self.permanent_lockdown:
            self.display.risk_high()
            self.status_led.high_risk()
        elif self.current_risk_level == RISK_SUSPICIOUS:
            self.display.risk_suspicious()
            self.status_led.warning()
        else:
            return
        sleep(LCD_INFO_DELAY)
        self.status_led.locked()
    def generate_verification_code(self, unix_seconds):
        """
        Generate TOTP verification code per RFC 6238.
        
        Uses HMAC-SHA1 with 30-second time step and 6-digit output.
        Offset-based truncation extracts 4 bytes from digest deterministically.
        
        Args:
            unix_seconds (int): Current Unix timestamp
            
        Returns:
            str: 6-digit code with leading zeros
        """
        counter = int(unix_seconds // VERIFICATION_CODE_INTERVAL)
        msg = struct.pack(">Q", counter)
        digest = hmac_sha1(self._totp_key, msg)
        # Dynamic truncation per RFC 6238
        offset = digest[-1] & 0x0F
        code = (((digest[offset] & 0x7F) << 24) | ((digest[offset + 1] & 0xFF) << 16) | ((digest[offset + 2] & 0xFF) << 8) | (digest[offset + 3] & 0xFF))
        code = code % (10 ** VERIFICATION_CODE_DIGITS)
        code_text = str(code)
        while len(code_text) < VERIFICATION_CODE_DIGITS:
            code_text = "0" + code_text
        return code_text
    def verify_verification_code(self, entered_code):
        """
        Verify TOTP code with time window tolerance.
        
        Accepts codes from previous, current, and next time windows to handle
        clock drift and user input delays.
        
        Args:
            entered_code (str): User-entered 6-digit code
            
        Returns:
            bool: True if code matches any valid window
        """
        now = unix_time_now()
        valid_codes = (self.generate_verification_code(now - VERIFICATION_CODE_INTERVAL), self.generate_verification_code(now), self.generate_verification_code(now + VERIFICATION_CODE_INTERVAL))
        return entered_code in valid_codes
    def get_pin(self):
        # Read PIN input from the keypad; # confirms and * clears the entry
        entered = ""
        self.display.pin_entry("")
        while True:
            telemetry_tick()  # Keep network active during input
            key = self.keypad.poll()
            if key is None:
                sleep_ms(10)
                continue
            if key in "0123456789":
                entered += key
                self.display.pin_entry(("*" * len(entered))[-16:])
            elif key == "*":
                entered = ""
                self.display.pin_entry("")
            elif key == "#":
                if len(entered) > 0:
                    return entered
    def get_admin_choice(self):
        # Read one valid admin menu selection
        self.display.admin_menu()
        sleep(LCD_INFO_DELAY)
        while True:
            telemetry_tick()
            key = self.keypad.poll()
            if key in ("1", "2", "3"):
                return key
    def get_template_id(self):
        # Read a numeric template ID; # confirms and * clears the entry
        entered = ""
        self.display.enter_id()
        sleep(LCD_INFO_DELAY)
        while True:
            telemetry_tick()
            key = self.keypad.poll()
            if key is None:
                sleep_ms(10)
                continue
            if key in "0123456789":
                if len(entered) < 2:
                    entered += key
                    self.display.show("Enter ID", entered)
            elif key == "*":
                entered = ""
                self.display.enter_id()
            elif key == "#":
                if len(entered) > 0:
                    return int(entered)
    def get_verification_code(self):
        # Read the verification code from the keypad
        entered = ""
        self.display.enter_verification_code("")
        sleep(LCD_INFO_DELAY)
        while True:
            telemetry_tick()
            key = self.keypad.poll()
            if key is None:
                sleep_ms(10)
                continue
            if key in "0123456789":
                if len(entered) < VERIFICATION_CODE_DIGITS:
                    entered += key
                    self.display.enter_verification_code(("*" * len(entered))[-16:])
            elif key == "*":
                entered = ""
                self.display.enter_verification_code("")
            elif key == "#":
                if len(entered) > 0:
                    return entered
    def verification_code_step(self):
        # The verification code step depends on a valid system clock
        if not VERIFICATION_CODE_ENABLED:
            return True
        now = unix_time_now()
        # Unix timestamp ~November 2023 - sanity check for valid NTP sync
        if now < 1700000000:
            self.display.time_error()
            self.add_attempt_log("EVENT", "Verification code unavailable - time not synced")
            sleep(LCD_ERROR_DELAY)
            return False
        attempts = 0
        while attempts < MAX_VERIFICATION_CODE_ATTEMPTS:
            entered_code = self.get_verification_code()
            self.add_attempt_log("EVENT", "Entered verification code")
            if self.verify_verification_code(entered_code):
                self.display.verification_code_ok()
                self.add_attempt_log("EVENT", "Verification code accepted")
                self._log_event(EVENT_VERIFICATION_CODE_VERIFIED, "event=access_attempt;method=2fa_code;outcome=verified", extra="pin_verified=1", access_result=1)
                sleep(LCD_INFO_DELAY)
                return True
            attempts += 1
            self.add_attempt_log("EVENT", "Verification code failed count={}".format(attempts))
            if attempts >= MAX_VERIFICATION_CODE_ATTEMPTS:
                break
            self.display.verification_code_retry(MAX_VERIFICATION_CODE_ATTEMPTS - attempts)
            sleep(LCD_INFO_DELAY)
        self.add_attempt_log("EVENT", "Verification code retry limit reached")
        return False
    def current_lockout_seconds(self):
        # Escalating timed lockout sequence
        if self.lockout_stage == 0:
            return 10
        if self.lockout_stage == 1:
            return 20
        return 30
    def reset_escalation_state(self):
        # Clear staged lockout escalation after a successful authorised session
        self.lockout_stage = 0
        self.final_warning_mode = False
        self.high_risk_attempts_left = FINAL_HIGH_RISK_ATTEMPTS
        self.permanent_lockdown = False
    def enter_final_warning_mode(self):
        # After the 30-second lockout, allow only 3 final attempts
        self.final_warning_mode = True
        self.high_risk_attempts_left = FINAL_HIGH_RISK_ATTEMPTS
        self.add_attempt_log("SECURITY", "Final high-risk warning mode active")
        self.display.show("HIGH RISK", "3 Attempts Left")
        self.status_led.high_risk()
        sleep(LCD_WARNING_DELAY)
        self.display.locked()
        self.status_led.locked()
        sleep(LCD_INFO_DELAY)
    def admin_alert_lockdown(self):
        # Enter a full lockdown that only the admin fingerprint can clear
        self.permanent_lockdown = True
        self.add_attempt_log("SECURITY", "Intrusion response: hard lockdown")
        self._log_event(EVENT_LOCKOUT, "event=intrusion_detected;response=lockdown", REASON_ADMIN_ALERT, "permanent=1")
        self.display.show("Admin Alerted", "Finger Req")
        self.status_led.high_risk()
        sleep(LCD_WARNING_DELAY)
        while self.permanent_lockdown:
            telemetry_tick()
            self.display.show("Admin Alerted", "Finger Req")
            matched, fp_score, match_id = self.fingerprint.identify(self.display)
            if matched and match_id == ADMIN_FINGERPRINT_ID:
                self.add_attempt_log("EVENT", "Lockdown lifted - admin biometric score={}".format(fp_score))
                self._log_event(EVENT_ADMIN_ACTION, "event=lockdown_cleared;method=fingerprint_override", REASON_ADMIN_ALERT, "fp_score={};match_id={}".format(fp_score, match_id), fp=fp_score, access_result=1, fa=0)
                self.failed_attempts = 0
                self.consecutive_failed_sessions = 0
                self.fp_session_failures = 0
                self.reset_escalation_state()
                self.display.locked()
                self.status_led.locked()
                sleep(LCD_INFO_DELAY)
                return
            self.display.show("Admin Alerted", "Finger Req")
            self.status_led.high_risk()
            sleep(LCD_WARNING_DELAY)
    def do_lockout(self):
        # Timed lockout sequence:
        # 1st lockout = 10 seconds
        # 2nd lockout = 20 seconds
        # 3rd lockout = 30 seconds
        seconds = self.current_lockout_seconds()
        self.total_lockout_count += 1
        self.update_risk(lockout_started=True)
        self.add_attempt_log("EVENT", "Lockout started {}s".format(seconds))
        self._log_event(EVENT_LOCKOUT, "event=lockout_initiated", REASON_LOCKOUT, "duration={}s".format(seconds))
        # Count down in 1-second intervals with telemetry processing
        for remaining in range(seconds, 0, -1):
            self.display.lockout(remaining)
            telemetry_tick()
            sleep(1)
        self.display.locked()
        self.status_led.locked()
        self.add_attempt_log("EVENT", "Lockout ended")
        sleep(LCD_INFO_DELAY)
        if self.lockout_stage < 2:
            self.lockout_stage += 1
        else:
            self.enter_final_warning_mode()
    def unlock_cycle(self, fp_score):
        """
        Execute complete unlock/access/relock cycle.
        
        Sequence order is critical:
        1. Log event before physical unlock (fail-secure if exception during unlock)
        2. Seal AES record for forensics before granting access
        3. Reset escalation to clear attack state after legitimate access
        4. Physical unlock only after all security state updated
        
        Args:
            fp_score (int): Fingerprint confidence score for audit trail
        """
        self.add_attempt_log("EVENT", "Access authorised")
        self._log_event(EVENT_SYSTEM_UNLOCKED, "event=access_granted;state=unlocked", extra="fp_score={}".format(fp_score), fp=fp_score, lock=0, access_result=1, fa=0)
        self._seal_local_record("event=access_granted;fp_score={};time={}".format(fp_score, unix_time_now()))
        # Successful authorised access clears staged escalation
        self.reset_escalation_state()
        # Unlock phase
        self.display.show("Access Granted", "Session Active")
        self.status_led.access_granted()
        sleep(LCD_INFO_DELAY)
        self.servo_lock.unlock()
        # Active access window countdown
        for remaining in range(AUTO_RELOCK_SECONDS, 0, -1):
            self.display.show("Access Window", "{}s remaining".format(remaining))
            telemetry_tick()
            sleep(1)
        # Securing phase - update the display before the lock moves
        self.display.show("System Securing", "Locking...")
        self.status_led.locked()
        self.servo_lock.lock()
        # Final secured state
        self.display.show("Safe Secured", "Await Input")
        self.add_attempt_log("EVENT", "Safe re-secured")
        self._log_event(EVENT_SYSTEM_RELOCKED, "event=system_secured;state=locked", extra="auto_relock=1", access_result=1, fa=0)
        sleep(LCD_INFO_DELAY)
    def admin_enrol(self):
        # Enrol a non-admin fingerprint template from the admin menu
        template_id = self.get_template_id()
        if template_id < MIN_USER_FINGERPRINT_ID or template_id > MAX_USER_FINGERPRINT_ID:
            self.display.invalid_id()
            self.add_attempt_log("EVENT", "Invalid enrol ID {}".format(template_id))
            sleep(LCD_ERROR_DELAY)
            self.display.locked()
            self.status_led.locked()
            sleep(LCD_INFO_DELAY)
            return
        self.add_attempt_log("EVENT", "Admin chose enrol ID {}".format(template_id))
        ok = self.fingerprint.enrol(self.display, template_id)
        if ok:
            self.add_attempt_log("EVENT", "Enrol complete ID {}".format(template_id))
            self._log_event(EVENT_ADMIN_ACTION, "event=administrative_action;method=enrolment", REASON_ENROL, "id={}".format(template_id), access_result=1, fa=0)
            self._seal_local_record("event=admin_enrol;id={};time={}".format(template_id, unix_time_now()))
            self.reset_escalation_state()
        else:
            self.add_attempt_log("EVENT", "Enrol failed ID {}".format(template_id))
        self.display.locked()
        self.status_led.locked()
        sleep(LCD_INFO_DELAY)
    def admin_clear(self):
        # Block deletion of the protected admin template
        template_id = self.get_template_id()
        if template_id == ADMIN_FINGERPRINT_ID:
            self.display.cannot_clear_admin()
            self.add_attempt_log("EVENT", "Admin slot template protected")
            sleep(LCD_ADMIN_PROTECT_DELAY)
            self.display.locked()
            self.status_led.locked()
            sleep(LCD_WARNING_DELAY)
            return
        if template_id < MIN_USER_FINGERPRINT_ID or template_id > MAX_USER_FINGERPRINT_ID:
            self.display.invalid_id()
            self.add_attempt_log("EVENT", "Invalid clear ID {}".format(template_id))
            sleep(LCD_ERROR_DELAY)
            self.display.locked()
            self.status_led.locked()
            sleep(LCD_INFO_DELAY)
            return
        self.add_attempt_log("EVENT", "Admin chose clear ID {}".format(template_id))
        ok = self.fingerprint.clear_one(template_id)
        if ok:
            self.display.clear_done(template_id)
            self.add_attempt_log("EVENT", "Template cleared ID {}".format(template_id))
            self._log_event(EVENT_ADMIN_ACTION, "event=administrative_action;method=template_clear", REASON_CLEAR, "id={}".format(template_id), access_result=1, fa=0)
            self._seal_local_record("event=admin_clear;id={};time={}".format(template_id, unix_time_now()))
            self.reset_escalation_state()
            sleep(LCD_INFO_DELAY)
        else:
            self.display.clear_failed()
            self.add_attempt_log("EVENT", "Clear failed ID {}".format(template_id))
            sleep(LCD_ERROR_DELAY)
        self.display.locked()
        self.status_led.locked()
        sleep(LCD_INFO_DELAY)
    def admin_action(self, fp_score, match_id):
        # Admin access still passes through the verification-code stage before the menu is shown
        self.add_attempt_log("EVENT", "Admin verified id={} score={}".format(match_id, fp_score))
        self._log_event(EVENT_FINGERPRINT_VERIFIED, "event=access_attempt;method=fingerprint;outcome=verified", extra="fp_score={};match_id={}".format(fp_score, match_id), fp=fp_score, access_result=1, fa=0)
        self.status_led.admin()
        if not self.verification_code_step():
            self.handle_verification_code_failure()
            return
        self.train_risk_model(0)
        self.update_risk()
        self.reset_escalation_state()
        choice = self.get_admin_choice()
        if choice == "1":
            self.add_attempt_log("EVENT", "Admin chose unlock")
            self.unlock_cycle(fp_score)
            self.add_mllog_summary("pass", REASON_NONE, fp_score)
        elif choice == "2":
            self.admin_enrol()
            self.add_mllog_summary("pass", REASON_ENROL, fp_score)
        elif choice == "3":
            self.admin_clear()
            self.add_mllog_summary("pass", REASON_CLEAR, fp_score)
    # Deception-based anti-impersonation:
    # Honeypot PIN detects unauthorised access attempts and triggers controlled response.
    def _handle_honeypot(self):
        # Trigger a full lockout without revealing that a trap condition was hit
        self.add_attempt_log("SECURITY", "Honeypot PIN triggered - possible intrusion")
        self.add_attempt_log("STEALTH", "Deception response active")
        self._log_event(EVENT_FAILED_ATTEMPT, "event=deception_triggered;response=honeypot_lockout", REASON_WRONG_PIN, "honeypot=1")
        self.status_led.high_risk()
        for remaining in range(MAX_LOCKOUT_TIME_SECONDS, 0, -1):
            self.display.lockout(remaining)
            telemetry_tick()
            sleep(1)
        self.failed_attempts = 0
        self.display.locked()
        self.status_led.locked()
        sleep(LCD_INFO_DELAY)
    def handle_failure(self, reason):
        # All failed stages contribute to both logging and risk escalation
        self.failed_attempts += 1
        self.total_failed_attempts += 1
        if reason == REASON_WRONG_PIN:
            self.add_attempt_log("EVENT", "PIN failed")
        elif reason == REASON_FINGERPRINT_FAILED:
            self.add_attempt_log("EVENT", "Fingerprint failed")
        elif reason == REASON_VERIFICATION_CODE_FAILED:
            self.add_attempt_log("EVENT", "Verification code failed")
        self.update_risk(reason=reason)
        self._log_event(EVENT_FAILED_ATTEMPT, "event=access_attempt;outcome=denied", reason, "count={}".format(self.failed_attempts))
        self.display.denied()
        self.status_led.access_denied()
        sleep(LCD_ERROR_DELAY)
        self.show_risk_feedback_if_needed()
        self.train_risk_model(1)
        self.update_risk()
        if self.permanent_lockdown:
            return
        if self.final_warning_mode:
            self.high_risk_attempts_left -= 1
            self.add_attempt_log("SECURITY", "Final attempts left={}".format(self.high_risk_attempts_left))
            if self.high_risk_attempts_left <= 0:
                self.admin_alert_lockdown()
                return
            self.display.show("HIGH RISK", "{} Attempts Left".format(self.high_risk_attempts_left))
            self.status_led.high_risk()
            sleep(LCD_WARNING_DELAY)
            self.display.locked()
            self.status_led.locked()
            sleep(LCD_INFO_DELAY)
            return
        if self.failed_attempts >= MAX_FAILED_ATTEMPTS:
            self.do_lockout()
            self.failed_attempts = 0
        else:
            self.display.locked()
            self.status_led.locked()
            sleep(LCD_INFO_DELAY)
    def handle_verification_code_failure(self):
        # Treat final 2FA failure as a full failed session for behavioural tracking
        self.consecutive_failed_sessions += 1
        self.handle_failure(REASON_VERIFICATION_CODE_FAILED)
        self.add_mllog_summary("fail", REASON_VERIFICATION_CODE_FAILED, 0)
    def startup(self):
        # Lock the system first, then check the fingerprint sensor before entering service
        self.display.boot()
        self.status_led.boot()
        sleep(LCD_BOOT_DELAY)
        self.servo_lock.lock()
        self.display.locked()
        self.status_led.locked()
        sleep(LCD_INFO_DELAY)
        if not self.fingerprint.sensor_ready():
            self.display.sensor_error()
            self.status_led.error()
            sleep(LCD_ERROR_DELAY)
            self.display.locked()
            self.status_led.locked()
            sleep(LCD_INFO_DELAY)
        self._log_event(EVENT_SYSTEM_ARMED, "event=system_armed", extra="startup=1", fa=0)
    # The system enforces a strict sequential authentication pipeline:
    # PIN -> Fingerprint -> Verification Code (2FA)
    #
    # Each stage must succeed before progressing, reducing the risk
    # of single-point compromise.
    def run(self):
        # Main loop processes one full authentication session at a time
        self.startup()
        while True:
            telemetry_tick()
            if self.permanent_lockdown:
                self.admin_alert_lockdown()
                continue
            self.start_new_attempt()
            self.add_attempt_log("EVENT", "Attempt started")
            entered_pin = self.get_pin()
            # Hash the PIN immediately so plaintext input is not kept longer than needed
            entered_hash = hash_pin(entered_pin)
            del entered_pin
            # Honeypot check runs before the real PIN comparison
            if constant_time_compare(entered_hash, HONEYPOT_PIN_HASH):
                self._handle_honeypot()
                self.print_attempt_log()
                continue
            # Main PIN validation
            if not constant_time_compare(entered_hash, MASTER_PIN_HASH):
                self.consecutive_failed_sessions += 1
                self.handle_failure(REASON_WRONG_PIN)
                self.add_mllog_summary("fail", REASON_WRONG_PIN, 0)
                self.print_attempt_log()
                continue
            # PIN accepted - proceed to fingerprint stage
            self.add_attempt_log("EVENT", "PIN accepted")
            self._log_event(EVENT_PIN_ACCEPTED, "event=access_attempt;method=pin;outcome=verified", extra="pin_verified=1", access_result=1)
            self.display.pin_ok()
            self.status_led.pin_ok()
            sleep(LCD_INFO_DELAY)
            matched, fp_score, match_id = self.fingerprint.identify(self.display)
            # Raise the minimum fingerprint score slightly when risk has already increased
            required_fp_score = FP_MIN_SCORE
            # High risk requires 20% higher confidence to reduce false accepts under attack
            if self.current_risk_level == RISK_HIGH or self.final_warning_mode or self.permanent_lockdown:
                required_fp_score = FP_MIN_SCORE + 10
            # Suspicious risk requires 10% higher confidence
            elif self.current_risk_level == RISK_SUSPICIOUS:
                required_fp_score = FP_MIN_SCORE + 5
            # Anti-spoofing control:
            # Reject low-confidence biometric matches to reduce spoofed fingerprint acceptance
            # and mitigate identity impersonation attempts.
            if matched and fp_score < required_fp_score:
                self.add_attempt_log("SECURITY", "Match rejected - score {} below threshold {}".format(fp_score, required_fp_score))
                matched = False
            # Anti-impersonation control:
            # Track repeated biometric failures to detect spoofing attempts or unauthorised identity use.
            if not matched:
                self.fp_session_failures += 1
                self.consecutive_failed_sessions += 1
                self.add_attempt_log("SECURITY", "FP session failures: {}/{}".format(self.fp_session_failures, FP_MAX_ATTEMPTS))
                # Anti-spoofing escalation:
                # Force lockout when repeated biometric attempts suggest brute-force or spoofing behaviour.
                if self.fp_session_failures >= FP_MAX_ATTEMPTS and not self.final_warning_mode:
                    self.add_attempt_log("SECURITY", "FP session limit reached - forcing lockout")
                    self.failed_attempts = MAX_FAILED_ATTEMPTS
                self.handle_failure(REASON_FINGERPRINT_FAILED)
                self.add_mllog_summary("fail", REASON_FINGERPRINT_FAILED, 0)
                self.print_attempt_log()
                continue
            # Clear session-based counters after a successful biometric match
            self.fp_session_failures = 0
            self.failed_attempts = 0
            self.consecutive_failed_sessions = 0
            # Admin path
            if match_id == ADMIN_FINGERPRINT_ID:
                self.admin_action(fp_score, match_id)
            # User path
            else:
                self.add_attempt_log("EVENT", "Fingerprint verified id={} score={}".format(match_id, fp_score))
                self._log_event(EVENT_FINGERPRINT_VERIFIED, "event=access_attempt;method=fingerprint;outcome=verified", extra="fp_score={};match_id={}".format(fp_score, match_id), fp=fp_score, access_result=1, fa=0)
                if self.verification_code_step():
                    self.train_risk_model(0)
                    self.update_risk()
                    self.unlock_cycle(fp_score)
                    self.add_mllog_summary("pass", REASON_NONE, fp_score)
                else:
                    self.handle_verification_code_failure()
            self.print_attempt_log()
# -------------------- Fail Secure --------------------
# In the event of a runtime error, the system defaults to a locked state,
# signals an error condition, and avoids unintended access.
def fail_secure(display, status_led, servo_lock, error_message):
    try:
        servo_lock.lock()
    except Exception:
        pass
    try:
        display.system_error()
    except Exception:
        pass
    try:
        status_led.error()
    except Exception:
        pass
    print("SYSTEM ERROR:", error_message)
# -------------------- Hardware Initialisation --------------------
def init_devices():
    # Build and return the hardware-facing objects needed by the runtime
    import gc
    gc.collect()
    from i2c_lcd import I2cLcd
    from pcf8574 import PCF8574
    print("Initializing hardware...")
    i2c = I2C(I2C_BUS_ID, scl=Pin(I2C_SCL_PIN), sda=Pin(I2C_SDA_PIN), freq=I2C_FREQ)
    sleep(0.2)
    devices = i2c.scan()
    print("I2C devices:", devices)
    if LCD_I2C_ADDR not in devices:
        raise OSError("LCD not found at address {}".format(hex(LCD_I2C_ADDR)))
    if PCF8574_ADDR not in devices:
        raise OSError("PCF8574 not found at address {}".format(hex(PCF8574_ADDR)))
    lcd = I2cLcd(i2c, LCD_I2C_ADDR, LCD_ROWS, LCD_COLS)
    pcf = PCF8574(i2c, PCF8574_ADDR)
    pcf.check()
    display = DisplayManager(lcd)
    status_led = StatusLED(8)
    keypad = Keypad(pcf)
    fingerprint = FingerprintSensor(FP_UART_ID, FP_BAUDRATE, FP_TX_PIN, FP_RX_PIN, FP_TOUCH_PIN, telemetry)
    servo_lock = ServoLock(SERVO_PIN, SERVO_FREQ, LOCKED_ANGLE, UNLOCKED_ANGLE, SERVO_STEP_DELAY, SERVO_ANGLE_STEP)
    system = SecurityControlSystem(display, status_led, keypad, fingerprint, servo_lock)
    return {"system": system, "display": display, "status_led": status_led, "servo_lock": servo_lock}
# -------------------- Program Entry --------------------
def run_app(telemetry_obj):
    """
    Main application entry point.
    
    Binds telemetry object from boot module and initializes hardware
    before starting the main authentication loop.
    
    Args:
        telemetry_obj: ThingSpeakTelemetry instance from boot module
    """
    global telemetry
    telemetry = telemetry_obj
    print("Starting system...")
    sleep(1)
    devices = init_devices()
    system = devices["system"]
    display = devices["display"]
    status_led = devices["status_led"]
    servo_lock = devices["servo_lock"]
    print("System ready")
    try:
        system.run()
    except Exception as e:
        fail_secure(display, status_led, servo_lock, e)
