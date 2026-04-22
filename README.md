# Secure IoT Safe Control System

This project implements a secure IoT-based safe control system using the ESP32-C3 microcontroller.

## Features
- Multi-layer authentication:
  - PIN (keypad input)
  - Fingerprint recognition
  - Time-based One-Time Password (TOTP)
- Behaviour-driven risk scoring (embedded ML model)
- Adaptive lockout and intrusion detection
- Tamper-evident logging using SHA-256 hash chaining
- Encrypted telemetry via ThingSpeak
- Servo-controlled locking mechanism
- LCD user interface (I2C)
- Real-time status LED feedback

## Security Design
- Salted SHA-256 PIN hashing
- Constant-time comparison (timing attack resistance)
- Honeypot PIN (deception-based security)
- Fingerprint brute-force protection
- AES-encrypted local records
- XOR stream cipher for telemetry protection

## Hardware
- ESP32-C3 DevKitC-02
- UART Fingerprint sensor (ZFM/SEN0188)
- 3x4 Matrix keypad (via PCF8574 I2C expander)
- 16x2 LCD (I2C interface)
- SG90 Servo motor (lock mechanism)
- Onboard NeoPixel LED

## Project Structure
secure-iot-safe/
├── app/ # Main application logic
├── drivers/ # Hardware drivers
├── config/ # Local configuration (excluded from repo)
└── README.md
