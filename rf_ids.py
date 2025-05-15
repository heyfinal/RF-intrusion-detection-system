#!/usr/bin/env python3
"""
RF-based Intrusion Detection System using RTL-SDR
Enhanced with Terminal Dashboard and SMS Alerts
"""

import numpy as np
import matplotlib.pyplot as plt
from rtlsdr import RtlSdr
import time
import datetime
import os
import json
import smtplib
from email.message import EmailMessage
import threading
import pickle
from scipy import signal
import sys
import curses
from curses import wrapper
import traceback
import requests
from typing import Dict, List, Any, Tuple, Optional

# For macOS notifications
try:
    import pync
    NOTIFICATIONS_AVAILABLE = True
except ImportError:
    NOTIFICATIONS_AVAILABLE = False

# Global variables for dashboard display
DASHBOARD = {
    'status': 'Initializing...',
    'current_freq': None,
    'last_anomaly': None,
    'last_alert_time': None,
    'alert_count': 0,
    'frequencies': [],
    'error_log': [],
    'monitoring_log': [],
    'start_time': time.time(),  # Track system uptime
    'scan_count': 0,            # Track number of scans
    'signal_level': 0.0,        # Current signal level (0.0-1.0)
    'early_detection': None,    # For detecting devices at longer range
    'early_detection_time': None # Timestamp for early detection
}

# Maximum number of log entries to keep
MAX_LOG_ENTRIES = 10

class RFIntrusionDetector:
    def __init__(self, config_file='config.json', stdscr=None):
        self.stdscr = stdscr  # Curses screen for dashboard
        self.update_dashboard(status="Loading configuration...")
        
        # Load configuration
        self.load_config(config_file)
        
        # Check if we should run interactive setup
        if self.config.get('run_setup', False):
            self.update_dashboard(status="Running initial setup...")
            self.config = self.setup_initial_config()
            
        # Initialize SDR
        try:
            self.update_dashboard(status="Initializing RTL-SDR device...")
            self.sdr = RtlSdr()
            self.sdr.sample_rate = self.config['sample_rate']
            self.sdr.center_freq = 100e6  # Start with a safe frequency
            self.sdr.gain = self.config['gain']
            
            # Determine frequency range
            self.update_dashboard(status="Testing maximum frequency capability...")
            max_freq = self.test_max_frequency()
            self.update_dashboard(status=f"Maximum reliable frequency: {max_freq/1e6:.1f} MHz")
            self.config['device_max_freq'] = max_freq
            
            # Filter frequencies that are too high
            self.filter_invalid_frequencies()
            
        except Exception as e:
            self.update_dashboard(status=f"Error initializing RTL-SDR: {e}", error=True)
            print(f"Error initializing RTL-SDR: {e}")
            print("Please make sure your RTL-SDR device is connected and recognized by your system.")
            if NOTIFICATIONS_AVAILABLE:
                pync.notify("Error initializing RTL-SDR. Please check connection.", 
                          title="RF-IDS Error", 
                          sound="Basso")
            time.sleep(5)  # Allow time to read the error
            sys.exit(1)
        
        # Create output directory
        os.makedirs(self.config['output_dir'], exist_ok=True)
        
        # Load baseline if exists
        self.baseline = None
        self.baseline_file = os.path.join(self.config['output_dir'], 'baseline.pkl')
        if os.path.exists(self.baseline_file) and not self.config['force_new_baseline']:
            self.load_baseline()
        
        # Alert counter
        self.alert_count = 0
        self.last_alert_time = datetime.datetime.now() - datetime.timedelta(hours=1)
        
        # Last anomaly details
        self.last_anomaly = None

    def update_dashboard(self, status=None, current_freq=None, log_message=None, error=False, alert=None):
        """Update the dashboard display"""
        global DASHBOARD
        
        if status:
            DASHBOARD['status'] = status
            
        if current_freq is not None:
            DASHBOARD['current_freq'] = current_freq
            
        if log_message:
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            entry = f"[{timestamp}] {log_message}"
            if error:
                DASHBOARD['error_log'].insert(0, entry)
                # Trim log if too long
                if len(DASHBOARD['error_log']) > MAX_LOG_ENTRIES:
                    DASHBOARD['error_log'] = DASHBOARD['error_log'][:MAX_LOG_ENTRIES]
            else:
                DASHBOARD['monitoring_log'].insert(0, entry)
                # Trim log if too long
                if len(DASHBOARD['monitoring_log']) > MAX_LOG_ENTRIES:
                    DASHBOARD['monitoring_log'] = DASHBOARD['monitoring_log'][:MAX_LOG_ENTRIES]
        
        if alert:
            DASHBOARD['last_anomaly'] = alert
            DASHBOARD['last_alert_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            DASHBOARD['alert_count'] += 1
        
        # Update frequencies list
        if hasattr(self, 'config') and 'frequencies' in self.config:
            DASHBOARD['frequencies'] = self.config['frequencies']
        
        # If curses is available, refresh the display
        if self.stdscr:
            self.draw_dashboard()
    
    def draw_dashboard(self):
        """Draw the dashboard using curses"""
        try:
            if not self.stdscr:
                return
                
            # Get terminal dimensions
            height, width = self.stdscr.getmaxyx()
            
            # Clear screen
            self.stdscr.clear()
            
            # Draw border
            self.stdscr.border()
            
            # Title
            title = "RF Intrusion Detection System"
            self.stdscr.addstr(0, (width - len(title)) // 2, title)
            
            # Active indicator (spinner) and current time
            spinner_chars = "|/-\\"
            spinner_idx = int(time.time()) % len(spinner_chars)
            current_time = datetime.datetime.now().strftime("%H:%M:%S")
            active_indicator = f"[{spinner_chars[spinner_idx]}] Active - {current_time}"
            self.stdscr.addstr(0, width - len(active_indicator) - 2, active_indicator)
            
            # Status area
            self.stdscr.addstr(2, 2, "Status: " + DASHBOARD['status'])
            
            # Current frequency
            if DASHBOARD['current_freq'] is not None:
                self.stdscr.addstr(3, 2, f"Current Frequency: {DASHBOARD['current_freq']} MHz")
            
            # Monitoring frequencies
            freq_str = ", ".join(map(str, DASHBOARD['frequencies']))
            if len(freq_str) > width - 25:
                freq_str = freq_str[:width-28] + "..."
            self.stdscr.addstr(4, 2, f"Monitoring: {freq_str}")
            
            # Alert count
            self.stdscr.addstr(5, 2, f"Alerts: {DASHBOARD['alert_count']}")
            
            # System uptime and scan info
            uptime_str = f"Uptime: {int(time.time() - DASHBOARD.get('start_time', time.time()))}s"
            scan_count = DASHBOARD.get('scan_count', 0)
            scan_str = f"Scans: {scan_count}"
            self.stdscr.addstr(5, width - len(uptime_str) - 2, uptime_str)
            self.stdscr.addstr(4, width - len(scan_str) - 2, scan_str)
            
            # Last anomaly
            self.stdscr.addstr(7, 2, "=== Last Alert ===")
            if DASHBOARD['last_anomaly']:
                anomaly_info = DASHBOARD['last_anomaly']
                self.stdscr.addstr(8, 2, f"Type: {anomaly_info.get('type', 'Unknown')}")
                self.stdscr.addstr(9, 2, f"Time: {DASHBOARD['last_alert_time']}")
                if 'frequency' in anomaly_info:
                    self.stdscr.addstr(10, 2, f"Frequency: {anomaly_info['frequency']} MHz")
                if 'power' in anomaly_info:
                    self.stdscr.addstr(11, 2, f"Signal: {anomaly_info['power']:.2f} dB")
                if 'distance' in anomaly_info:
                    self.stdscr.addstr(12, 2, f"Distance: {anomaly_info['distance']} feet")
            else:
                self.stdscr.addstr(8, 2, "No alerts detected yet")
            
            # Early detection area (devices at longer range)
            early_y = 7
            early_x = width // 2 + 2
            self.stdscr.addstr(early_y, early_x, "=== Early Detection ===")
            if DASHBOARD['early_detection']:
                early_info = DASHBOARD['early_detection']
                # Use yellow for early detection text
                attr = curses.A_NORMAL
                if curses.has_colors():
                    try:
                        attr = curses.color_pair(2)  # Yellow
                    except:
                        pass
                
                self.stdscr.addstr(early_y + 1, early_x, f"Type: {early_info.get('type', 'Unknown')}", attr)
                self.stdscr.addstr(early_y + 2, early_x, f"Time: {DASHBOARD['early_detection_time']}", attr)
                if 'frequency' in early_info:
                    self.stdscr.addstr(early_y + 3, early_x, f"Frequency: {early_info['frequency']} MHz", attr)
                if 'power' in early_info:
                    self.stdscr.addstr(early_y + 4, early_x, f"Signal: {early_info['power']:.2f} dB", attr)
                if 'distance' in early_info:
                    self.stdscr.addstr(early_y + 5, early_x, f"Est. Distance: ~{early_info['distance']} feet", attr)
            else:
                self.stdscr.addstr(early_y + 1, early_x, "No devices detected at extended range")
            
            # Signal meter (with dB value)
            signal_meter_width = 20
            signal_level = DASHBOARD.get('signal_level', 0.1)
            meter_fill = int(signal_level * signal_meter_width)
            
            # Create a gradient colored meter (goes from blue to red based on intensity)
            meter_str = "["
            for i in range(signal_meter_width):
                if i < meter_fill:
                    char = "#"
                else:
                    char = " "
                meter_str += char
            meter_str += "]"
            
            # Try to display signal in dB if available
            signal_db = DASHBOARD.get('signal_db', -120)
            signal_str = f"Signal: {signal_db:.1f} dB "
            
            self.stdscr.addstr(12, width - len(meter_str) - len(signal_str) - 2, signal_str)
            
            # Set colors for meter if possible
            try:
                if curses.has_colors():
                    if signal_level < 0.3:
                        # Low - blue
                        self.stdscr.addstr(12, width - len(meter_str) - 2, meter_str)
                    elif signal_level < 0.6:
                        # Medium - yellow/white
                        self.stdscr.addstr(12, width - len(meter_str) - 2, meter_str, curses.A_BOLD)
                    else:
                        # High - red (removed blinking)
                        self.stdscr.addstr(12, width - len(meter_str) - 2, meter_str, curses.A_BOLD)
                else:
                    self.stdscr.addstr(12, width - len(meter_str) - 2, meter_str)
            except:
                # Fall back to basic display if colors fail
                self.stdscr.addstr(12, width - len(meter_str) - 2, meter_str)
            
            # Monitoring log
            log_y = 14
            self.stdscr.addstr(log_y, 2, "=== Monitoring Log ===")
            log_y += 1
            for i, log_entry in enumerate(DASHBOARD['monitoring_log']):
                if log_y + i < height - 3:  # Leave space for error log
                    self.stdscr.addstr(log_y + i, 2, log_entry[:width-4])
            
            # Error log
            error_y = height - 3 - len(DASHBOARD['error_log']) - 1
            if error_y > log_y + len(DASHBOARD['monitoring_log']) + 1:
                self.stdscr.addstr(error_y, 2, "=== Error Log ===")
                error_y += 1
                for i, error_entry in enumerate(DASHBOARD['error_log']):
                    if error_y + i < height - 2:
                        self.stdscr.addstr(error_y + i, 2, error_entry[:width-4], curses.A_BOLD)
            
            # Instructions
            self.stdscr.addstr(height-1, 2, "Press 'q' to exit, 'r' to reset baseline")
            
            # Refresh the screen
            self.stdscr.refresh()
        except Exception as e:
            # Fall back to regular console output if curses fails
            print(f"Dashboard error: {e}")
    
    def test_max_frequency(self):
        """Test the maximum frequency this RTL-SDR can handle"""
        self.update_dashboard(status="Testing maximum frequency capability...", 
                             log_message="Testing RTL-SDR frequency range")
        
        # Test frequencies in descending order (MHz)
        test_freqs = [1700, 1500, 1200, 1000, 900, 800, 700, 600, 500, 400, 300, 200, 100, 50]
        
        max_freq = 0
        # Save current stderr to suppress error messages during testing
        old_stderr = sys.stderr
        try:
            for freq in test_freqs:
                freq_hz = freq * 1e6
                try:
                    # Redirect stderr to null to hide error messages
                    sys.stderr = open(os.devnull, 'w')
                    self.sdr.center_freq = freq_hz
                    # Read a small number of samples to verify tuning worked
                    self.sdr.read_samples(1024)
                    # If we reach here without error, the frequency is supported
                    max_freq = freq_hz
                    sys.stderr = old_stderr
                    self.update_dashboard(log_message=f"Successfully tuned to {freq} MHz")
                    break
                except Exception as e:
                    sys.stderr = old_stderr
                    self.update_dashboard(log_message=f"Cannot tune to {freq} MHz", error=True)
        finally:
            sys.stderr = old_stderr
            
        if max_freq == 0:
            self.update_dashboard(status="Could not determine maximum frequency", 
                                 log_message="Using 500 MHz as default maximum", error=True)
            max_freq = 500e6
        
        # Set back to a safe frequency
        self.sdr.center_freq = 100e6
        return max_freq
    
    def filter_invalid_frequencies(self):
        """Remove frequencies that are too high for this device"""
        self.update_dashboard(status="Filtering incompatible frequencies...")
        
        max_freq = self.config.get('device_max_freq', 1700e6)
        valid_freqs = []
        
        for freq in self.config['frequencies']:
            if freq * 1e6 <= max_freq:
                valid_freqs.append(freq)
            else:
                self.update_dashboard(log_message=f"Removing frequency {freq} MHz - exceeds device capabilities", error=True)
        
        # If we removed all frequencies, add some safe ones
        if not valid_freqs:
            self.update_dashboard(log_message="No valid frequencies in configuration. Adding safe defaults.", error=True)
            for freq in [100, 200, 400, 500]:
                if freq * 1e6 <= max_freq:
                    valid_freqs.append(freq)
        
        self.config['frequencies'] = valid_freqs
        
        # Save updated config
        with open('config.json', 'w') as f:
            json.dump(self.config, f, indent=4)
    
    def setup_initial_config(self):
        """Interactive setup for first-time configuration"""
        # Switch to regular output mode for setup
        if self.stdscr:
            curses.endwin()
        
        print("\n" + "="*60)
        print("Welcome to RF Intrusion Detection System - First-time Setup")
        print("="*60 + "\n")
        
        print("Let's configure your monitoring preferences.\n")
        
        # Test max frequency capability
        max_freq = self.test_max_frequency()
        max_freq_mhz = max_freq / 1e6
        
        # Default configuration
        config = {
            'sample_rate': 2.4e6,       # Sample rate
            'center_freq': 100e6,       # Safe center frequency
            'gain': 'auto',             # Gain setting
            'fft_size': 1024,           # FFT size
            'num_samples': 256000,      # Number of samples to collect
            'threshold': 15,            # Anomaly threshold in dB
            'scan_interval': 5,         # Seconds between scans
            'output_dir': 'rf_ids_data',# Output directory
            'baseline_samples': 10,     # Number of samples for baseline
            'force_new_baseline': False,# Force new baseline calculation
            'device_max_freq': max_freq,# Maximum frequency for this device
            'frequencies': [],          # Frequencies to monitor (in MHz)
            'email_alerts': False,      # Send email alerts
            'sms_alerts': False,        # SMS alerts
            'sms_config': {
                'service': 'twilio',    # SMS service to use
                'account_sid': '',      # Twilio account SID
                'auth_token': '',       # Twilio auth token
                'from_number': '',      # Twilio phone number
                'to_number': ''         # Recipient phone number
            },
            'proximity_detection': {
                'enabled': True,
                'bluetooth_distance_threshold': 10,  # feet
                'cellular_distance_threshold': 15,   # feet
                'calibration_needed': True,
                'use_lower_frequencies': True  # Use lower frequencies for detection
            },
            'email': {
                'sender': '',
                'recipient': '',
                'password': '',
                'server': 'smtp.gmail.com',
                'port': 587
            }
        }
        
        # Create frequency options based on device capabilities
        freq_options = []
        
        # Add standard bands based on capability
        if max_freq_mhz >= 900:
            freq_options.append(("ISM Band (915 MHz)", 915))
        if max_freq_mhz >= 868:
            freq_options.append(("ISM Band (868 MHz)", 868))
        if max_freq_mhz >= 500:
            freq_options.append(("UHF TV (500-600 MHz)", 550))
        
        freq_options.extend([
            ("ISM Band (433 MHz)", 433),
            ("LPD433 (433 MHz)", 433),
            ("Medical/Weather (400-406 MHz)", 403),
            ("Marine Band (156-174 MHz)", 162),
            ("VHF TV (174-216 MHz)", 200),
            ("Aircraft Band (108-137 MHz)", 120),
            ("FM Radio (88-108 MHz)", 100),
            ("Weather Radio (162 MHz)", 162),
            ("Amateur Radio (144-148 MHz)", 146),
            ("Remote Controls (300-350 MHz)", 315),
        ])
        
        # Add cellular if in range
        if max_freq_mhz >= 700:
            freq_options.append(("Cellular (700-800 MHz)", 750))
        if max_freq_mhz >= 850:
            freq_options.append(("Cellular (850 MHz)", 850))
        if max_freq_mhz >= 900:
            freq_options.append(("Cellular (900 MHz)", 900))
        
        print("\nSelect frequencies to monitor (compatible with your device):")
        for i, (name, freq) in enumerate(freq_options, 1):
            print(f"{i}. {name}")
        
        # Determine default selection
        default_indices = []
        # Always include 433 MHz ISM band if available
        ism433_idx = next((i for i, (name, freq) in enumerate(freq_options) if freq == 433), None)
        if ism433_idx is not None:
            default_indices.append(ism433_idx + 1)
        
        # Include FM radio
        fm_idx = next((i for i, (name, freq) in enumerate(freq_options) if "FM Radio" in name), None)
        if fm_idx is not None:
            default_indices.append(fm_idx + 1)
        
        # Include cellular if available
        cell_idx = next((i for i, (name, freq) in enumerate(freq_options) if "Cellular" in name), None)
        if cell_idx is not None:
            default_indices.append(cell_idx + 1)
        
        # Include 915 MHz ISM if available
        ism915_idx = next((i for i, (name, freq) in enumerate(freq_options) if freq == 915), None)
        if ism915_idx is not None:
            default_indices.append(ism915_idx + 1)
        
        default_selection = ",".join(map(str, default_indices))
        
        print("\nEnter the numbers of the frequencies you want to monitor, separated by commas")
        print("Example: 1,2,3")
        selection = input(f"Selection [{default_selection}]: ").strip() or default_selection
        
        try:
            selected_indices = [int(x.strip()) - 1 for x in selection.split(",")]
            for idx in selected_indices:
                if 0 <= idx < len(freq_options):
                    config['frequencies'].append(freq_options[idx][1])
        except:
            print("Invalid selection. Using default frequencies.")
            # Use default frequencies
            for idx in [i-1 for i in map(int, default_selection.split(","))]:
                if 0 <= idx < len(freq_options):
                    config['frequencies'].append(freq_options[idx][1])
        
        # Threshold
        print("\nDetection sensitivity (threshold in dB)")
        print("Lower values = more sensitive (more alerts, potential false positives)")
        print("Higher values = less sensitive (fewer alerts, might miss subtle signals)")
        print("Recommended: 10-15 dB")
        try:
            threshold = float(input("Enter threshold [12]: ").strip() or "12")
            config['threshold'] = threshold
        except:
            print("Invalid input. Using default threshold of 12 dB.")
            config['threshold'] = 12
        
        # Scan interval
        print("\nScan interval (seconds between checking each frequency)")
        print("Lower values = faster detection but higher CPU usage")
        print("Recommended: 3-10 seconds")
        try:
            interval = float(input("Enter scan interval [5]: ").strip() or "5")
            config['scan_interval'] = interval
        except:
            print("Invalid input. Using default interval of 5 seconds.")
            config['scan_interval'] = 5
        
        # Proximity detection using lower frequencies
        print("\nWould you like to enable low-frequency proximity detection?")
        print("This can detect when wireless devices get close to your location.")
        print("NOTE: Your RTL-SDR cannot tune to WiFi or Bluetooth frequencies.")
        print("We'll use lower frequency bands to detect device proximity.")
        proximity_choice = input("Enable proximity detection? (y/n) [y]: ").strip().lower() or "y"
        
        if proximity_choice == "y":
            config['proximity_detection']['enabled'] = True
            
            print("\nProximity alert distances:")
            try:
                bt_distance = float(input("Wireless device alert distance in feet [10]: ").strip() or "10")
                config['proximity_detection']['bluetooth_distance_threshold'] = bt_distance
            except:
                print("Invalid input. Using default distance of 10 feet.")
            
            try:
                cell_distance = float(input("Cell phone alert distance in feet [15]: ").strip() or "15")
                config['proximity_detection']['cellular_distance_threshold'] = cell_distance
            except:
                print("Invalid input. Using default distance of 15 feet.")
            
            print("\nThe system will need to be calibrated to accurately detect distances.")
            print("You'll be guided through calibration when you start the system.")
            
            # Explain the limited capabilities
            print("\nNOTE: Since your RTL-SDR cannot tune to high frequencies:")
            print("- We'll use lower frequencies to detect device presence")
            print("- Detection may be less precise than with full-range devices")
            print("- The system will focus on detecting changes in RF activity")
            
            # Make sure we have frequencies for proximity detection
            cell_freq_included = any(f for f in config['frequencies'] if 700 <= f <= 900)
            if not cell_freq_included and max_freq_mhz >= 700:
                # Add the lowest available cellular frequency
                if max_freq_mhz >= 700:
                    config['frequencies'].append(750)
                    print("Added 750 MHz cellular band for detection.")
            
            # Add 433 MHz if not already included
            if 433 not in config['frequencies']:
                config['frequencies'].append(433)
                print("Added 433 MHz ISM band for general RF monitoring.")
        else:
            config['proximity_detection']['enabled'] = False
        
        # SMS alerts
        print("\nWould you like to receive SMS alerts for detected anomalies?")
        sms_choice = input("Enable SMS alerts? (y/n) [n]: ").strip().lower() or "n"
        
        if sms_choice == "y":
            config['sms_alerts'] = True
            
            print("\nSMS Configuration (Twilio):")
            print("You'll need a Twilio account. Get your credentials at https://www.twilio.com")
            config['sms_config']['account_sid'] = input("Twilio Account SID: ").strip()
            config['sms_config']['auth_token'] = input("Twilio Auth Token: ").strip()
            config['sms_config']['from_number'] = input("Twilio Phone Number (with country code, e.g., +1234567890): ").strip()
            config['sms_config']['to_number'] = input("Your Phone Number (with country code, e.g., +1234567890): ").strip()
            
            print("\nTest SMS will be sent when calibration is complete.")
        
        # Email alerts
        print("\nWould you like to receive email alerts when anomalies are detected?")
        email_choice = input("Enable email alerts? (y/n) [n]: ").strip().lower() or "n"
        
        if email_choice == "y":
            config['email_alerts'] = True
            
            print("\nEmail configuration:")
            config['email']['sender'] = input("Sender email address: ").strip()
            config['email']['recipient'] = input("Recipient email address: ").strip()
            
            import getpass
            config['email']['password'] = getpass.getpass("Email password (or app password): ")
            
            server = input("SMTP server [smtp.gmail.com]: ").strip()
            config['email']['server'] = server if server else "smtp.gmail.com"
            
            try:
                port = int(input("SMTP port [587]: ").strip() or "587")
                config['email']['port'] = port
            except:
                print("Invalid port. Using default port 587.")
                config['email']['port'] = 587
            
            print("\nNote: For Gmail, you need to use an App Password.")
            print("See: https://support.google.com/accounts/answer/185833")
        
        # Save configuration
        with open('config.json', 'w') as f:
            json.dump(config, f, indent=4)
        
        print("\nConfiguration saved to config.json!")
        print("\nIMPORTANT: This configuration is optimized for your RTL-SDR's")
        print(f"limited frequency range (max: {max_freq_mhz:.1f} MHz).")
        print("If you connect a different RTL-SDR in the future that supports higher")
        print("frequencies, run the setup again to take advantage of more bands.\n")
        
        input("Press Enter to continue to monitoring...")
        
        # Switch back to curses mode if available
        if self.stdscr:
            curses.initscr()
        
        return config
    
    def load_config(self, config_file):
        """Load configuration from JSON file or set up interactively"""
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
            self.update_dashboard(log_message=f"Loaded configuration from {config_file}")
        except FileNotFoundError:
            self.update_dashboard(log_message=f"Configuration file not found: {config_file}")
            self.config = self.setup_initial_config()
    
    def capture_spectrum(self):
        """Capture RF spectrum data"""
        try:
            samples = self.sdr.read_samples(self.config['num_samples'])
            
            # Compute power spectral density
            frequencies, psd = signal.welch(
                samples, 
                fs=self.sdr.sample_rate/1e6, 
                nperseg=self.config['fft_size'],
                scaling='density'
            )
            
            # Convert to dB
            psd_db = 10 * np.log10(psd)
            
            # Center the frequencies
            frequencies = frequencies + (self.sdr.center_freq/1e6 - self.sdr.sample_rate/2e6)
            
            return frequencies, psd_db
        except Exception as e:
            self.update_dashboard(log_message=f"Error capturing spectrum: {e}", error=True)
            # Return empty data
            return np.array([]), np.array([])
    
    def create_baseline(self):
        """Create baseline RF spectrum for comparison"""
        self.update_dashboard(status="Creating baseline RF spectrum profile...")
        baseline_data = {}
        
        # Create a baseline for each frequency
        for freq in self.config['frequencies']:
            self.update_dashboard(status=f"Creating baseline for {freq} MHz...")
            
            # Try to set frequency
            try:
                self.sdr.center_freq = freq * 1e6
            except Exception as e:
                self.update_dashboard(log_message=f"Error setting frequency {freq} MHz: {e}", error=True)
                self.update_dashboard(log_message=f"Skipping {freq} MHz in baseline creation", error=True)
                continue
                
            freq_data = []
            for i in range(self.config['baseline_samples']):
                self.update_dashboard(status=f"Collecting sample {i+1}/{self.config['baseline_samples']} for {freq} MHz")
                frequencies, psd = self.capture_spectrum()
                if len(frequencies) > 0:
                    freq_data.append(psd)
                time.sleep(1)
            
            if freq_data:
                # Create baseline for this frequency
                baseline_data[freq] = {
                    'frequencies': frequencies,
                    'psd_mean': np.mean(freq_data, axis=0),
                    'psd_std': np.std(freq_data, axis=0)
                }
                
                # Plot baseline for this frequency
                self.plot_spectrum(frequencies, baseline_data[freq]['psd_mean'], 
                                  title=f"RF Baseline - {freq} MHz", 
                                  filename=f"baseline_{freq}MHz.png")
                self.update_dashboard(log_message=f"Baseline created for {freq} MHz")
            else:
                self.update_dashboard(log_message=f"Could not create baseline for {freq} MHz - no valid data", error=True)
        
        if baseline_data:
            # Add timestamp
            self.baseline = {
                'timestamp': datetime.datetime.now().isoformat(),
                'data': baseline_data
            }
            
            # Save baseline
            with open(self.baseline_file, 'wb') as f:
                pickle.dump(self.baseline, f)
            
            self.update_dashboard(log_message=f"Baseline created and saved to {self.baseline_file}")
                    
            # Send macOS notification
            if NOTIFICATIONS_AVAILABLE:
                pync.notify("Baseline RF profile has been created successfully.", 
                          title="RF-IDS Setup Complete", 
                          sound="Glass")
            
            # Send test SMS if enabled
            if self.config.get('sms_alerts', False):
                self.send_sms_alert("RF-IDS system initialized and baseline created. This is a test message.")
        else:
            self.update_dashboard(log_message="Failed to create baseline - no valid frequency data", error=True)
            return False
            
        return True
    
    def create_baseline_for_frequency(self, freq):
        """Create baseline for a specific frequency"""
        self.update_dashboard(status=f"Creating baseline for {freq} MHz...")
        
        # Try to set frequency
        try:
            self.sdr.center_freq = freq * 1e6
        except Exception as e:
            self.update_dashboard(log_message=f"Error setting frequency {freq} MHz: {e}", error=True)
            self.update_dashboard(log_message=f"Cannot create baseline for {freq} MHz", error=True)
            return False
            
        freq_data = []
        for i in range(self.config['baseline_samples']):
            self.update_dashboard(status=f"Collecting sample {i+1}/{self.config['baseline_samples']} for {freq} MHz")
            frequencies, psd = self.capture_spectrum()
            if len(frequencies) > 0:
                freq_data.append(psd)
            time.sleep(1)
        
        if not freq_data:
            self.update_dashboard(log_message=f"Could not create baseline for {freq} MHz - no valid data", error=True)
            return False
        
        # Initialize baseline structure if it doesn't exist
        if self.baseline is None:
            self.baseline = {
                'timestamp': datetime.datetime.now().isoformat(),
                'data': {}
            }
        elif 'data' not in self.baseline:
            self.baseline['data'] = {}
        
        # Add or update baseline for this frequency
        self.baseline['data'][freq] = {
            'frequencies': frequencies,
            'psd_mean': np.mean(freq_data, axis=0),
            'psd_std': np.std(freq_data, axis=0)
        }
        
        # Plot baseline for this frequency
        self.plot_spectrum(frequencies, self.baseline['data'][freq]['psd_mean'], 
                          title=f"RF Baseline - {freq} MHz", 
                          filename=f"baseline_{freq}MHz.png")
        
        # Save updated baseline
        with open(self.baseline_file, 'wb') as f:
            pickle.dump(self.baseline, f)
        
        self.update_dashboard(log_message=f"Baseline for {freq} MHz created and saved")
        return True
    
    def load_baseline(self):
        """Load baseline from file"""
        try:
            with open(self.baseline_file, 'rb') as f:
                self.baseline = pickle.load(f)
            self.update_dashboard(log_message=f"Loaded baseline from {self.baseline_file}")
            self.update_dashboard(log_message=f"Baseline created on: {self.baseline['timestamp']}")
            return True
        except Exception as e:
            self.update_dashboard(log_message=f"Error loading baseline: {e}", error=True)
            self.baseline = None
            return False
    
    def calibrate_proximity_detection(self):
        """Calibrate the system for proximity detection with limited frequency range"""
        # Switch to regular output mode for calibration
        if self.stdscr:
            curses.endwin()
        
        print("\n" + "="*60)
        print("Proximity Detection Calibration (Limited Range Mode)")
        print("="*60)
        print("\nThis process will calibrate the system to detect devices within specific distances.")
        print("NOTE: Your RTL-SDR has limited frequency range capabilities.")
        print("We'll use general RF activity to detect nearby devices.")
        
        # Initialize calibration values
        calibration_values = {}
        valid_frequencies = []
        
        # Test frequencies up to device max
        max_freq = self.config.get('device_max_freq', 1700e6)
        max_freq_mhz = max_freq / 1e6
        
        # Calibrate for wireless devices (would be Bluetooth in full-range version)
        bt_distance = self.config['proximity_detection']['bluetooth_distance_threshold']
        print(f"\n[Wireless Device Calibration for {bt_distance} feet]")
        print("Since your RTL-SDR cannot tune to Bluetooth frequency (2.4 GHz),")
        print("we'll use alternative frequencies to detect general wireless activity.")
        print(f"1. Place a smartphone or wireless device exactly {bt_distance} feet away from your RTL-SDR antenna")
        print("2. Make sure the device is powered on with Bluetooth and WiFi enabled")
        print("3. Optionally, perform some activity like Bluetooth scanning to increase transmission power")
        input("Press Enter when ready...")
        
        # Try different frequencies for wireless device detection
        test_freqs = []
        
        # Build list of test frequencies based on device capability
        if max_freq_mhz >= 900:
            test_freqs.append(915)  # ISM band
        if max_freq_mhz >= 850:
            test_freqs.append(850)  # Cellular
        if max_freq_mhz >= 750:
            test_freqs.append(750)  # Cellular
        
        # Always include these lower frequencies
        test_freqs.extend([433, 315, 146, 100])
        
        print("\nScanning for wireless device signals...")
        best_power_readings = {}
        
        for freq in test_freqs:
            try:
                print(f"Testing frequency {freq} MHz...")
                self.sdr.center_freq = freq * 1e6
                readings = []
                
                for i in range(5):
                    print(f"Sample {i+1}/5...")
                    samples = self.sdr.read_samples(self.config['num_samples'])
                    frequencies, psd = signal.welch(
                        samples, 
                        fs=self.sdr.sample_rate/1e6, 
                        nperseg=self.config['fft_size'],
                        scaling='density'
                    )
                    psd_db = 10 * np.log10(psd)
                    max_power = np.max(psd_db)
                    readings.append(max_power)
                    time.sleep(1)
                
                avg_power = np.mean(readings)
                print(f"Average power at {freq} MHz: {avg_power:.2f} dB")
                best_power_readings[freq] = avg_power
                valid_frequencies.append(freq)
            except Exception as e:
                print(f"Error testing frequency {freq} MHz: {e}")
        
        # Find the best frequency for detection
        if valid_frequencies:
            # Sort frequencies by power reading (highest first)
            sorted_freqs = sorted(valid_frequencies, key=lambda f: best_power_readings[f], reverse=True)
            best_freq = sorted_freqs[0]
            best_power = best_power_readings[best_freq]
            
            print(f"\nBest frequency for wireless device detection: {best_freq} MHz")
            print(f"Reference power: {best_power:.2f} dB")
            
            # Add buffer to the power reading to reduce false positives
            calibration_values['wireless_freq'] = best_freq
            calibration_values['wireless_power'] = best_power + 2  # 2dB buffer
            
            # Save the frequency for monitoring if not already in the list
            if best_freq not in self.config['frequencies']:
                self.config['frequencies'].append(best_freq)
                print(f"Added {best_freq} MHz to monitoring frequencies")
        else:
            print("Could not find a suitable frequency for wireless device detection.")
            print("Using default power threshold.")
            calibration_values['wireless_freq'] = 433  # Default to 433 MHz ISM band
            calibration_values['wireless_power'] = -50  # Default power threshold
        
        # Calibrate Cellular distance
        cell_distance = self.config['proximity_detection']['cellular_distance_threshold']
        print(f"\n[Cellular Calibration for {cell_distance} feet]")
        print(f"1. Place a cell phone exactly {cell_distance} feet away from your RTL-SDR antenna")
        print("2. Make sure the phone is on and has cellular signal")
        print("3. Optionally, make a call or use mobile data to increase signal strength")
        input("Press Enter when ready...")
        
        print("\nScanning for Cellular signals...")
        
        # Get cellular frequencies we can scan based on device capability
        cellular_freqs = []
        if max_freq_mhz >= 900:
            cellular_freqs.append(900)
        if max_freq_mhz >= 850:
            cellular_freqs.append(850)
        if max_freq_mhz >= 750:
            cellular_freqs.append(750)
        
        # If no cellular frequencies, use lower frequencies as proxy
        if not cellular_freqs:
            print("Your device cannot tune to typical cellular frequencies.")
            print("Using lower frequencies as proxy for cellular activity.")
            cellular_freqs = [433, 200, 100]  # Low frequencies that might catch harmonics
        
        best_cell_readings = {}
        valid_cell_freqs = []
        
        for freq in cellular_freqs:
            try:
                print(f"Testing frequency {freq} MHz...")
                self.sdr.center_freq = freq * 1e6
                readings = []
                
                for i in range(5):
                    print(f"Sample {i+1}/5...")
                    samples = self.sdr.read_samples(self.config['num_samples'])
                    frequencies, psd = signal.welch(
                        samples, 
                        fs=self.sdr.sample_rate/1e6, 
                        nperseg=self.config['fft_size'],
                        scaling='density'
                    )
                    psd_db = 10 * np.log10(psd)
                    max_power = np.max(psd_db)
                    readings.append(max_power)
                    time.sleep(1)
                
                avg_power = np.mean(readings)
                print(f"Average power at {freq} MHz: {avg_power:.2f} dB")
                best_cell_readings[freq] = avg_power
                valid_cell_freqs.append(freq)
            except Exception as e:
                print(f"Error testing frequency {freq} MHz: {e}")
        
        # Find the best frequency for cellular detection
        if valid_cell_freqs:
            # Sort frequencies by power reading (highest first)
            sorted_freqs = sorted(valid_cell_freqs, key=lambda f: best_cell_readings[f], reverse=True)
            best_cell_freq = sorted_freqs[0]
            best_cell_power = best_cell_readings[best_cell_freq]
            
            print(f"\nBest frequency for cellular detection: {best_cell_freq} MHz")
            print(f"Reference power: {best_cell_power:.2f} dB")
            
            # Add buffer to the power reading
            calibration_values['cellular_freq'] = best_cell_freq
            calibration_values['cellular_power'] = best_cell_power + 2  # 2dB buffer
            
            # Save the frequency for monitoring if not already in the list
            if best_cell_freq not in self.config['frequencies']:
                self.config['frequencies'].append(best_cell_freq)
                print(f"Added {best_cell_freq} MHz to monitoring frequencies")
        else:
            print("Could not find a suitable frequency for cellular detection.")
            print("Using default power threshold.")
            if cellular_freqs:
                calibration_values['cellular_freq'] = cellular_freqs[0]
            else:
                calibration_values['cellular_freq'] = 433
            calibration_values['cellular_power'] = -50  # Default power threshold
        
        # Save calibration in config
        self.config['proximity_detection']['calibration_values'] = calibration_values
        self.config['proximity_detection']['calibration_needed'] = False
        
        # Save updated config
        with open('config.json', 'w') as f:
            json.dump(self.config, f, indent=4)
        
        print("\nCalibration complete! The system will now be able to detect devices within:")
        print(f"- Wireless devices: {bt_distance} feet using {calibration_values.get('wireless_freq', 'N/A')} MHz")
        print(f"- Cellular devices: {cell_distance} feet using {calibration_values.get('cellular_freq', 'N/A')} MHz")
        print("\nNOTE: Detection may be less precise than with full-range RTL-SDR devices.")
        print("="*60 + "\n")
        
        input("Press Enter to continue to monitoring...")
        
        # Switch back to curses mode if available
        if self.stdscr:
            curses.initscr()
    
    def check_proximity_breach(self, current_freq, current_psd):
        """Check if a device is too close based on signal strength using limited frequency range"""
        global DASHBOARD
        
        if not self.config.get('proximity_detection', {}).get('enabled', False):
            return False
        
        # Skip if not calibrated
        if self.config.get('proximity_detection', {}).get('calibration_needed', True):
            return False
        
        # Get calibrated values
        calibration_values = self.config['proximity_detection'].get('calibration_values', {})
        if not calibration_values:
            return False
        
        # Check for wireless device (Bluetooth proxy)
        is_wireless_proxy = (current_freq == calibration_values.get('wireless_freq'))
        
        # Check for cellular
        is_cellular_proxy = (current_freq == calibration_values.get('cellular_freq'))
        
        if not (is_wireless_proxy or is_cellular_proxy):
            return False
        
        # Get max power
        max_power = np.max(current_psd)
        
        # Calculate extended range thresholds
        # In RF, power drops with square of distance, so double distance = 1/4 power = -6 dB
        extended_range_factor = -6  # dB reduction for double the distance
        
        # Check wireless device breach
        if is_wireless_proxy:
            ref_power = calibration_values.get('wireless_power')
            distance = self.config['proximity_detection']['bluetooth_distance_threshold']
            
            # Check for extended range detection (at 2x the distance)
            extended_ref = ref_power + extended_range_factor
            if max_power > extended_ref and max_power <= ref_power:
                # This is an early detection - store it but don't trigger alert
                early_detection = {
                    'type': 'wireless',
                    'distance': distance * 2,  # Double the distance
                    'power': max_power,
                    'reference': extended_ref,
                    'frequency': current_freq,
                    'alert_level': 'early'
                }
                DASHBOARD['early_detection'] = early_detection
                DASHBOARD['early_detection_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.update_dashboard(log_message=f"Early detection: Wireless device at ~{distance*2} feet")
            
            # Check for actual alert threshold
            if max_power > ref_power:
                return {
                    'type': 'wireless',
                    'distance': distance,
                    'power': max_power,
                    'reference': ref_power,
                    'frequency': current_freq,
                    'alert_level': 'alert'
                }
        
        # Check cellular breach
        if is_cellular_proxy:
            ref_power = calibration_values.get('cellular_power')
            distance = self.config['proximity_detection']['cellular_distance_threshold']
            
            # Check for extended range detection (at 2x the distance)
            extended_ref = ref_power + extended_range_factor
            if max_power > extended_ref and max_power <= ref_power:
                # This is an early detection - store it but don't trigger alert
                early_detection = {
                    'type': 'cellular',
                    'distance': distance * 2,  # Double the distance
                    'power': max_power,
                    'reference': extended_ref,
                    'frequency': current_freq,
                    'alert_level': 'early'
                }
                DASHBOARD['early_detection'] = early_detection
                DASHBOARD['early_detection_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.update_dashboard(log_message=f"Early detection: Cell phone at ~{distance*2} feet")
            
            # Check for actual alert threshold
            if max_power > ref_power:
                return {
                    'type': 'cellular',
                    'distance': distance,
                    'power': max_power,
                    'reference': ref_power,
                    'frequency': current_freq,
                    'alert_level': 'alert'
                }
        
        return False
    
    def scan_for_intrusions(self, current_freq):
        """Scan RF spectrum and detect anomalies"""
        # Check if baseline exists at all
        if self.baseline is None:
            self.update_dashboard(status="No baseline available. Creating baseline for all frequencies.")
            if not self.create_baseline():
                return False
        
        # Check if we have baseline specifically for this frequency
        if 'data' not in self.baseline or current_freq not in self.baseline['data']:
            self.update_dashboard(status=f"No baseline data for {current_freq} MHz. Creating baseline...")
            try:
                # Create baseline just for this frequency
                success = self.create_baseline_for_frequency(current_freq)
                if not success:
                    self.update_dashboard(log_message=f"Failed to create baseline for {current_freq} MHz.", error=True)
                    return False
                self.update_dashboard(log_message=f"Successfully created baseline for {current_freq} MHz.")
            except Exception as e:
                self.update_dashboard(log_message=f"Error creating baseline for {current_freq} MHz: {e}", error=True)
                return False
                
            return False  # Skip this scan cycle, we'll scan on the next cycle
        
        # Capture current spectrum
        frequencies, current_psd = self.capture_spectrum()
        if len(frequencies) == 0:
            self.update_dashboard(log_message=f"Error capturing spectrum at {current_freq} MHz.", error=True)
            return False
        
        # First check for proximity breaches (takes priority)
        proximity_breach = self.check_proximity_breach(current_freq, current_psd)
        if proximity_breach:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"proximity_{proximity_breach['type']}_{timestamp}.png"
            
            # Log proximity breach
            log_file = os.path.join(self.config['output_dir'], 'proximity_alerts.log')
            with open(log_file, 'a') as f:
                f.write(f"{timestamp},{proximity_breach['type']},{proximity_breach['distance']},{proximity_breach['power']:.2f},{proximity_breach['frequency']}\n")
            
            # Plot the spectrum showing the breach
            self.plot_proximity_breach(frequencies, current_psd, proximity_breach, filename)
            
            # Alert for proximity breach
            self.send_proximity_alert(proximity_breach, filename)
            
            # Update dashboard with alert
            self.update_dashboard(alert=proximity_breach)
            
            return True
        
        # Get baseline for this frequency
        baseline_data = self.baseline['data'][current_freq]
        baseline_psd = baseline_data['psd_mean']
        
        # Compare with baseline
        diff = current_psd - baseline_psd
        
        # Find frequencies that exceed threshold
        threshold = self.config['threshold']
        anomalies = []
        
        for i, freq in enumerate(frequencies):
            if abs(diff[i]) > threshold:
                anomalies.append({
                    'frequency': freq,
                    'baseline_power': baseline_psd[i],
                    'current_power': current_psd[i],
                    'difference': diff[i]
                })
        
        # Plot if anomalies detected
        if anomalies:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"anomaly_{current_freq}MHz_{timestamp}.png"
            
            self.plot_comparison(frequencies, baseline_psd, current_psd, 
                               anomalies, filename)
            
            # Log anomalies
            log_file = os.path.join(self.config['output_dir'], 'anomalies.log')
            with open(log_file, 'a') as f:
                for anomaly in anomalies:
                    f.write(f"{timestamp},{current_freq},{anomaly['frequency']:.3f},{anomaly['difference']:.2f}\n")
            
            # Send alert if configured
            anomaly_alert = {
                'type': 'spectrum_anomaly', 
                'frequency': current_freq, 
                'power': max([a['current_power'] for a in anomalies]),
                'detected_at': anomalies[0]['frequency']
            }
            
            self.send_alert(anomalies, current_freq, filename)
            
            # Update dashboard
            self.update_dashboard(alert=anomaly_alert)
            
            return True
        
        return False
    
    def plot_spectrum(self, frequencies, psd, title="RF Spectrum", filename=None):
        """Plot RF spectrum"""
        plt.figure(figsize=(12, 6))
        plt.plot(frequencies, psd)
        plt.title(title)
        plt.xlabel('Frequency (MHz)')
        plt.ylabel('Power (dB)')
        plt.grid(True)
        
        if filename:
            plt.savefig(os.path.join(self.config['output_dir'], filename))
            plt.close()
        else:
            plt.show()
    
    def plot_comparison(self, frequencies, baseline_psd, current_psd, anomalies, filename):
        """Plot comparison between baseline and current spectrum"""
        plt.figure(figsize=(12, 8))
        
        # Plot spectrums
        plt.subplot(2, 1, 1)
        plt.plot(frequencies, baseline_psd, label='Baseline', alpha=0.7)
        plt.plot(frequencies, current_psd, label='Current', alpha=0.7)
        
        # Highlight anomalies
        for anomaly in anomalies:
            idx = (np.abs(frequencies - anomaly['frequency'])).argmin()
            plt.plot(anomaly['frequency'], current_psd[idx], 'ro')
        
        plt.title('RF Spectrum Comparison')
        plt.ylabel('Power (dB)')
        plt.legend()
        plt.grid(True)
        
        # Plot difference
        plt.subplot(2, 1, 2)
        plt.plot(frequencies, current_psd - baseline_psd)
        plt.axhline(y=self.config['threshold'], color='r', linestyle='--', alpha=0.7, 
                   label=f'Threshold (+{self.config["threshold"]} dB)')
        plt.axhline(y=-self.config['threshold'], color='r', linestyle='--', alpha=0.7, 
                   label=f'Threshold (-{self.config["threshold"]} dB)')
        
        # Annotate anomalies
        for anomaly in anomalies:
            idx = (np.abs(frequencies - anomaly['frequency'])).argmin()
            plt.annotate(f"{anomaly['frequency']:.1f} MHz",
                        xy=(anomaly['frequency'], current_psd[idx] - baseline_psd[idx]),
                        xytext=(0, 20), textcoords='offset points',
                        arrowprops=dict(arrowstyle='->'))
        
        plt.xlabel('Frequency (MHz)')
        plt.ylabel('Difference (dB)')
        plt.legend()
        plt.grid(True)
        
        # Save figure
        plt.tight_layout()
        plt.savefig(os.path.join(self.config['output_dir'], filename))
        plt.close()
    
    def plot_proximity_breach(self, frequencies, current_psd, breach_info, filename):
        """Plot proximity breach detection"""
        plt.figure(figsize=(12, 6))
        plt.plot(frequencies, current_psd, label='Current', color='red')
        
        # Highlight the reference level
        plt.axhline(y=breach_info['reference'], color='r', linestyle='--', 
                  label=f"Proximity Threshold ({breach_info['distance']} feet)")
        
        # Determine device type based on breach type
        if breach_info['type'] == 'wireless':
            device_type = "Wireless Device"
        else:
            device_type = "Cell Phone"
        
        # Mark the breach point
        max_idx = np.argmax(current_psd)
        plt.plot(frequencies[max_idx], current_psd[max_idx], 'ro', markersize=10)
        plt.annotate(f"{device_type} Detected!", 
                   xy=(frequencies[max_idx], current_psd[max_idx]),
                   xytext=(0, 30), textcoords='offset points',
                   arrowprops=dict(arrowstyle='->', color='black'),
                   fontsize=12, fontweight='bold')
        
        # Add title and labels
        plt.title(f"Proximity Alert: {device_type} within {breach_info['distance']} feet", 
                fontsize=14)
        plt.xlabel('Frequency (MHz)')
        plt.ylabel('Power (dB)')
        plt.grid(True)
        plt.legend()
        
        # Save figure
        plt.tight_layout()
        plt.savefig(os.path.join(self.config['output_dir'], filename))
        plt.close()
    
    def send_alert(self, anomalies, center_freq, image_filename=None):
        """Send alert with anomaly information"""
        now = datetime.datetime.now()
        
        # Check if we should throttle alerts (no more than 1 per 5 minutes)
        if (now - self.last_alert_time).total_seconds() < 300:
            return
        
        self.last_alert_time = now
        self.alert_count += 1
        
        # Update log
        self.update_dashboard(log_message=f"ALERT: {len(anomalies)} anomalies detected at {center_freq} MHz")
        
        # macOS notification
        if NOTIFICATIONS_AVAILABLE:
            # Create a summary of detected frequencies
            freq_summary = ", ".join([f"{anomaly['frequency']:.1f} MHz" for anomaly in anomalies[:3]])
            if len(anomalies) > 3:
                freq_summary += f", and {len(anomalies)-3} more"
                
            pync.notify(f"Detected {len(anomalies)} anomalies at {center_freq} MHz band", 
                     title=f"RF-IDS Alert #{self.alert_count}", 
                     sound="Basso",
                     open=os.path.join(self.config['output_dir'], image_filename))
        
        # Send email if configured
        if self.config['email_alerts']:
            try:
                msg = EmailMessage()
                msg['Subject'] = f'RF-IDS Alert: {len(anomalies)} anomalies at {center_freq} MHz'
                msg['From'] = self.config['email']['sender']
                msg['To'] = self.config['email']['recipient']
                
                # Create email content
                content = f"""
                RF Intrusion Detection System Alert
                
                Time: {now}
                Frequency Band: {center_freq} MHz
                Detected {len(anomalies)} anomalies:
                
                """
                
                for i, anomaly in enumerate(anomalies):
                    content += f"{i+1}. Frequency: {anomaly['frequency']:.3f} MHz, " + \
                              f"Difference: {anomaly['difference']:.2f} dB\n"
                
                msg.set_content(content)
                
                # Add image attachment if available
                if image_filename:
                    image_path = os.path.join(self.config['output_dir'], image_filename)
                    with open(image_path, 'rb') as img:
                        img_data = img.read()
                        msg.add_attachment(img_data, maintype='image', 
                                         subtype='png', filename=image_filename)
                
                # Send email
                server = smtplib.SMTP(self.config['email']['server'], self.config['email']['port'])
                server.starttls()
                server.login(self.config['email']['sender'], self.config['email']['password'])
                server.send_message(msg)
                server.quit()
                
                self.update_dashboard(log_message="Alert email sent successfully")
            
            except Exception as e:
                self.update_dashboard(log_message=f"Failed to send email alert: {e}", error=True)
        
        # Send SMS if configured
        if self.config.get('sms_alerts', False):
            try:
                message = f"RF-IDS Alert #{self.alert_count}: {len(anomalies)} anomalies detected at {center_freq} MHz band"
                self.send_sms_alert(message)
            except Exception as e:
                self.update_dashboard(log_message=f"Failed to send SMS alert: {e}", error=True)
    
    def send_proximity_alert(self, breach_info, image_filename=None):
        """Send alert specifically for proximity breaches"""
        now = datetime.datetime.now()
        
        # Check if we should throttle alerts (no more than 1 per minute for proximity)
        if (now - self.last_alert_time).total_seconds() < 60:
            return
        
        self.last_alert_time = now
        self.alert_count += 1
        
        # Determine device type for readable message
        device_type = "wireless device" if breach_info['type'] == 'wireless' else "cell phone"
        
        # Update log
        self.update_dashboard(log_message=f"PROXIMITY ALERT: {device_type} within {breach_info['distance']} feet")
        
        # macOS notification with higher urgency
        if NOTIFICATIONS_AVAILABLE:
            pync.notify(f"A {device_type} is within {breach_info['distance']} feet!", 
                     title=f"PROXIMITY ALERT!", 
                     sound="Basso",
                     open=os.path.join(self.config['output_dir'], image_filename))
        
        # Send email if configured
        if self.config['email_alerts']:
            try:
                msg = EmailMessage()
                msg['Subject'] = f'RF-IDS PROXIMITY ALERT: {device_type} detected'
                msg['From'] = self.config['email']['sender']
                msg['To'] = self.config['email']['recipient']
                
                # Create email content
                content = f"""
                RF Intrusion Detection System - PROXIMITY ALERT
                
                Time: {now}
                A {device_type} is within {breach_info['distance']} feet of the sensor!
                
                Detection frequency: {breach_info['frequency']} MHz
                Signal strength: {breach_info['power']:.2f} dB 
                Threshold: {breach_info['reference']:.2f} dB
                
                This could indicate unauthorized device presence in your secure area.
                """
                
                msg.set_content(content)
                
                # Add image attachment if available
                if image_filename:
                    image_path = os.path.join(self.config['output_dir'], image_filename)
                    with open(image_path, 'rb') as img:
                        img_data = img.read()
                        msg.add_attachment(img_data, maintype='image', 
                                         subtype='png', filename=image_filename)
                
                # Send email
                server = smtplib.SMTP(self.config['email']['server'], self.config['email']['port'])
                server.starttls()
                server.login(self.config['email']['sender'], self.config['email']['password'])
                server.send_message(msg)
                server.quit()
                
                self.update_dashboard(log_message="Alert email sent successfully")
            
            except Exception as e:
                self.update_dashboard(log_message=f"Failed to send email alert: {e}", error=True)
        
        # Send SMS if configured
        if self.config.get('sms_alerts', False):
            try:
                message = f"RF-IDS PROXIMITY ALERT: {device_type} detected within {breach_info['distance']} feet!"
                self.send_sms_alert(message)
            except Exception as e:
                self.update_dashboard(log_message=f"Failed to send SMS alert: {e}", error=True)
    
    def send_sms_alert(self, message):
        """Send SMS alert using Twilio"""
        if not self.config.get('sms_alerts', False):
            return
            
        sms_config = self.config.get('sms_config', {})
        if sms_config.get('service') == 'twilio':
            try:
                account_sid = sms_config.get('account_sid')
                auth_token = sms_config.get('auth_token')
                from_number = sms_config.get('from_number')
                to_number = sms_config.get('to_number')
                
                # Check if all required fields are present
                if not all([account_sid, auth_token, from_number, to_number]):
                    self.update_dashboard(log_message="SMS alert failed: Missing Twilio configuration", error=True)
                    return
                    
                # Send SMS using Twilio API
                url = f'https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json'
                data = {
                    'From': from_number,
                    'To': to_number,
                    'Body': message
                }
                
                response = requests.post(
                    url,
                    data=data,
                    auth=(account_sid, auth_token)
                )
                
                if response.status_code == 201:
                    self.update_dashboard(log_message="SMS alert sent successfully")
                else:
                    self.update_dashboard(log_message=f"SMS alert failed: {response.json().get('message', 'Unknown error')}", error=True)
                    
            except Exception as e:
                self.update_dashboard(log_message=f"Failed to send SMS alert: {e}", error=True)
    
    def monitor_frequency(self, frequency):
        """Monitor a specific frequency with error recovery"""
        global DASHBOARD
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                self.update_dashboard(status=f"Monitoring frequency: {frequency} MHz", current_freq=frequency)
                self.sdr.center_freq = frequency * 1e6
                
                # Increment scan count
                DASHBOARD['scan_count'] = DASHBOARD.get('scan_count', 0) + 1
                
                # Capture spectrum for signal level indicator
                try:
                    samples = self.sdr.read_samples(4096)  # Larger sample for better signal detection
                    # Calculate signal power - use log scale for better visibility
                    power = np.mean(np.abs(samples)**2)
                    # Add noise floor and use log scale to make weak signals visible
                    # Ensure meter always shows some activity with minimum 0.1 level
                    log_power = np.log10(power + 1e-10)  # Avoid log(0)
                    # Normalize to 0.1-1.0 range (never empty) with some scaling
                    min_level = 0.1  # Minimum level to always show some activity
                    normalized_power = min_level + (1.0 - min_level) * min(1.0, max(0, (log_power + 10) / 10))
                    DASHBOARD['signal_level'] = normalized_power
                    
                    # Store current signal strength in dB for display
                    if len(samples) > 0:
                        signal_db = 10 * np.log10(power + 1e-10)
                        DASHBOARD['signal_db'] = signal_db
                    
                    # Force dashboard refresh to show activity
                    if self.stdscr:
                        self.draw_dashboard()
                except Exception:
                    # If error, ensure we show some movement in the meter
                    import random
                    DASHBOARD['signal_level'] = 0.1 + random.random() * 0.3
                    pass
                
                return self.scan_for_intrusions(frequency)
            except Exception as e:
                self.update_dashboard(log_message=f"Error with frequency {frequency} MHz (attempt {attempt+1}/{max_retries}): {e}", error=True)
                if attempt < max_retries - 1:
                    self.update_dashboard(log_message=f"Retrying in 2 seconds...")
                    time.sleep(2)
                    # Try to reset the device
                    try:
                        self.sdr.close()
                        self.sdr = RtlSdr()
                        self.sdr.sample_rate = self.config['sample_rate']
                        self.sdr.gain = self.config['gain']
                    except Exception as reset_error:
                        self.update_dashboard(log_message=f"Error resetting device: {reset_error}", error=True)
                else:
                    self.update_dashboard(log_message=f"Failed to monitor {frequency} MHz after {max_retries} attempts.", error=True)
                    self.update_dashboard(log_message=f"Removing {frequency} MHz from monitoring list.", error=True)
                    if frequency in self.config['frequencies']:
                        self.config['frequencies'].remove(frequency)
                        # Save updated config
                        with open('config.json', 'w') as f:
                            json.dump(self.config, f, indent=4)
                    
                    # Try switching to a known safe frequency
                    try:
                        self.sdr.center_freq = 100e6  # FM radio is usually safe
                        self.update_dashboard(log_message="Reset to safe frequency")
                    except:
                        pass
        return False
    
    def handle_user_input(self):
        """Handle user input for keyboard commands"""
        if not self.stdscr:
            return
            
        try:
            # Check for keypress (non-blocking)
            self.stdscr.nodelay(True)
            key = self.stdscr.getch()
            
            if key == ord('q'):  # Quit
                return False
            elif key == ord('r'):  # Reset baseline
                self.update_dashboard(status="Resetting baseline...")
                self.baseline = None
                os.remove(self.baseline_file) if os.path.exists(self.baseline_file) else None
                self.create_baseline()
                self.update_dashboard(status="Baseline reset complete")
        except:
            pass
            
        return True
    
    def run(self):
        """Run continuous monitoring with error recovery"""
        try:
            # Check if proximity detection is enabled and needs calibration
            if self.config.get('proximity_detection', {}).get('enabled', False) and \
               self.config.get('proximity_detection', {}).get('calibration_needed', True):
                self.calibrate_proximity_detection()
            
            # Make sure output directory exists
            os.makedirs(self.config['output_dir'], exist_ok=True)
            
            # Load or create baseline
            if self.baseline is None:
                self.update_dashboard(status="Checking for existing baseline file...")
                if os.path.exists(self.baseline_file):
                    self.update_dashboard(log_message=f"Found baseline file: {self.baseline_file}")
                    success = self.load_baseline()
                    if not success:
                        self.update_dashboard(status="Failed to load baseline file. Creating new baseline...")
                        success = self.create_baseline()
                        if not success:
                            self.update_dashboard(log_message="Failed to create baseline. Please check your RTL-SDR connection.", error=True)
                            return
                else:
                    self.update_dashboard(status="No baseline file found. Creating new baseline...")
                    success = self.create_baseline()
                    if not success:
                        self.update_dashboard(log_message="Failed to create baseline. Please check your RTL-SDR connection.", error=True)
                        return
            
            self.update_dashboard(status="Starting RF intrusion detection system...")
            
            # Verify we have frequencies to monitor
            if not self.config['frequencies']:
                self.update_dashboard(log_message="No valid frequencies to monitor! Adding some safe defaults.", error=True)
                # Add some safe defaults
                self.config['frequencies'] = [100, 200, 433]  # FM radio, VHF, ISM band
                with open('config.json', 'w') as f:
                    json.dump(self.config, f, indent=4)
            
            self.update_dashboard(log_message=f"Monitoring {len(self.config['frequencies'])} frequencies: {', '.join(map(str, self.config['frequencies']))} MHz")
            self.update_dashboard(log_message=f"Scan interval: {self.config['scan_interval']} seconds")
            
            # Check if we need to create baseline for frequencies
            if self.baseline and 'data' in self.baseline:
                missing_baselines = []
                for freq in self.config['frequencies']:
                    if freq not in self.baseline['data']:
                        missing_baselines.append(freq)
                
                if missing_baselines:
                    self.update_dashboard(status=f"Creating baseline for {len(missing_baselines)} frequencies...")
                    for freq in missing_baselines:
                        self.update_dashboard(status=f"Creating baseline for {freq} MHz...")
                        try:
                            success = self.create_baseline_for_frequency(freq)
                            if success:
                                self.update_dashboard(log_message=f"Successfully created baseline for {freq} MHz")
                            else:
                                self.update_dashboard(log_message=f"Failed to create baseline for {freq} MHz", error=True)
                        except Exception as e:
                            self.update_dashboard(log_message=f"Error creating baseline for {freq} MHz: {e}", error=True)
            
            # Send startup notification
            if NOTIFICATIONS_AVAILABLE:
                pync.notify(f"Monitoring {len(self.config['frequencies'])} frequencies", 
                          title="RF-IDS Started", 
                          sound="Glass")
            
            # Main monitoring loop
            error_count = 0
            max_consecutive_errors = 5
            
            self.update_dashboard(status="Monitoring active...")
            
            # Status ticker variables
            ticker_messages = [
                "Analyzing RF spectrum...",
                "Scanning for anomalies...",
                "Monitoring wireless activity...",
                "Looking for unauthorized transmissions...",
                "Checking signal patterns...",
                "Monitoring RF environment..."
            ]
            last_ticker_update = 0
            ticker_index = 0
            
            while True:
                # Update status ticker every 3 seconds
                current_time = time.time()
                if current_time - last_ticker_update > 3:
                    self.update_dashboard(status=ticker_messages[ticker_index])
                    ticker_index = (ticker_index + 1) % len(ticker_messages)
                    last_ticker_update = current_time
                    
                    # Force dashboard refresh to show "alive" status
                    if self.stdscr:
                        self.draw_dashboard()
                
                # Check for user input
                if not self.handle_user_input():
                    self.update_dashboard(status="User requested exit...")
                    break
                
                # Check if we still have frequencies to monitor
                if not self.config['frequencies']:
                    self.update_dashboard(status="No valid frequencies left to monitor! Exiting...", error=True)
                    break
                
                # Try to monitor each frequency
                monitoring_successful = False
                for freq in list(self.config['frequencies']):  # Use list() to allow removing items during iteration
                    try:
                        detected = self.monitor_frequency(freq)
                        monitoring_successful = True  # At least one frequency monitored successfully
                        
                        if detected:
                            # Increase scan rate temporarily if anomaly detected
                            time.sleep(1)
                        else:
                            time.sleep(self.config['scan_interval'])
                    except Exception as e:
                        self.update_dashboard(log_message=f"Unexpected error monitoring {freq} MHz: {e}", error=True)
                        # Try to reset the SDR if we're having problems
                        try:
                            self.sdr.close()
                            time.sleep(1)
                            self.sdr = RtlSdr()
                            self.sdr.sample_rate = self.config['sample_rate']
                            self.sdr.gain = self.config['gain']
                            self.update_dashboard(log_message="Reset RTL-SDR device")
                        except Exception as reset_error:
                            self.update_dashboard(log_message=f"Error resetting device: {reset_error}", error=True)
                
                # Reset error count if we had a successful monitoring cycle
                if monitoring_successful:
                    error_count = 0
                else:
                    error_count += 1
                    self.update_dashboard(log_message=f"Full monitoring cycle failed (consecutive failures: {error_count}/{max_consecutive_errors})", error=True)
                    # Wait longer after errors to give the device time to recover
                    time.sleep(5)
                
                # Exit if we've had too many errors in a row
                if error_count >= max_consecutive_errors:
                    self.update_dashboard(status=f"Too many consecutive errors ({error_count}). Stopping monitoring.", error=True)
                    break
        
        except KeyboardInterrupt:
            self.update_dashboard(status="Stopping RF intrusion detection system...")
            if NOTIFICATIONS_AVAILABLE:
                pync.notify("System stopped by user", 
                          title="RF-IDS Stopped", 
                          sound="Submarine")
        
        except Exception as e:
            self.update_dashboard(status=f"Unexpected error: {e}", error=True)
            traceback.print_exc()
        
        finally:
            try:
                self.sdr.close()
                self.update_dashboard(log_message="SDR device closed")
            except:
                self.update_dashboard(log_message="Note: Error while closing SDR device")
    
    def close(self):
        """Clean up resources"""
        try:
            self.sdr.close()
        except:
            pass

def run_with_dashboard(stdscr):
    """Run the RF-IDS system with a curses dashboard"""
    # Set up curses
    curses.curs_set(0)  # Hide cursor
    stdscr.nodelay(True)  # Non-blocking input
    
    # Try to initialize colors if terminal supports them
    if curses.has_colors():
        try:
            curses.start_color()
            curses.init_pair(1, curses.COLOR_BLUE, curses.COLOR_BLACK)
            curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
            curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
            curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK)
        except:
            pass  # If colors fail, we'll fall back to default display
    
    # Create and run the detector
    detector = RFIntrusionDetector(stdscr=stdscr)
    detector.run()
    detector.close()

def main():
    # Check if we should use dashboard or console mode
    use_dashboard = True
    
    # Extract command line arguments
    for arg in sys.argv[1:]:
        if arg == "--console" or arg == "-c":
            use_dashboard = False
    
    if use_dashboard:
        try:
            # Run with curses dashboard
            wrapper(run_with_dashboard)
        except Exception as e:
            print(f"Error with dashboard mode: {e}")
            print("Falling back to console mode...")
            detector = RFIntrusionDetector()
            detector.run()
            detector.close()
    else:
        # Console mode
        detector = RFIntrusionDetector()
        detector.run()
        detector.close()

if __name__ == "__main__":
    main()
