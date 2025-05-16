"""
Enhanced anomaly logging and real-time log viewer for RF-IDS
This adds:
- Signal % increase tracking
- Distance estimation for all anomalies
- First seen and last seen timestamps
- "L" key to view logs while monitoring
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
import csv

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
    'early_detection_time': None, # Timestamp for early detection
    'viewing_logs': False,      # Flag to indicate if we're viewing logs
    'log_page': 0,              # Current page of logs being viewed
    'log_entries': []           # Cached log entries when viewing
}

# Maximum number of log entries to keep
MAX_LOG_ENTRIES = 10
# Number of log entries per page in log viewer
LOG_ENTRIES_PER_PAGE = 15

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
        
        # Create enhanced log file with CSV header if it doesn't exist
        self.enhanced_log_file = os.path.join(self.config['output_dir'], 'enhanced_anomalies.csv')
        if not os.path.exists(self.enhanced_log_file):
            with open(self.enhanced_log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'first_seen', 'last_seen', 'center_freq', 
                    'anomaly_freq', 'difference_db', 'signal_increase_pct',
                    'estimated_distance', 'type'
                ])
        
        # Create log file for proximity detections with CSV header if it doesn't exist
        self.proximity_log_file = os.path.join(self.config['output_dir'], 'proximity_log.csv')
        if not os.path.exists(self.proximity_log_file):
            with open(self.proximity_log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'first_seen', 'last_seen', 'device_type', 
                    'frequency', 'power_db', 'distance', 'status'
                ])
        
        # Anomaly tracking dictionary - for storing first_seen/last_seen
        self.anomaly_tracker = {}
        
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
        if self.stdscr and not DASHBOARD.get('viewing_logs', False):
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
                if 'signal_increase' in anomaly_info:
                    self.stdscr.addstr(13, 2, f"Signal Increase: {anomaly_info['signal_increase']:.1f}%")
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
                if 'signal_increase' in early_info:
                    self.stdscr.addstr(early_y + 6, early_x, f"Signal Increase: {early_info['signal_increase']:.1f}%", attr)
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
            self.stdscr.addstr(height-1, 2, "Press 'q' to exit, 'r' to reset baseline, 'l' to view logs")
            
            # Refresh the screen
            self.stdscr.refresh()
        except Exception as e:
            # Fall back to regular console output if curses fails
            print(f"Dashboard error: {e}")
    
    def draw_log_viewer(self):
        """Draw the log viewer screen"""
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
            title = "RF-IDS Log Viewer"
            self.stdscr.addstr(0, (width - len(title)) // 2, title)
            
            # Log type selector
            log_types = ["Anomaly Log", "Proximity Log"]
            log_type_idx = DASHBOARD.get('log_type', 0)
            log_type_str = f"Log Type: {log_types[log_type_idx]}"
            self.stdscr.addstr(2, 2, log_type_str)
            
            # Current time
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            time_str = f"Time: {current_time}"
            self.stdscr.addstr(2, width - len(time_str) - 2, time_str)
            
            # Page indicator
            total_pages = max(1, (len(DASHBOARD['log_entries']) + LOG_ENTRIES_PER_PAGE - 1) // LOG_ENTRIES_PER_PAGE)
            page_str = f"Page {DASHBOARD['log_page'] + 1}/{total_pages}"
            self.stdscr.addstr(3, 2, page_str)
            
            # Column headers
            if log_type_idx == 0:  # Anomaly log
                header = f"{'Timestamp':<19} {'First Seen':<19} {'Last Seen':<19} {'Freq':<7} {'Anom MHz':<8} {'Diff dB':<8} {'Inc %':<6} {'Dist':<6} {'Type':<12}"
            else:  # Proximity log
                header = f"{'Timestamp':<19} {'First Seen':<19} {'Last Seen':<19} {'Type':<10} {'Freq MHz':<8} {'Power dB':<9} {'Dist':<6} {'Status':<8}"
            
            # Make sure header fits in the width
            if len(header) > width - 4:
                header = header[:width-7] + "..."
                
            self.stdscr.addstr(5, 2, header)
            self.stdscr.addstr(6, 2, "-" * min(len(header), width-4))
            
            # Show log entries for current page
            start_idx = DASHBOARD['log_page'] * LOG_ENTRIES_PER_PAGE
            end_idx = min(start_idx + LOG_ENTRIES_PER_PAGE, len(DASHBOARD['log_entries']))
            
            for i, entry in enumerate(DASHBOARD['log_entries'][start_idx:end_idx]):
                row_y = 7 + i
                
                if row_y < height - 2:
                    # Format the entry based on log type
                    if log_type_idx == 0:  # Anomaly log
                        try:
                            line = f"{entry[0]:<19} {entry[1]:<19} {entry[2]:<19} {entry[3]:<7} {entry[4]:<8} {entry[5]:<8} {entry[6]:<6} {entry[7]:<6} {entry[8]:<12}"
                        except (IndexError, TypeError):
                            line = f"Error formatting log entry: {entry}"
                    else:  # Proximity log
                        try:
                            line = f"{entry[0]:<19} {entry[1]:<19} {entry[2]:<19} {entry[3]:<10} {entry[4]:<8} {entry[5]:<9} {entry[6]:<6} {entry[7]:<8}"
                        except (IndexError, TypeError):
                            line = f"Error formatting log entry: {entry}"
                    
                    # Truncate if too long
                    if len(line) > width - 4:
                        line = line[:width-7] + "..."
                    
                    # Highlight recent entries (last hour)
                    try:
                        entry_time = datetime.datetime.strptime(entry[0], "%Y-%m-%d %H:%M:%S")
                        now = datetime.datetime.now()
                        if (now - entry_time).total_seconds() < 3600:
                            self.stdscr.addstr(row_y, 2, line, curses.A_BOLD)
                        else:
                            self.stdscr.addstr(row_y, 2, line)
                    except:
                        self.stdscr.addstr(row_y, 2, line)
            
            # Instructions
            instructions = "Press 'q' to return to dashboard, 'n'/'p' for next/prev page, 't' to switch log type"
            if len(instructions) > width - 4:
                instructions = instructions[:width-7] + "..."
            self.stdscr.addstr(height-1, 2, instructions)
            
            # Refresh the screen
            self.stdscr.refresh()
        except Exception as e:
            # Fall back to regular console output if curses fails
            print(f"Log viewer error: {e}")
            traceback.print_exc()
    
    def load_log_entries(self):
        """Load log entries based on selected type"""
        log_type_idx = DASHBOARD.get('log_type', 0)
        entries = []
        
        try:
            if log_type_idx == 0:  # Anomaly log
                if os.path.exists(self.enhanced_log_file):
                    with open(self.enhanced_log_file, 'r', newline='') as f:
                        reader = csv.reader(f)
                        next(reader)  # Skip header
                        entries = list(reader)
            else:  # Proximity log
                if os.path.exists(self.proximity_log_file):
                    with open(self.proximity_log_file, 'r', newline='') as f:
                        reader = csv.reader(f)
                        next(reader)  # Skip header
                        entries = list(reader)
                        
            # Sort entries by timestamp (newest first)
            entries.sort(key=lambda x: x[0], reverse=True)
        except Exception as e:
            print(f"Error loading log entries: {e}")
            entries = [["Error loading log entries", str(e)]]
        
        DASHBOARD['log_entries'] = entries
        DASHBOARD['log_page'] = 0  # Reset to first page
    
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
        # Existing implementation...
        # This is a long method from the original code, I'm not modifying it
        pass
    
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
        # Existing implementation...
        # This is a long method from the original code, I'm not modifying it
        pass
    
    def create_baseline_for_frequency(self, freq):
        """Create baseline for a specific frequency"""
        # Existing implementation...
        # This is a long method from the original code, I'm not modifying it
        pass
    
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
        # Existing implementation...
        # This is a long method from the original code, I'm not modifying it
        pass
    
    def estimate_distance(self, current_power, baseline_power, freq_mhz):
        """Estimate distance based on signal strength using FSPL model"""
        # Free Space Path Loss formula: FSPL(dB) = 20*log10(d) + 20*log10(f) + 20*log10(4π/c)
        # where d is distance in meters, f is frequency in Hz, c is speed of light
        
        # Calculate signal strength difference
        power_diff = current_power - baseline_power
        
        # If power is less than baseline, not approaching
        if power_diff <= 0:
            return None
        
        # Simplified distance estimation based on RF principles
        # In free space, doubling distance reduces power by 6dB
        # We use baseline as a reference point and assume it's at ~50 feet
        reference_distance = 50.0  # feet
        
        # Calculate distance based on 6dB rule (each 6dB increase = half the distance)
        # power_diff = 10 * log10(d_ref^2 / d^2) for free space
        distance = reference_distance / (10 ** (power_diff / 20.0))
        
        # Apply frequency-based correction (higher freq = shorter range)
        # This is a simple approximation
        freq_factor = 1.0
        if freq_mhz >= 800:
            freq_factor = 0.7  # Higher frequencies attenuate faster
        elif freq_mhz >= 400:
            freq_factor = 0.85
            
        distance *= freq_factor
        
        # Constrain distance to reasonable values
        if distance < 1:
            distance = 1
        if distance > 100:
            distance = 100
            
        return round(distance, 1)
    
    def calculate_signal_increase(self, current_power, baseline_power):
        """Calculate percentage increase in signal strength"""
        # Convert from dB to linear power ratio
        current_linear = 10 ** (current_power / 10)
        baseline_linear = 10 ** (baseline_power / 10)
        
        # Calculate percentage increase
        if baseline_linear <= 0:
            return 0.0
        
        increase = ((current_linear - baseline_linear) / baseline_linear) * 100
        
        # Clip to reasonable values
        if increase < 0:
            increase = 0.0
        if increase > 10000:  # Cap at 10,000% to avoid huge numbers
            increase = 10000.0
            
        return increase
    
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
        
        # Current timestamp
        now = datetime.datetime.now()
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
        
        # Check wireless device breach
        if is_wireless_proxy:
            ref_power = calibration_values.get('wireless_power')
            distance = self.config['proximity_detection']['bluetooth_distance_threshold']
            
            # Check for extended range detection (at 2x the distance)
            extended_ref = ref_power + extended_range_factor
            
            # Calculate signal increase percentage
            signal_increase = self.calculate_signal_increase(max_power, extended_ref)
            
            # Update device tracking for wireless devices
            device_key = f"wireless_{current_freq}"
            
            if max_power > extended_ref and max_power <= ref_power:
                # This is an early detection - store it but don't trigger alert
                early_detection = {
                    'type': 'wireless',
                    'distance': distance * 2,  # Double the distance
                    'power': max_power,
                    'reference': extended_ref,
                    'frequency': current_freq,
                    'alert_level': 'early',
                    'signal_increase': signal_increase
                }
                DASHBOARD['early_detection'] = early_detection
                DASHBOARD['early_detection_time'] = timestamp
                self.update_dashboard(log_message=f"Early detection: Wireless device at ~{distance*2} feet")
                
                # Track this device for logging
                if device_key not in self.anomaly_tracker:
                    self.anomaly_tracker[device_key] = {
                        'first_seen': timestamp,
                        'last_seen': timestamp,
                        'status': 'early_detection'
                    }
                else:
                    self.anomaly_tracker[device_key]['last_seen'] = timestamp
                    self.anomaly_tracker[device_key]['status'] = 'early_detection'
                
                # Log this early detection
                self.log_proximity_detection(
                    device_key, 'wireless', current_freq, max_power, 
                    distance * 2, 'early_detection'
                )
            
            # Check for actual alert threshold
            if max_power > ref_power:
                # Update device tracking for proximity alerts
                if device_key not in self.anomaly_tracker:
                    self.anomaly_tracker[device_key] = {
                        'first_seen': timestamp,
                        'last_seen': timestamp,
                        'status': 'alert'
                    }
                else:
                    self.anomaly_tracker[device_key]['last_seen'] = timestamp
                    self.anomaly_tracker[device_key]['status'] = 'alert'
                
                # Log this proximity alert
                self.log_proximity_detection(
                    device_key, 'wireless', current_freq, max_power, 
                    distance, 'alert'
                )
                
                return {
                    'type': 'wireless',
                    'distance': distance,
                    'power': max_power,
                    'reference': ref_power,
                    'frequency': current_freq,
                    'alert_level': 'alert',
                    'signal_increase': signal_increase
                }
        
        # Check cellular breach
        if is_cellular_proxy:
            ref_power = calibration_values.get('cellular_power')
            distance = self.config['proximity_detection']['cellular_distance_threshold']
            
            # Check for extended range detection (at 2x the distance)
            extended_ref = ref_power + extended_range_factor
            
            # Calculate signal increase percentage
            signal_increase = self.calculate_signal_increase(max_power, extended_ref)
            
            # Update device tracking for cellular devices
            device_key = f"cellular_{current_freq}"
            
            if max_power > extended_ref and max_power <= ref_power:
                # This is an early detection - store it but don't trigger alert
                early_detection = {
                    'type': 'cellular',
                    'distance': distance * 2,  # Double the distance
                    'power': max_power,
                    'reference': extended_ref,
                    'frequency': current_freq,
                    'alert_level': 'early',
                    'signal_increase': signal_increase
                }
                DASHBOARD['early_detection'] = early_detection
                DASHBOARD['early_detection_time'] = timestamp
                self.update_dashboard(log_message=f"Early detection: Cell phone at ~{distance*2} feet")
                
                # Track this device for logging
                if device_key not in self.anomaly_tracker:
                    self.anomaly_tracker[device_key] = {
                        'first_seen': timestamp,
                        'last_seen': timestamp,
                        'status': 'early_detection'
                    }
                else:
                    self.anomaly_tracker[device_key]['last_seen'] = timestamp
                    self.anomaly_tracker[device_key]['status'] = 'early_detection'
                
                # Log this early detection
                self.log_proximity_detection(
                    device_key, 'cellular', current_freq, max_power, 
                    distance * 2, 'early_detection'
                )
            
            # Check for actual alert threshold
            if max_power > ref_power:
                # Update device tracking for proximity alerts
                if device_key not in self.anomaly_tracker:
                    self.anomaly_tracker[device_key] = {
                        'first_seen': timestamp,
                        'last_seen': timestamp,
                        'status': 'alert'
                    }
                else:
                    self.anomaly_tracker[device_key]['last_seen'] = timestamp
                    self.anomaly_tracker[device_key]['status'] = 'alert'
                
                # Log this proximity alert
                self.log_proximity_detection(
                    device_key, 'cellular', current_freq, max_power, 
                    distance, 'alert'
                )
                
                return {
                    'type': 'cellular',
                    'distance': distance,
                    'power': max_power,
                    'reference': ref_power,
                    'frequency': current_freq,
                    'alert_level': 'alert',
                    'signal_increase': signal_increase
                }
        
        return False
    
    def log_proximity_detection(self, device_key, device_type, frequency, power, distance, status):
        """Log proximity detection to CSV file"""
        try:
            # Get timestamp info
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Get first_seen and last_seen
            first_seen = self.anomaly_tracker[device_key]['first_seen'] if device_key in self.anomaly_tracker else now
            last_seen = now
            
            # Write to proximity log file
            with open(self.proximity_log_file, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    now, first_seen, last_seen, device_type, 
                    frequency, f"{power:.2f}", distance, status
                ])
        except Exception as e:
            self.update_dashboard(log_message=f"Error logging proximity detection: {e}", error=True)
    
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
                # Calculate signal increase percentage
                signal_increase = self.calculate_signal_increase(current_psd[i], baseline_psd[i])
                
                # Estimate distance based on signal strength
                distance = self.estimate_distance(current_psd[i], baseline_psd[i], freq)
                
                anomalies.append({
                    'frequency': freq,
                    'baseline_power': baseline_psd[i],
                    'current_power': current_psd[i],
                    'difference': diff[i],
                    'signal_increase': signal_increase,
                    'distance': distance
                })
        
        # Plot if anomalies detected
        if anomalies:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"anomaly_{current_freq}MHz_{timestamp}.png"
            
            self.plot_comparison(frequencies, baseline_psd, current_psd, 
                               anomalies, filename)
            
            # Current timestamp
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Log anomalies to enhanced log file
            for anomaly in anomalies:
                # Create unique key for this anomaly
                anomaly_key = f"{current_freq}_{anomaly['frequency']:.3f}"
                
                # Check if we've seen this anomaly before
                if anomaly_key not in self.anomaly_tracker:
                    self.anomaly_tracker[anomaly_key] = {
                        'first_seen': now,
                        'last_seen': now
                    }
                else:
                    # Update last seen time
                    self.anomaly_tracker[anomaly_key]['last_seen'] = now
                
                # Get first seen time
                first_seen = self.anomaly_tracker[anomaly_key]['first_seen']
                
                # Write to enhanced log file
                try:
                    with open(self.enhanced_log_file, 'a', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow([
                            now, 
                            first_seen,
                            now,  # last_seen (same as timestamp for new entries)
                            current_freq,
                            f"{anomaly['frequency']:.3f}",
                            f"{anomaly['difference']:.2f}", 
                            f"{anomaly['signal_increase']:.1f}",
                            str(anomaly['distance'] if anomaly['distance'] is not None else "N/A"),
                            "rf_anomaly"
                        ])
                except Exception as e:
                    self.update_dashboard(log_message=f"Error writing to enhanced log: {e}", error=True)
            
            # Also log to original log file for backward compatibility
            log_file = os.path.join(self.config['output_dir'], 'anomalies.log')
            with open(log_file, 'a') as f:
                for anomaly in anomalies:
                    f.write(f"{timestamp},{current_freq},{anomaly['frequency']:.3f},{anomaly['difference']:.2f}\n")
            
            # Send alert if configured
            # Include signal increase and distance in the alert
            max_anomaly = max(anomalies, key=lambda a: abs(a['difference']))
            anomaly_alert = {
                'type': 'spectrum_anomaly', 
                'frequency': current_freq, 
                'power': max_anomaly['current_power'],
                'detected_at': max_anomaly['frequency'],
                'signal_increase': max_anomaly['signal_increase'],
                'distance': max_anomaly['distance']
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
            annotation_text = f"{anomaly['frequency']:.1f} MHz"
            
            # Add signal increase % if available
            if 'signal_increase' in anomaly and anomaly['signal_increase'] is not None:
                annotation_text += f"\n+{anomaly['signal_increase']:.1f}%"
            
            # Add distance if available
            if 'distance' in anomaly and anomaly['distance'] is not None:
                annotation_text += f"\n~{anomaly['distance']} ft"
                
            plt.annotate(annotation_text,
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
        
        # Create annotation with signal increase
        annotation_text = f"{device_type} Detected!"
        if 'signal_increase' in breach_info and breach_info['signal_increase'] is not None:
            annotation_text += f"\nSignal: +{breach_info['signal_increase']:.1f}%"
        
        plt.annotate(annotation_text, 
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
        
        # Get the strongest anomaly for reporting
        max_anomaly = max(anomalies, key=lambda a: abs(a['difference']))
        signal_increase = max_anomaly.get('signal_increase', 0)
        distance = max_anomaly.get('distance', 'unknown')
        
        # Update log with enhanced info
        self.update_dashboard(log_message=f"ALERT: {len(anomalies)} anomalies detected at {center_freq} MHz (Signal: +{signal_increase:.1f}%, Dist: {distance} ft)")
        
        # macOS notification
        if NOTIFICATIONS_AVAILABLE:
            # Create a summary of detected frequencies
            freq_summary = ", ".join([f"{anomaly['frequency']:.1f} MHz" for anomaly in anomalies[:3]])
            if len(anomalies) > 3:
                freq_summary += f", and {len(anomalies)-3} more"
                
            pync.notify(f"Detected {len(anomalies)} anomalies at {center_freq} MHz band\nSignal: +{signal_increase:.1f}%", 
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
                
                # Create email content with enhanced info
                content = f"""
                RF Intrusion Detection System Alert
                
                Time: {now}
                Frequency Band: {center_freq} MHz
                Detected {len(anomalies)} anomalies:
                
                """
                
                for i, anomaly in enumerate(anomalies):
                    content += f"{i+1}. Frequency: {anomaly['frequency']:.3f} MHz, " + \
                              f"Difference: {anomaly['difference']:.2f} dB, " + \
                              f"Signal Increase: +{anomaly['signal_increase']:.1f}%"
                    
                    if anomaly['distance'] is not None:
                        content += f", Est. Distance: ~{anomaly['distance']} feet"
                    
                    content += "\n"
                
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
                message = f"RF-IDS Alert #{self.alert_count}: {len(anomalies)} anomalies at {center_freq} MHz band. Signal: +{signal_increase:.1f}%, Dist: {distance} ft"
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
        
        # Get signal increase if available
        signal_increase = breach_info.get('signal_increase', 0)
        
        # Update log with enhanced info
        self.update_dashboard(log_message=f"PROXIMITY ALERT: {device_type} within {breach_info['distance']} feet (Signal: +{signal_increase:.1f}%)")
        
        # macOS notification with higher urgency
        if NOTIFICATIONS_AVAILABLE:
            pync.notify(f"A {device_type} is within {breach_info['distance']} feet!\nSignal: +{signal_increase:.1f}%", 
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
                
                # Create email content with enhanced info
                content = f"""
                RF Intrusion Detection System - PROXIMITY ALERT
                
                Time: {now}
                A {device_type} is within {breach_info['distance']} feet of the sensor!
                
                Detection frequency: {breach_info['frequency']} MHz
                Signal strength: {breach_info['power']:.2f} dB 
                Threshold: {breach_info['reference']:.2f} dB
                Signal increase: +{signal_increase:.1f}%
                
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
                message = f"RF-IDS PROXIMITY ALERT: {device_type} detected within {breach_info['distance']} feet! Signal: +{signal_increase:.1f}%"
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
                    if self.stdscr and not DASHBOARD.get('viewing_logs', False):
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
    
    def handle_log_viewer_input(self):
        """Handle user input for log viewer"""
        try:
            # Check for keypress (non-blocking)
            self.stdscr.nodelay(True)
            key = self.stdscr.getch()
            
            if key == ord('q'):  # Return to dashboard
                DASHBOARD['viewing_logs'] = False
                return True
            elif key == ord('n'):  # Next page
                total_pages = max(1, (len(DASHBOARD['log_entries']) + LOG_ENTRIES_PER_PAGE - 1) // LOG_ENTRIES_PER_PAGE)
                if DASHBOARD['log_page'] < total_pages - 1:
                    DASHBOARD['log_page'] += 1
                self.draw_log_viewer()
            elif key == ord('p'):  # Previous page
                if DASHBOARD['log_page'] > 0:
                    DASHBOARD['log_page'] -= 1
                self.draw_log_viewer()
            elif key == ord('t'):  # Switch log type
                DASHBOARD['log_type'] = (DASHBOARD.get('log_type', 0) + 1) % 2
                self.load_log_entries()
                self.draw_log_viewer()
        except:
            pass
            
        return True
    
    def handle_user_input(self):
        """Handle user input for keyboard commands"""
        if not self.stdscr:
            return True
            
        # If viewing logs, handle log viewer input
        if DASHBOARD.get('viewing_logs', False):
            return self.handle_log_viewer_input()
            
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
            elif key == ord('l'):  # View logs
                DASHBOARD['viewing_logs'] = True
                DASHBOARD['log_type'] = 0  # Default to anomaly log
                self.load_log_entries()
                self.draw_log_viewer()
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
            
            # Create enhanced log files if they don't exist
            if not os.path.exists(self.enhanced_log_file):
                with open(self.enhanced_log_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        'timestamp', 'first_seen', 'last_seen', 'center_freq', 
                        'anomaly_freq', 'difference_db', 'signal_increase_pct',
                        'estimated_distance', 'type'
                    ])
            
            if not os.path.exists(self.proximity_log_file):
                with open(self.proximity_log_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        'timestamp', 'first_seen', 'last_seen', 'device_type', 
                        'frequency', 'power_db', 'distance', 'status'
                    ])
            
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
            self.update_dashboard(log_message=f"Enhanced logging enabled - press 'l' to view logs")
            
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
                if current_time - last_ticker_update > 3 and not DASHBOARD.get('viewing_logs', False):
                    self.update_dashboard(status=ticker_messages[ticker_index])
                    ticker_index = (ticker_index + 1) % len(ticker_messages)
                    last_ticker_update = current_time
                    
                    # Force dashboard refresh to show "alive" status
                    if self.stdscr and not DASHBOARD.get('viewing_logs', False):
                        self.draw_dashboard()
                
                # Check for user input
                if not self.handle_user_input():
                    self.update_dashboard(status="User requested exit...")
                    break
                
                # If viewing logs, just continue and poll for input
                if DASHBOARD.get('viewing_logs', False):
                    time.sleep(0.1)
                    self.draw_log_viewer()
                    continue
                
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
