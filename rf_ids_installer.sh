#!/bin/bash
# RF-IDS Installer for macOS
# This script automates the installation of a RF-based Intrusion Detection System

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
NC="\033[0m" # No Color

# Installation directory
INSTALL_DIR="$HOME/rf_ids"
LAUNCH_AGENT_DIR="$HOME/Library/LaunchAgents"
LAUNCH_AGENT_FILE="com.user.rfids.plist"

echo -e "${BOLD}${BLUE}============================================${NC}"
echo -e "${BOLD}${BLUE}  RF Intrusion Detection System Installer   ${NC}"
echo -e "${BOLD}${BLUE}============================================${NC}"
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to show progress
show_progress() {
    echo -e "${YELLOW}$1...${NC}"
}

# Function to show success
show_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Function to show error and exit
show_error() {
    echo -e "${RED}✗ $1${NC}"
    exit 1
}

# Function to ask yes/no question
ask_yes_no() {
    while true; do
        read -p "$1 (y/n): " yn
        case $yn in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer yes (y) or no (n).";;
        esac
    done
}

# Create installation directory
show_progress "Creating installation directory"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR" || show_error "Failed to create installation directory"
show_success "Installation directory created at $INSTALL_DIR"

# Check for Homebrew and install if missing
if ! command_exists brew; then
    show_progress "Installing Homebrew"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || show_error "Failed to install Homebrew"
    show_success "Homebrew installed"
    
    # Add Homebrew to PATH for current session
    if [[ $(uname -m) == "arm64" ]]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    else
        eval "$(/usr/local/bin/brew shellenv)"
    fi
else
    show_success "Homebrew already installed"
fi

# Install RTL-SDR drivers and utilities
show_progress "Installing RTL-SDR libraries and drivers"
brew install librtlsdr rtl-sdr || show_error "Failed to install RTL-SDR libraries"
show_success "RTL-SDR libraries installed"

# Install required applications
show_progress "Installing required applications (this might take a while)"
brew install gnuradio || show_error "Failed to install GNU Radio"
brew install --cask gqrx || echo "Note: GQRX installation skipped or failed, but we can continue"
show_success "Applications installed"

# Set up Python environment
show_progress "Setting up Python environment"
brew install python3 || show_error "Failed to install Python"

# Install Python packages
show_progress "Checking Python packages"

# Function to check if a Python package is installed
check_python_package() {
    python3 -c "import $1" 2>/dev/null
    return $?
}

# Check which packages need to be installed
MISSING_PACKAGES=()
for package in numpy scipy matplotlib rtlsdr setuptools pync; do
    if ! check_python_package $package; then
        MISSING_PACKAGES+=($package)
    fi
done

# Convert rtlsdr to pyrtlsdr for pip
MISSING_PIP_PACKAGES=("${MISSING_PACKAGES[@]}")
for i in "${!MISSING_PIP_PACKAGES[@]}"; do
    if [ "${MISSING_PIP_PACKAGES[$i]}" = "rtlsdr" ]; then
        MISSING_PIP_PACKAGES[$i]="pyrtlsdr"
    fi
done

# Only install missing packages
if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
    echo -e "${YELLOW}The following packages need to be installed: ${MISSING_PACKAGES[*]}${NC}"
    
    # Try to install with --user flag to avoid permission issues
    show_progress "Installing missing Python packages"
    python3 -m pip install --user "${MISSING_PIP_PACKAGES[@]}" || {
        echo -e "${YELLOW}Installation with regular pip failed. Trying with sudo...${NC}"
        echo -e "${YELLOW}You may be prompted for your password.${NC}"
        sudo python3 -m pip install "${MISSING_PIP_PACKAGES[@]}" || {
            echo -e "${RED}Failed to install packages with sudo as well.${NC}"
            echo -e "${YELLOW}You can continue but may encounter issues when running the program.${NC}"
            if ask_yes_no "Do you want to continue with the installation?"; then
                echo "Continuing installation..."
            else
                show_error "Installation aborted due to package installation failure."
            fi
        }
    }
else
    echo -e "${GREEN}All required Python packages are already installed.${NC}"
fi

show_success "Python environment configured"

# Create RF-IDS Python script
show_progress "Creating RF-IDS script"
cat > "$INSTALL_DIR/rf_ids.py" << 'EOF'
#!/usr/bin/env python3
"""
RF-based Intrusion Detection System for macOS using RTL-SDR
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

# For macOS notifications
try:
    import pync
    NOTIFICATIONS_AVAILABLE = True
except ImportError:
    NOTIFICATIONS_AVAILABLE = False

class RFIntrusionDetector:
    def __init__(self, config_file='config.json'):
        # Load configuration
        self.load_config(config_file)
        
        # Check if we should run interactive setup
        if self.config.get('run_setup', False):
            self.config = self.setup_initial_config()
            
        # Initialize SDR
        try:
            self.sdr = RtlSdr()
            self.sdr.sample_rate = self.config['sample_rate']
            self.sdr.center_freq = self.config['center_freq']
            self.sdr.gain = self.config['gain']
        except Exception as e:
            print(f"Error initializing RTL-SDR: {e}")
            print("Please make sure your RTL-SDR device is connected and recognized by your system.")
            if NOTIFICATIONS_AVAILABLE:
                pync.notify("Error initializing RTL-SDR. Please check connection.", 
                          title="RF-IDS Error", 
                          sound="Basso")
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
    
    def setup_initial_config(self):
        """Interactive setup for first-time configuration"""
        print("\n" + "="*60)
        print("Welcome to RF Intrusion Detection System - First-time Setup")
        print("="*60 + "\n")
        
        print("Let's configure your monitoring preferences.\n")
        
        # Default configuration
        config = {
            'sample_rate': 2.4e6,       # Sample rate
            'center_freq': 915e6,       # Center frequency
            'gain': 'auto',             # Gain setting
            'fft_size': 1024,           # FFT size
            'num_samples': 256000,      # Number of samples to collect
            'threshold': 15,            # Anomaly threshold in dB
            'scan_interval': 5,         # Seconds between scans
            'output_dir': 'rf_ids_data',# Output directory
            'baseline_samples': 10,     # Number of samples for baseline
            'force_new_baseline': False,# Force new baseline calculation
            'frequencies': [],          # Frequencies to monitor (in MHz)
            'email_alerts': False,      # Send email alerts
            'proximity_detection': {
                'enabled': True,
                'bluetooth_distance_threshold': 10,  # feet
                'cellular_distance_threshold': 15,   # feet
                'calibration_needed': True
            },
            'email': {
                'sender': '',
                'recipient': '',
                'password': '',
                'server': 'smtp.gmail.com',
                'port': 587
            }
        }
        
        # Frequency band selection
        print("Which frequency bands would you like to monitor?")
        
        freq_options = [
            ("WiFi Channel 1 (2412 MHz)", 2412),
            ("WiFi Channel 6 (2437 MHz)", 2437),
            ("WiFi Channel 11 (2462 MHz)", 2462),
            ("Bluetooth (2480 MHz)", 2480),
            ("ISM Band (915 MHz)", 915),
            ("ISM Band (433 MHz)", 433),
            ("ISM Band (868 MHz)", 868),
            ("ZigBee/Smart Home (2405 MHz)", 2405),
            ("Wireless Mics (600-700 MHz)", 675),
            ("Cellular (700-800 MHz)", 750),
            ("Cellular (850 MHz)", 850),
            ("Cellular (1900 MHz)", 1900)
        ]
        
        for i, (name, freq) in enumerate(freq_options, 1):
            print(f"{i}. {name}")
        
        print("\nEnter the numbers of the frequencies you want to monitor, separated by commas")
        print("Example: 1,2,3")
        selection = input("Selection [1,2,3,4,5,10,11]: ").strip() or "1,2,3,4,5,10,11"
        
        try:
            selected_indices = [int(x.strip()) - 1 for x in selection.split(",")]
            for idx in selected_indices:
                if 0 <= idx < len(freq_options):
                    config['frequencies'].append(freq_options[idx][1])
        except:
            print("Invalid selection. Using default WiFi, Bluetooth and Cellular bands.")
            config['frequencies'] = [2412, 2437, 2462, 2480, 750, 850, 1900]
        
        # Ensure Bluetooth and Cellular frequencies are included for proximity detection
        if config['proximity_detection']['enabled']:
            essential_freqs = {
                'bluetooth': 2480,
                'cellular1': 750,
                'cellular2': 850,
                'cellular3': 1900
            }
            
            for freq_type, freq in essential_freqs.items():
                if freq not in config['frequencies']:
                    config['frequencies'].append(freq)
                    print(f"Added {freq_type} frequency ({freq} MHz) for proximity detection.")
        
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
        
        # Proximity detection
        print("\nWould you like to enable proximity detection for Bluetooth devices and cell phones?")
        print("This feature will alert you when devices get too close to your location.")
        proximity_choice = input("Enable proximity detection? (y/n) [y]: ").strip().lower() or "y"
        
        if proximity_choice == "y":
            config['proximity_detection']['enabled'] = True
            
            print("\nProximity alert distances:")
            try:
                bt_distance = float(input("Bluetooth alert distance in feet [10]: ").strip() or "10")
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
        else:
            config['proximity_detection']['enabled'] = False
        
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
        return config
    
    def load_config(self, config_file):
        """Load configuration from JSON file or set up interactively"""
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
                print(f"Loaded configuration from {config_file}")
        except FileNotFoundError:
            print(f"Configuration file not found: {config_file}")
            self.config = self.setup_initial_config()
    
    def capture_spectrum(self):
        """Capture RF spectrum data"""
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
    
    def create_baseline(self):
        """Create baseline RF spectrum for comparison"""
        print("Creating baseline RF spectrum profile...")
        baseline_data = []
        
        for i in range(self.config['baseline_samples']):
            print(f"Collecting baseline sample {i+1}/{self.config['baseline_samples']}")
            frequencies, psd = self.capture_spectrum()
            baseline_data.append(psd)
            time.sleep(1)
        
        # Average the samples to create baseline
        self.baseline = {
            'frequencies': frequencies,
            'psd_mean': np.mean(baseline_data, axis=0),
            'psd_std': np.std(baseline_data, axis=0),
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        # Save baseline
        with open(self.baseline_file, 'wb') as f:
            pickle.dump(self.baseline, f)
        
        print(f"Baseline created and saved to {self.baseline_file}")
        
        # Plot baseline
        self.plot_spectrum(frequencies, self.baseline['psd_mean'], 
                          title="RF Baseline Spectrum", 
                          filename="baseline_spectrum.png")
                          
        # Send macOS notification
        if NOTIFICATIONS_AVAILABLE:
            pync.notify("Baseline RF profile has been created successfully.", 
                      title="RF-IDS Setup Complete", 
                      sound="Glass")
    
    def load_baseline(self):
        """Load baseline from file"""
        try:
            with open(self.baseline_file, 'rb') as f:
                self.baseline = pickle.load(f)
            print(f"Loaded baseline from {self.baseline_file}")
            print(f"Baseline created on: {self.baseline['timestamp']}")
        except Exception as e:
            print(f"Error loading baseline: {e}")
            self.baseline = None
    
    def check_proximity_breach(self, frequency, current_psd):
        """Check if a device is too close based on signal strength"""
        if not self.config.get('proximity_detection', {}).get('enabled', False):
            return False
        
        # Skip if not calibrated
        if self.config.get('proximity_detection', {}).get('calibration_needed', True):
            return False
        
        # Check which frequency type we're monitoring
        is_bluetooth = abs(frequency - 2480) < 10  # Bluetooth frequency
        is_cellular = any(abs(frequency - cell_freq) < 10 for cell_freq in [750, 850, 1900])
        
        if not (is_bluetooth or is_cellular):
            return False  # Not a frequency we're checking for proximity
        
        # Get the max power in this band
        max_power = np.max(current_psd)
        
        if is_bluetooth:
            ref_power = self.config['proximity_detection']['bluetooth_reference_power']
            distance = self.config['proximity_detection']['bluetooth_distance_threshold']
            if max_power > ref_power:
                return {
                    'type': 'bluetooth',
                    'distance': distance,
                    'power': max_power,
                    'reference': ref_power
                }
                
        if is_cellular:
            ref_power = self.config['proximity_detection']['cellular_reference_power']
            distance = self.config['proximity_detection']['cellular_distance_threshold']
            if max_power > ref_power:
                return {
                    'type': 'cellular',
                    'distance': distance,
                    'power': max_power,
                    'reference': ref_power
                }
        
        return False
    
    def scan_for_intrusions(self):
        """Scan RF spectrum and detect anomalies"""
        if self.baseline is None:
            print("No baseline available. Creating new baseline.")
            self.create_baseline()
            return False
        
        # Capture current spectrum
        frequencies, current_psd = self.capture_spectrum()
        
        # First check for proximity breaches (takes priority)
        proximity_breach = self.check_proximity_breach(self.sdr.center_freq/1e6, current_psd)
        if proximity_breach:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"proximity_{proximity_breach['type']}_{timestamp}.png"
            
            # Log proximity breach
            log_file = os.path.join(self.config['output_dir'], 'proximity_alerts.log')
            with open(log_file, 'a') as f:
                f.write(f"{timestamp},{proximity_breach['type']},{proximity_breach['distance']},{proximity_breach['power']:.2f}\n")
            
            # Plot the spectrum showing the breach
            self.plot_proximity_breach(frequencies, current_psd, proximity_breach, filename)
            
            # Alert for proximity breach
            self.send_proximity_alert(proximity_breach, filename)
            return True
        
        # If no proximity breach, check regular anomalies
        # Compare with baseline
        diff = current_psd - self.baseline['psd_mean']
        
        # Find frequencies that exceed threshold
        threshold = self.config['threshold']
        anomalies = []
        
        for i, freq in enumerate(frequencies):
            if abs(diff[i]) > threshold:
                anomalies.append({
                    'frequency': freq,
                    'baseline_power': self.baseline['psd_mean'][i],
                    'current_power': current_psd[i],
                    'difference': diff[i]
                })
        
        # Plot if anomalies detected
        if anomalies:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"anomaly_{timestamp}.png"
            
            self.plot_comparison(frequencies, self.baseline['psd_mean'], current_psd, 
                               anomalies, filename)
            
            # Log anomalies
            log_file = os.path.join(self.config['output_dir'], 'anomalies.log')
            with open(log_file, 'a') as f:
                for anomaly in anomalies:
                    f.write(f"{timestamp},{anomaly['frequency']:.3f},{anomaly['difference']:.2f}\n")
            
            # Send alert if configured
            self.send_alert(anomalies, filename)
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
        
        device_type = "Bluetooth Device" if breach_info['type'] == 'bluetooth' else "Cell Phone"
        
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
    
    def send_alert(self, anomalies, image_filename=None):
        """Send alert with anomaly information"""
        now = datetime.datetime.now()
        
        # Check if we should throttle alerts (no more than 1 per 5 minutes)
        if (now - self.last_alert_time).total_seconds() < 300:
            return
        
        self.last_alert_time = now
        self.alert_count += 1
        
        # Print to console
        print("\n" + "="*50)
        print(f"⚠️  ALERT #{self.alert_count}: RF Anomalies Detected!")
        print("="*50)
        print(f"Time: {now}")
        print(f"Detected {len(anomalies)} anomalies:")
        
        for i, anomaly in enumerate(anomalies):
            print(f"  {i+1}. Frequency: {anomaly['frequency']:.3f} MHz, " +
                  f"Difference: {anomaly['difference']:.2f} dB")
        
        if image_filename:
            print(f"Spectrum saved to: {os.path.join(self.config['output_dir'], image_filename)}")
        
        print("="*50 + "\n")
        
        # macOS notification
        if NOTIFICATIONS_AVAILABLE:
            # Create a summary of detected frequencies
            freq_summary = ", ".join([f"{anomaly['frequency']:.1f} MHz" for anomaly in anomalies[:3]])
            if len(anomalies) > 3:
                freq_summary += f", and {len(anomalies)-3} more"
                
            pync.notify(f"Detected {len(anomalies)} anomalies: {freq_summary}", 
                     title=f"RF-IDS Alert #{self.alert_count}", 
                     sound="Basso",
                     open=os.path.join(self.config['output_dir'], image_filename))
        
        # Send email if configured
        if self.config['email_alerts']:
            try:
                msg = EmailMessage()
                msg['Subject'] = f'RF-IDS Alert: {len(anomalies)} anomalies detected'
                msg['From'] = self.config['email']['sender']
                msg['To'] = self.config['email']['recipient']
                
                # Create email content
                content = f"""
                RF Intrusion Detection System Alert
                
                Time: {now}
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
                
                print("Alert email sent successfully")
            
            except Exception as e:
                print(f"Failed to send email alert: {e}")
    
    def send_proximity_alert(self, breach_info, image_filename=None):
        """Send alert specifically for proximity breaches"""
        now = datetime.datetime.now()
        
        # Check if we should throttle alerts (no more than 1 per minute for proximity)
        if (now - self.last_alert_time).total_seconds() < 60:
            return
        
        self.last_alert_time = now
        self.alert_count += 1
        
        # Determine device type for readable message
        device_type = "Bluetooth device" if breach_info['type'] == 'bluetooth' else "Cell phone"
        
        # Print to console
        print("\n" + "="*50)
        print(f"⚠️  PROXIMITY ALERT #{self.alert_count}: {device_type.upper()} DETECTED!")
        print("="*50)
        print(f"Time: {now}")
        print(f"A {device_type} is within {breach_info['distance']} feet of the sensor!")
        print(f"Signal strength: {breach_info['power']:.2f} dB (threshold: {breach_info['reference']:.2f} dB)")
        
        if image_filename:
            print(f"Spectrum saved to: {os.path.join(self.config['output_dir'], image_filename)}")
        
        print("="*50 + "\n")
        
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
                
                print("Alert email sent successfully")
            
            except Exception as e:
                print(f"Failed to send email alert: {e}")
    
    def calibrate_proximity_detection(self):
        """Calibrate the system for proximity detection"""
        print("\n" + "="*60)
        print("Proximity Detection Calibration")
        print("="*60)
        print("\nThis process will calibrate the system to detect devices within specific distances.")
        print("You'll need a Bluetooth device and/or a cell phone for this calibration.")
        
        # Initialize calibration values
        bluetooth_calibration = None
        cellular_calibration = None
        
        # Calibrate Bluetooth distance
        bt_distance = self.config['proximity_detection']['bluetooth_distance_threshold']
        print(f"\n[Bluetooth Calibration for {bt_distance} feet]")
        print(f"1. Place a Bluetooth device exactly {bt_distance} feet away from your RTL-SDR antenna")
        print("2. Make sure the device is powered on and discoverable")
        input("Press Enter when ready...")
        
        print("\nScanning for Bluetooth signals...")
        # Set to Bluetooth frequency
        self.sdr.center_freq = 2480e6
        # Scan multiple times to get reliable readings
        bluetooth_readings = []
        for i in range(5):
            print(f"Scan {i+1}/5...")
            samples = self.sdr.read_samples(self.config['num_samples'])
            frequencies, psd = signal.welch(
                samples, 
                fs=self.sdr.sample_rate/1e6, 
                nperseg=self.config['fft_size'],
                scaling='density'
            )
            psd_db = 10 * np.log10(psd)
            # Get max power in the Bluetooth range
            bluetooth_readings.append(np.max(psd_db))
            time.sleep(1)
        
        # Average the readings and add a small buffer
        bluetooth_calibration = np.mean(bluetooth_readings) + 2  # 2dB buffer
        print(f"Bluetooth calibration complete. Reference power: {bluetooth_calibration:.2f} dB")
        
        # Calibrate Cellular distance
        cell_distance = self.config['proximity_detection']['cellular_distance_threshold']
        print(f"\n[Cellular Calibration for {cell_distance} feet]")
        print(f"1. Place a cell phone exactly {cell_distance} feet away from your RTL-SDR antenna")
        print("2. Make sure the phone is on and has cellular signal")
        print("3. Optionally, make a call or use data to increase signal strength")
        input("Press Enter when ready...")
        
        print("\nScanning for Cellular signals...")
        # Try different cellular frequencies
        cellular_freqs = [750, 850, 1900]  # MHz
        max_cellular_reading = -float('inf')
        
        for freq in cellular_freqs:
            print(f"Scanning frequency {freq} MHz...")
            self.sdr.center_freq = freq * 1e6
            readings = []
            for i in range(3):
                samples = self.sdr.read_samples(self.config['num_samples'])
                frequencies, psd = signal.welch(
                    samples, 
                    fs=self.sdr.sample_rate/1e6, 
                    nperseg=self.config['fft_size'],
                    scaling='density'
                )
                psd_db = 10 * np.log10(psd)
                readings.append(np.max(psd_db))
                time.sleep(1)
            avg_reading = np.mean(readings)
            if avg_reading > max_cellular_reading:
                max_cellular_reading = avg_reading
        
        # Add buffer to cellular reading
        cellular_calibration = max_cellular_reading + 2  # 2dB buffer
        print(f"Cellular calibration complete. Reference power: {cellular_calibration:.2f} dB")
        
        # Save calibration values
        self.config['proximity_detection']['bluetooth_reference_power'] = bluetooth_calibration
        self.config['proximity_detection']['cellular_reference_power'] = cellular_calibration
        self.config['proximity_detection']['calibration_needed'] = False
        
        # Save updated config
        with open('config.json', 'w') as f:
            json.dump(self.config, f, indent=4)
        
        print("\nCalibration complete! The system will now be able to detect devices within:")
        print(f"- Bluetooth devices: {bt_distance} feet")
        print(f"- Cellular devices: {cell_distance} feet")
        print("="*60 + "\n")
    
    def monitor_frequency(self, frequency):
        """Monitor a specific frequency"""
        self.sdr.center_freq = frequency * 1e6
        print(f"Monitoring frequency: {frequency} MHz")
        return self.scan_for_intrusions()
    
    def run(self):
        """Run continuous monitoring"""
        try:
            # Check if proximity detection is enabled and needs calibration
            if self.config.get('proximity_detection', {}).get('enabled', False) and \
               self.config.get('proximity_detection', {}).get('calibration_needed', True):
                self.calibrate_proximity_detection()
            
            # Create baseline if needed
            if self.baseline is None:
                self.create_baseline()
            
            print("\nStarting RF intrusion detection system...")
            print(f"Monitoring {len(self.config['frequencies'])} frequencies")
            print(f"Scan interval: {self.config['scan_interval']} seconds")
            
            # Print proximity detection status if enabled
            if self.config.get('proximity_detection', {}).get('enabled', False):
                print(f"Proximity detection enabled:")
                print(f"  - Bluetooth alert distance: {self.config['proximity_detection']['bluetooth_distance_threshold']} feet")
                print(f"  - Cellular alert distance: {self.config['proximity_detection']['cellular_distance_threshold']} feet")
            
            print("Press Ctrl+C to stop\n")
            
            # Send startup notification
            if NOTIFICATIONS_AVAILABLE:
                pync.notify(f"Monitoring {len(self.config['frequencies'])} frequencies", 
                          title="RF-IDS Started", 
                          sound="Glass")
            
            while True:
                for freq in self.config['frequencies']:
                    detected = self.monitor_frequency(freq)
                    if detected:
                        # Increase scan rate temporarily if anomaly detected
                        time.sleep(1)
                    else:
                        time.sleep(self.config['scan_interval'])
        
        except KeyboardInterrupt:
            print("\nStopping RF intrusion detection system...")
            if NOTIFICATIONS_AVAILABLE:
                pync.notify("System stopped by user", 
                          title="RF-IDS Stopped", 
                          sound="Submarine")
        
        finally:
            self.sdr.close()
            print("SDR device closed")
    
    def close(self):
        """Clean up resources"""
        self.sdr.close()

def main():
    # Create and run the detector
    detector = RFIntrusionDetector()
    detector.run()

if __name__ == "__main__":
    main()
EOF
chmod +x "$INSTALL_DIR/rf_ids.py"
show_success "RF-IDS script created"

# Ask about proximity detection
if ask_yes_no "Would you like to enable proximity detection for Bluetooth devices and cell phones?"; then
    PROXIMITY_ENABLED=true
    
    echo -e "\n${BOLD}Proximity detection settings:${NC}"
    read -p "Bluetooth alert distance in feet [10]: " BT_DISTANCE
    BT_DISTANCE=${BT_DISTANCE:-10}
    
    read -p "Cell phone alert distance in feet [15]: " CELL_DISTANCE
    CELL_DISTANCE=${CELL_DISTANCE:-15}
    
    echo -e "${YELLOW}Note: You'll need to calibrate the system on first run by placing devices at these distances.${NC}"
else
    PROXIMITY_ENABLED=false
    BT_DISTANCE=10
    CELL_DISTANCE=15
fi

# Ask if the user wants a guided setup or automatic config
if ask_yes_no "Would you like to run the guided setup now to configure the system? (Recommended)"; then
    # Create a minimal starter config that will trigger the interactive setup
    cat > "$INSTALL_DIR/config.json" << EOF
{
    "sample_rate": 2.4e6,
    "force_new_baseline": true,
    "run_setup": true,
    "proximity_detection": {
        "enabled": true,
        "calibration_needed": true
    }
}
EOF
    show_success "Setup will run interactively when you start the system"
else
    # Interactive configuration setup
    show_progress "Setting up configuration"

    # Default config values
    THRESHOLD=12
    SCAN_INTERVAL=5
    EMAIL_ALERTS=false
    SENDER_EMAIL="your_email@gmail.com"
    RECIPIENT_EMAIL="your_email@gmail.com"
    EMAIL_PASSWORD="your_app_password"
    EMAIL_SERVER="smtp.gmail.com"
    EMAIL_PORT=587

    # Arrays for frequency selection
    declare -a FREQ_NAMES=(
        "WiFi (2.4GHz channels)" 
        "Bluetooth" 
        "Common ISM band (915MHz)" 
        "Common ISM band (433MHz)" 
        "Common ISM band (868MHz)" 
        "ZigBee/Smart Home" 
        "Car key fobs"
        "Wireless microphones"
    )
    declare -a FREQ_VALUES=(
        "2412,2437,2462" 
        "2480" 
        "915" 
        "433" 
        "868" 
        "2405" 
        "315,433" 
        "600,722"
    )
    declare -a SELECTED_FREQS=()

    # Ask about frequency bands to monitor
    echo -e "\n${BOLD}Which frequency bands would you like to monitor?${NC}"
    echo "Select the options that apply to your security needs:"

    for i in "${!FREQ_NAMES[@]}"; do
        if ask_yes_no "  ${FREQ_NAMES[$i]}"; then
            SELECTED_FREQS+=("${FREQ_VALUES[$i]}")
        fi
    done

    # Make sure at least one frequency is selected
    if [ ${#SELECTED_FREQS[@]} -eq 0 ]; then
        echo -e "${YELLOW}No frequencies selected. Adding default WiFi channels.${NC}"
        SELECTED_FREQS+=("2412,2437,2462")
    fi

    # Convert selected frequencies to a flat array
    IFS=',' read -ra FLAT_FREQS <<< "$(IFS=','; echo "${SELECTED_FREQS[*]}")"
    UNIQUE_FREQS=($(echo "${FLAT_FREQS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

    # Ask about sensitivity
    echo -e "\n${BOLD}Detection sensitivity:${NC}"
    echo "Lower threshold = more sensitive (may cause false positives)"
    echo "Higher threshold = less sensitive (may miss subtle signals)"
    echo "Recommended: 10-15"
    read -p "Enter threshold value [12]: " INPUT_THRESHOLD
    THRESHOLD=${INPUT_THRESHOLD:-12}

    # Ask about scan interval
    echo -e "\n${BOLD}Scan interval:${NC}"
    echo "How often to check each frequency (in seconds)"
    echo "Lower = more frequent checks but higher CPU usage"
    read -p "Enter scan interval in seconds [5]: " INPUT_INTERVAL
    SCAN_INTERVAL=${INPUT_INTERVAL:-5}

    # Ask about email notifications
    if ask_yes_no "Would you like to enable email notifications for alerts?"; then
        EMAIL_ALERTS=true
        
        echo -e "\n${BOLD}Email configuration:${NC}"
        read -p "Sender email address: " SENDER_EMAIL
        read -p "Recipient email address: " RECIPIENT_EMAIL
        read -p "Email password (for app password): " -s EMAIL_PASSWORD
        echo ""
        read -p "SMTP server [smtp.gmail.com]: " INPUT_SERVER
        EMAIL_SERVER=${INPUT_SERVER:-smtp.gmail.com}
        read -p "SMTP port [587]: " INPUT_PORT
        EMAIL_PORT=${INPUT_PORT:-587}
        
        echo -e "\n${YELLOW}Note: For Gmail, you need to create an 'App Password' in your Google Account settings.${NC}"
        echo -e "${YELLOW}See: https://support.google.com/accounts/answer/185833${NC}"
    fi

    # Build frequency array for JSON
    FREQ_JSON=""
    for freq in "${UNIQUE_FREQS[@]}"; do
        if [ -n "$FREQ_JSON" ]; then
            FREQ_JSON+=","
        fi
        FREQ_JSON+="$freq"
    done

    # Create configuration file
    cat > "$INSTALL_DIR/config.json" << EOF
{
    "sample_rate": 2.4e6,
    "center_freq": 915e6,
    "gain": 40,
    "fft_size": 1024,
    "num_samples": 256000,
    "threshold": $THRESHOLD,
    "scan_interval": $SCAN_INTERVAL,
    "output_dir": "rf_ids_data",
    "baseline_samples": 10,
    "force_new_baseline": false,
    "frequencies": [
        $FREQ_JSON
    ],
    "email_alerts": $EMAIL_ALERTS,
    "email": {
        "sender": "$SENDER_EMAIL",
        "recipient": "$RECIPIENT_EMAIL",
        "password": "$EMAIL_PASSWORD",
        "server": "$EMAIL_SERVER",
        "port": $EMAIL_PORT
    },
    "proximity_detection": {
        "enabled": $PROXIMITY_ENABLED,
        "bluetooth_distance_threshold": $BT_DISTANCE,
        "cellular_distance_threshold": $CELL_DISTANCE,
        "calibration_needed": true
    }
}
EOF
    show_success "Configuration file created with your preferences"
fi

# Create launcher script
show_progress "Creating launcher script"
cat > "$INSTALL_DIR/launch_rf_ids.command" << EOF
#!/bin/bash
cd "$INSTALL_DIR"
./rf_ids.py
EOF
chmod +x "$INSTALL_DIR/launch_rf_ids.command"
show_success "Launcher script created"

# Create desktop shortcut
show_progress "Creating desktop shortcut"
ln -sf "$INSTALL_DIR/launch_rf_ids.command" "$HOME/Desktop/RF-IDS.command"
show_success "Desktop shortcut created"

# Ask about autostart
if ask_yes_no "Would you like RF-IDS to start automatically when you log in?"; then
    show_progress "Setting up autostart"
    mkdir -p "$LAUNCH_AGENT_DIR"
    cat > "$LAUNCH_AGENT_DIR/$LAUNCH_AGENT_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.user.rfids</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/rf_ids.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>$INSTALL_DIR/rf_ids_error.log</string>
    <key>StandardOutPath</key>
    <string>$INSTALL_DIR/rf_ids_output.log</string>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
</dict>
</plist>
EOF
    launchctl load "$LAUNCH_AGENT_DIR/$LAUNCH_AGENT_FILE"
    show_success "Autostart configured"
fi

# Final instructions
echo ""
echo -e "${BOLD}${GREEN}============================================${NC}"
echo -e "${BOLD}${GREEN}      Installation Complete!               ${NC}"
echo -e "${BOLD}${GREEN}============================================${NC}"
echo ""
echo -e "Your RF Intrusion Detection System has been installed to: ${BOLD}$INSTALL_DIR${NC}"
echo ""
echo -e "${BOLD}How to use:${NC}"
echo "1. Connect your RTL-SDR device to a USB port"
echo "2. Double-click the 'RF-IDS' icon on your desktop to start"
echo "3. The system will first create a baseline of your RF environment"
echo "4. The interactive dashboard will appear with real-time monitoring"
echo "5. Dashboard features:"
echo "   - Live signal meter and frequency display"
echo "   - Last alert and early detection panels"
echo "   - Monitoring and error logs"
echo "   - Press 'q' to quit, 'r' to reset baseline"
echo ""
echo -e "${BOLD}Files:${NC}"
echo "- Configuration: $INSTALL_DIR/config.json"
echo "- Data directory: $INSTALL_DIR/rf_ids_data"
echo "- Main script: $INSTALL_DIR/rf_ids.py"
echo ""
echo -e "${BOLD}Would you like to start the RF-IDS now?${NC}"

if ask_yes_no "Start RF-IDS now"; then
    show_progress "Starting RF-IDS"
    open "$INSTALL_DIR/launch_rf_ids.command"
    echo ""
    echo -e "${GREEN}RF-IDS has been started in a new Terminal window${NC}"
else
    echo ""
    echo -e "You can start RF-IDS anytime by double-clicking the ${BOLD}RF-IDS${NC} icon on your desktop"
fi

echo ""
echo -e "${BOLD}Thank you for installing RF-IDS!${NC}"
exit 0
