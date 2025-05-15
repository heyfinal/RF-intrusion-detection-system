## 🛡️ Proximity Detection

RF-IDS includes a powerful proximity detection feature that alerts you when wireless devices get too close to your secure area:

- **Bluetooth Proximity Alerts**: Get notified when Bluetooth devices enter within a configurable perimeter (default: 10 feet)
- **Cell Phone Detection**: Receive alerts when cellular devices come within range (default: 15 feet)
- **Guided Calibration**: Easy setup process to calibrate detection for your specific environment
- **Visual Confirmation**: Generates spectrum plots highlighting the detected device signals
- **Priority Alerts**: Proximity alerts take precedence over other detections for immediate response

This feature is ideal for:
- Enforcing "no wireless device" policies in secure areas
- Detecting unauthorized smartphones in restricted zones
- Monitoring for potential eavesdropping devices
- Creating an RF perimeter around sensitive equipment or discussions

![Proximity Detection](https://placeholder-for-proximity-detection.com/image.png)# 📡 RF-IDS: RF Intrusion Detection System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![macOS](https://img.shields.io/badge/platform-macOS-blue.svg)](https://www.apple.com/macos)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![RTL-SDR](https://img.shields.io/badge/hardware-RTL--SDR-red.svg)](https://www.rtl-sdr.com/)

> **Detect unauthorized wireless transmissions and RF-based security threats with an affordable Software Defined Radio setup**

RF-IDS turns your $30 RTL-SDR dongle into a powerful cybersecurity tool that continuously monitors the radio frequency spectrum around you, alerting you to potential security threats like rogue access points, unauthorized transmissions, covert surveillance devices, and wireless exfiltration attempts.

![RF-IDS Demo](https://placeholder-for-rf-ids-screenshot.com/image.png)

## ✨ Features

- 🔍 **Real-time RF spectrum monitoring** across multiple frequencies
- 🔔 **Instant alerts** via macOS notifications when suspicious signals are detected
- 📱 **Proximity detection** for Bluetooth devices (10ft) and cell phones (15ft)
- 📊 **Visual analysis** with auto-generated spectrum plots comparing anomalies against baseline
- 📱 **Email notifications** for remote monitoring capabilities
- 🔄 **Adaptive baseline** creation for your specific RF environment
- 🔌 **One-click installation** - be up and running in minutes
- 🖥️ **Native macOS integration** with desktop shortcuts and notifications
- 🔧 **Highly configurable** frequency bands, sensitivity, and alert thresholds

## 🚀 One-Click Installation

```bash
curl -sSL https://raw.githubusercontent.com/yourusername/rf-ids/main/install_rf_ids.sh | bash
```

That's it! The installer handles everything automatically:
- Installing all required dependencies and libraries
- Setting up the monitoring script and configuration
- Creating desktop shortcuts for easy access
- Configuring autostart options (optional)

## 📖 How It Works

RF-IDS creates a baseline of the normal RF spectrum in your environment, then continuously scans for deviations that could indicate security threats:

1. **Baseline Creation**: First-time setup samples your local RF environment to establish what's "normal"
2. **Continuous Monitoring**: Cycles through configured frequencies (WiFi, Bluetooth, common ISM bands, etc.)
3. **Anomaly Detection**: Identifies signals that exceed your configured power threshold
4. **Alert System**: Triggers notifications, logs events, and saves spectrum visualizations 
5. **Analysis**: Provides spectral plots showing exactly where and how anomalies differ from baseline

## 🛠️ Requirements

- macOS 10.15+ (Catalina or newer)
- RTL-SDR dongle (RTL2832U-based)
- USB port
- Internet connection (for installation only)

## 📊 Example Visualization

When RF-IDS detects an anomaly, it automatically generates visualizations like this:

![RF Spectrum Analysis](https://placeholder-for-visualization.com/image.png)

The upper graph shows baseline vs. current spectrum, while the lower graph highlights specific anomalies that triggered the alert.

## 🔧 Configuration Options

The system is fully configurable via the `config.json` file:

```json
{
  "frequencies": [915, 2412, 2437, 2462, 2480, 433, 868],
  "threshold": 12,
  "scan_interval": 5,
  "...": "..."
}
```

## 📚 Use Cases

- 🏢 **Enterprise Security**: Monitor for unauthorized wireless devices in secure areas
- 🏠 **Smart Home Security**: Detect potential attacks against IoT devices
- 🔒 **TEMPEST Protections**: Identify potential data exfiltration via RF
- 🛑 **Device-Free Zones**: Enforce no-phone policies in sensitive or classified environments
- 🔒 **Meeting Security**: Alert when unauthorized devices enter conference rooms during sensitive discussions  
- 🔬 **Security Research**: Analyze wireless protocols for vulnerabilities
- 🕵️ **Digital Forensics**: Gather RF evidence during incident response

## ⚡ Quick Start

After installation:

1. Double-click the **RF-IDS** icon on your desktop
2. The system will first create a baseline RF profile (takes ~1 minute)
3. Monitoring begins automatically after baseline creation
4. Check the `rf_ids_data` folder for logs and visualizations

## 🤝 Contributing

Contributions are welcome! Feel free to:

- Report bugs and suggest features by opening issues
- Submit pull requests for improvements
- Share your use cases and success stories

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements

- RTL-SDR community for drivers and tools
- GNU Radio project for signal processing capabilities
- Python scientific computing community

---

<p align="center">
  Made with ❤️ for the cybersecurity community
</p>
