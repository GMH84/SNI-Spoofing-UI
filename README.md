# SNI Spoofing UI

A modern, glassmorphic desktop client for Windows designed to bypass Deep Packet Inspection (DPI) and internet filtering. This application combines a native Python TCP packet spoofing engine with a sleek Liquid Glass user interface presented as a standalone, frameless desktop window.

This project is a modified fork of the Python-based [SNI-Spoofing by @patterniha](https://github.com/patterniha/SNI-Spoofing) core engine, presented inside a desktop wrapper using `pywebview` and `Flask`.

---

## ⚡ Key Features

* **Liquid Glass Interface**: Sleek, fully responsive translucent dashboard design with native drag, minimize, and close controls.
* **Native Python Packet Spoofing Engine**: Intercepts and modifies TCP handshakes directly in the Python runtime using `pydivert` (a Python wrapper for WinDivert). It injects fake Client Hello packets with manipulated sequence numbers (`wrong_seq` bypass) to circumvent network blockages.
* **Real-time Live Metrics Dashboard**:
  * **Gateway Route**: Automatically detects and displays your local physical IPv4 gateway.
  * **RTT Latency (Ping)**: Measures the exact time in milliseconds from sending your outbound TCP SYN to receiving the remote server's inbound TCP SYN-ACK during handshakes.
  * **Traffic Speed**: Tracks real-time data throughput (formatted dynamically as `KB/s` or `MB/s`).
  * **Traffic Volume**: Monitors total data consumed over the active session (formatted dynamically as `KB`, `MB`, or `GB`).
  * **Session Stopwatch**: Live duration counter tracking how long your connection has been active.
* **Integrated Log Terminal**: Review raw traffic activity and connection diagnostics directly inside the UI.
* **Auto-Initialization**: Automatically generates `config.ini` with safe defaults on first run if it does not already exist.
* **GitHub Releases Update Check**: Queries the official GitHub Releases API for this repository silently on launch or via the UI, keeping you notified of newer releases.

---

## 🛠️ Prerequisites & Installation

Since this application interacts directly with the Windows kernel-level network stack, it **requires Windows** and must be executed with **Administrator Privileges**.

1. Clone this repository to your local machine:
   ```bash
   git clone https://github.com/GMH84/SNI-Spoofing-UI.git
   cd SNI-Spoofing-UI
   ```

2. Install the required Python dependencies:
   ```bash
   pip install pydivert pywebview flask
   ```

---

## 🚀 How to Run

To run the application with the terminal console visible:
```bash
python main.py
```

To run the application entirely in the background (suppressing the black CMD window while still automatically popping open your browser/GUI):
```bash
pythonw main.py
```
*(Alternatively, you can rename `main.py` to `main.pyw` to run it silently by default on double-click).*

---

## 📦 Bundling into a Standalone Executable (`.exe`)

You can compile the entire application, including the embedded assets, into a single executable folder using `PyInstaller`.

1. Install PyInstaller:
   ```bash
   pip install pyinstaller
   ```

2. Compile the project (making sure to bundle the HTML asset):
   ```bash
   pyinstaller --noconfirm --onedir --windowed --add-data "index.html;." main.py
   ```
   *Your built executable will be generated inside the `dist/main/` folder.*

---

## 📝 Configuration File (`config.ini`)

On first launch, the program automatically generates a `config.ini` file in the same directory. You can edit this file with any standard text editor to adjust your bypass routing targets:

```ini
listen = 127.0.0.1:40443
connect = 104.19.229.21:443
fake-sni = hcaptcha.com
```

---

## ⚖️ License & Attribution

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License v3** as published by the Free Software Foundation. 

* This program is distributed **WITHOUT ANY WARRANTY**. For details, view the [GPLv3 License](https://www.gnu.org/licenses/gpl-3.0.html).
* Upstream core repository: [patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing)
* Fork repository: [GMH84/SNI-Spoofing-UI](https://github.com/GMH84/SNI-Spoofing-UI)
```
