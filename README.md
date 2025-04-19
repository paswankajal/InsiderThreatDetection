# Insider Threat Detection Tool

A Python-based tool to monitor and detect potential insider threats by tracking file access, off-hour system activities, USB device insertions, and suspicious processes. Events are logged to an SQLite database, and a simple Tkinter GUI is provided to view and refresh logs in real-time.

## Features

- **File Access Monitoring:** Detects access to sensitive directories and logs file activities.
- **Off-Hours Detection:** Flags any system activity occurring outside of defined working hours.
- **USB Device Monitoring:** Monitors the insertion of removable USB drives.
- **Suspicious Process Detection:** Flags usage of high-risk system processes like `cmd.exe`, `powershell.exe`, and others.
- **Real-time Logging:** Logs activities every 60 seconds and displays them in an easy-to-use Tkinter-based GUI.

## Technologies Used

- **Python 3**
- **Tkinter** (GUI)
- **SQLite3** (Log storage)
- **Psutil** (System monitoring)
- **OS, Time, Datetime, Getpass** (Core modules)

## Getting Started

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/insider-threat-tool.git
Navigate to the project directory:

bash
Copy
Edit
cd insider-threat-tool
Run the tool:

```bash

python main.py
```
Notes
Ensure Python 3 is installed.

Tested on Windows. Modify paths for compatibility with other operating systems.

Run with administrator privileges for full functionality.
