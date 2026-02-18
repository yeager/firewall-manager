# Firewall Manager

GTK4/Adwaita frontend for UFW (Uncomplicated Firewall).

![License](https://img.shields.io/badge/license-GPL--3.0-blue)
![Python](https://img.shields.io/badge/python-3.10+-green)

## Features

- View firewall status, default policies, and logging
- Enable/disable firewall with toggle switch
- List all active rules with visual indicators
- Add rules with full dialog (port, protocol, direction, source)
- Delete rules
- Quick profiles: SSH, HTTP/S, DNS, Reset
- Uses `pkexec` for privilege escalation
- Dark/light theme toggle

## Installation

```bash
pip install -e .
firewall-manager
```

## Requirements

- Python 3.10+
- GTK4, libadwaita
- PyGObject
- UFW, polkit (pkexec)

## License

GPL-3.0-or-later — Daniel Nylander
