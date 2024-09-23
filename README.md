# LogParser

## Overview
This Log Analysis Tool is a Python-based utility designed to provide real-time monitoring and analysis of system logs. It focuses on three key areas of system security:

1. UFW (Uncomplicated Firewall) logs
2. Authentication logs
3. Fail2ban logs

The tool offers a live, interactive dashboard that updates at regular intervals, providing system administrators with valuable insights into potential security threats and system activities.

## Features
- Real-time parsing and analysis of UFW, Auth, and Fail2ban logs
- Live updating dashboard with rich text formatting
- Configurable update intervals
- Display of key metrics including:
  - Blocked connections and top blocked IPs
  - Failed and successful login attempts
  - Fail2ban statistics

## Requirements
- Python 3.6+
- Dependencies listed in `requirements.txt`

## Installation
1. Clone this repository:
   ```
   git clone https://github.com/yourusername/log-analysis-tool.git
   ```
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Configuration
The tool comes with a default `settings.json` file configured for standard Unix/Linux systems. The default configuration is:

```json
{
    "ufw_log": "/var/log/ufw.log",
    "auth_log": "/var/log/auth.log",
    "fail2ban_log": "/var/log/fail2ban.log",
    "report_log": "/var/log/report.log",
    "update_interval": 5
}
```

You can modify this file if your system uses different log file locations or if you want to change the update interval.

## Usage
Run the script with Python:

```
python log_analysis_tool.py
```

The dashboard will start and update automatically based on the configured interval (default is 5 seconds).

## Customization
If you need to adjust the log file paths or update interval, you can modify the `settings.json` file. The `update_interval` is in seconds.

## Contributing
Contributions, issues, and feature requests are welcome. Feel free to check [issues page](https://github.com/yourusername/log-analysis-tool/issues) if you want to contribute.

## License
[MIT](https://choosealicense.com/licenses/mit/)

## Security Note
While this tool is designed to work with standard log file locations, always ensure you have the necessary permissions to access these logs. Be cautious when sharing or deploying this tool, as log files may contain sensitive system information.
