# LogParser

### Overview
This Log Analysis Tool is a Python-based utility designed to provide real-time monitoring and analysis of system logs. It focuses on three key areas of system security:

1. UFW (Uncomplicated Firewall) logs
2. Authentication logs
3. Fail2ban logs

The tool offers a live, interactive dashboard that updates at regular intervals, providing system administrators with valuable insights into potential security threats and system activities.

### Features
- Real-time parsing and analysis of UFW, Auth, and Fail2ban logs
- Live updating dashboard with rich text formatting
- Configurable update intervals
- Display of key metrics including:
  - Blocked connections and top blocked IPs
  - Failed and successful login attempts
  - Fail2ban statistics

### Requirements
- Python 3.6+
- Dependencies listed in `requirements.txt`

### Installation
1. Clone this repository:
   ```
   git clone https://github.com/ms42fg/LogParser.git
   ```
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

### Configuration
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

### Usage
Run the script with Python:

```
python log_analysis_tool.py
```

The dashboard will start and update automatically based on the configured interval (default is 5 seconds).

### Example Output
When you run the Log Analysis Tool, you'll see a live-updating dashboard similar to this:

```
🔒 Log Analysis Summary - Last Updated: 2024-09-23 15:30:45
┌────────────────────────────────────────────────────────────────────────────┐
│ 🛡️ UFW Log                                                                  │
│                                                                            │
│ Total Blocked Connections: 1337                                            │
│ Top 5 Blocked IPs:                                                         │
│ 192.168.1.100                           (500 blocks)                       │
│ 10.0.0.50                               (300 blocks)                       │
│ 172.16.0.1                              (200 blocks)                       │
│ 192.168.0.10                            (150 blocks)                       │
│ 10.10.10.10                             (100 blocks)                       │
│ Most Targeted Ports:                                                       │
│ 22     - 800 attempts                                                      │
│ 80     - 300 attempts                                                      │
│ 443    - 150 attempts                                                      │
│ 3306   - 50 attempts                                                       │
│ 21     - 37 attempts                                                       │
└────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────┐
│ 🔑 Auth Log                                                                 │
│                                                                            │
│ Failed Login Attempts: 250                                                 │
│ Successful Logins: 50                                                      │
│ Top 5 Usernames for Failed Logins:                                         │
│ admin           (100 attempts)                                             │
│ root            (75 attempts)                                              │
│ user            (40 attempts)                                              │
│ test            (20 attempts)                                              │
│ guest           (15 attempts)                                              │
│ Top 5 IPs for Failed Logins:                                               │
│ 192.168.1.100                           (80 attempts)                      │
│ 10.0.0.50                               (60 attempts)                      │
│ 172.16.0.1                              (50 attempts)                      │
│ 192.168.0.10                            (40 attempts)                      │
│ 10.10.10.10                             (20 attempts)                      │
└────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────┐
│ ⛔ Fail2ban Log                                                             │
│                                                                            │
│ Total Bans: 75                                                             │
│ Currently Banned IPs: 25                                                   │
│ Top 5 Banned IPs:                                                          │
│ 192.168.1.100                           (20 bans)                          │
│ 10.0.0.50                               (15 bans)                          │
│ 172.16.0.1                              (12 bans)                          │
│ 192.168.0.10                            (8 bans)                           │
│ 10.10.10.10                             (5 bans)                           │
└────────────────────────────────────────────────────────────────────────────┘
```

This dashboard provides a quick overview of your system's security status, including blocked connections, login attempts, and banned IPs. The information updates in real-time based on your configured interval.

### Customization
If you need to adjust the log file paths or update interval, you can modify the `settings.json` file. The `update_interval` is in seconds.

### License
[MIT](https://choosealicense.com/licenses/mit/)

### Security Note
While this tool is designed to work with standard log file locations, always ensure you have the necessary permissions to access these logs. Be cautious when sharing or deploying this tool, as log files may contain sensitive system information.
