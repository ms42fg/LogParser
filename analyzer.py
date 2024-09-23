import time
import json
import re
from collections import Counter
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text

console = Console()

def load_settings(settings_file='settings.json'):
    try:
        with open(settings_file, 'r') as f:
            settings = json.load(f)
        required_keys = ['ufw_log', 'auth_log', 'fail2ban_log', 'update_interval']
        if not all(key in settings for key in required_keys):
            raise ValueError("Missing required keys in settings.json")
        return settings
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        console.print(f"Error loading settings: {e}", style="bold red")
        exit(1)

def parse_ufw_log(filename):
    ufw_data = {'blocked_ips': Counter(), 'targeted_ports': Counter()}
    try:
        with open(filename, 'r') as f:
            for line in f:
                if 'UFW BLOCK' in line:
                    ip_match = re.search(r'SRC=(\S+)', line)
                    port_match = re.search(r'DPT=(\d+)', line)
                    if ip_match:
                        ufw_data['blocked_ips'][ip_match.group(1)] += 1
                    if port_match:
                        ufw_data['targeted_ports'][port_match.group(1)] += 1
    except FileNotFoundError:
        console.print(f"UFW log file not found: {filename}", style="bold red")
    return ufw_data

def parse_auth_log(filename):
    auth_data = {
        'failed_logins': 0,
        'successful_logins': 0,
        'failed_usernames': Counter(),
        'failed_ips': Counter(),
        'successful_usernames': Counter(),
        'successful_ips': Counter()
    }
    try:
        with open(filename, 'r') as f:
            for line in f:
                if 'Failed password' in line:
                    auth_data['failed_logins'] += 1
                    user_match = re.search(r'for (invalid user )?(\S+)', line)
                    ip_match = re.search(r'from (\S+)', line)
                    if user_match:
                        auth_data['failed_usernames'][user_match.group(2)] += 1
                    if ip_match:
                        auth_data['failed_ips'][ip_match.group(1)] += 1
                elif 'Invalid user' in line:
                    auth_data['failed_logins'] += 1
                    user_match = re.search(r'Invalid user (\S+)', line)
                    ip_match = re.search(r'from (\S+)', line)
                    if user_match:
                        auth_data['failed_usernames'][user_match.group(1)] += 1
                    if ip_match:
                        auth_data['failed_ips'][ip_match.group(1)] += 1
                elif 'Accepted' in line:
                    auth_data['successful_logins'] += 1
                    user_match = re.search(r'for (\S+)', line)
                    ip_match = re.search(r'from (\S+)', line)
                    if user_match:
                        auth_data['successful_usernames'][user_match.group(1)] += 1
                    if ip_match:
                        auth_data['successful_ips'][ip_match.group(1)] += 1
    except FileNotFoundError:
        console.print(f"Auth log file not found: {filename}", style="bold red")
    return auth_data

def parse_fail2ban_log(filename):
    fail2ban_data = {'total_bans': 0, 'banned_ips': Counter()}
    try:
        with open(filename, 'r') as f:
            for line in f:
                if 'Ban' in line:
                    fail2ban_data['total_bans'] += 1
                    ip_match = re.search(r'Ban (\S+)', line)
                    if ip_match:
                        fail2ban_data['banned_ips'][ip_match.group(1)] += 1
    except FileNotFoundError:
        console.print(f"Fail2ban log file not found: {filename}", style="bold red")
    return fail2ban_data

def format_ufw_log(ufw_data):
    text = Text()
    text.append("Total Blocked Connections: ", style="white")
    text.append(f"{sum(ufw_data['blocked_ips'].values())}\n", style="green")
    text.append("Top 5 Blocked IPs:\n", style="white")
    for ip, count in ufw_data['blocked_ips'].most_common(5):
        text.append(f"{ip:<39}", style="green")
        text.append(f"({count} blocks)\n", style="white")
    text.append("Most Targeted Ports:\n", style="white")
    for port, count in ufw_data['targeted_ports'].most_common(5):
        text.append(f"{port:<6}", style="green")
        text.append(f" - {count} attempts\n", style="white")
    return text

def format_auth_log(auth_data):
    text = Text()
    text.append("Failed Login Attempts: ", style="white")
    text.append(f"{auth_data['failed_logins']}\n", style="red")
    text.append("Successful Logins: ", style="white")
    text.append(f"{auth_data['successful_logins']}\n", style="green")
    text.append("Top 5 Usernames for Failed Logins:\n", style="white")
    for username, count in auth_data['failed_usernames'].most_common(5):
        text.append(f"{username:<15}", style="red")
        text.append(f"({count} attempts)\n", style="white")
    text.append("Top 5 IPs for Failed Logins:\n", style="white")
    for ip, count in auth_data['failed_ips'].most_common(5):
        text.append(f"{ip:<39}", style="red")
        text.append(f"({count} attempts)\n", style="white")
    text.append("Top 5 Usernames for Successful Logins:\n", style="white")
    for username, count in auth_data['successful_usernames'].most_common(5):
        text.append(f"{username:<15}", style="green")
        text.append(f"({count} logins)\n", style="white")
    text.append("Top 5 IPs for Successful Logins:\n", style="white")
    for ip, count in auth_data['successful_ips'].most_common(5):
        text.append(f"{ip:<39}", style="green")
        text.append(f"({count} logins)\n", style="white")
    return text

def format_fail2ban_log(fail2ban_data):
    text = Text()
    text.append("Total Bans: ", style="white")
    text.append(f"{fail2ban_data['total_bans']}\n", style="red")
    text.append("Currently Banned IPs: ", style="white")
    text.append(f"{len(fail2ban_data['banned_ips'])}\n", style="red")
    text.append("Top 5 Banned IPs:\n", style="white")
    for ip, count in fail2ban_data['banned_ips'].most_common(5):
        text.append(f"{ip:<39}", style="red")
        text.append(f"({count} bans)\n", style="white")
    return text

def create_layout():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=1),  # Reduced to 1 row
        Layout(name="ufw"),
        Layout(name="auth"),
        Layout(name="fail2ban")
    )
    return layout

def display_log_summary(ufw_data, auth_data, fail2ban_data):
    layout = create_layout()
    header = Text(f"🔒 Log Analysis Summary - Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    header.stylize("cyan")
    layout["header"].update(header)
    layout["ufw"].update(Panel(format_ufw_log(ufw_data), title="🛡️ UFW Log", border_style="blue"))
    layout["auth"].update(Panel(format_auth_log(auth_data), title="🔑 Auth Log", border_style="yellow"))
    layout["fail2ban"].update(Panel(format_fail2ban_log(fail2ban_data), title="⛔ Fail2ban Log", border_style="red"))
    return layout

def main():
    settings = load_settings()
    with Live(refresh_per_second=1/settings['update_interval'], screen=True) as live:
        while True:
            ufw_data = parse_ufw_log(settings['ufw_log'])
            auth_data = parse_auth_log(settings['auth_log'])
            fail2ban_data = parse_fail2ban_log(settings['fail2ban_log'])
            live.update(display_log_summary(ufw_data, auth_data, fail2ban_data))
            time.sleep(settings['update_interval'])

if __name__ == "__main__":
    main()