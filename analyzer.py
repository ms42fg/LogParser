import time
import json
import re
import subprocess
from collections import Counter
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
import threading

console = Console()

def load_settings(settings_file='settings.json'):
    try:
        with open(settings_file, 'r') as f:
            settings = json.load(f)
        required_keys = ['ufw_log', 'auth_log', 'fail2ban_log', 'update_interval', 'verbose']
        if not all(key in settings for key in required_keys):
            raise ValueError("Missing required keys in settings.json")
        verbose_keys = ['blocked_ips', 'targeted_ports', 'failed_usernames', 'failed_ips', 'successful_usernames', 'successful_ips', 'banned_ips']
        if not all(key in settings['verbose'] for key in verbose_keys):
            raise ValueError("Missing required verbose keys in settings.json")
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

def get_fail2ban_status():
    current_bans = {'total_bans': 0, 'banned_ips': Counter(), 'jails': []}
    try:
        # Get list of jails
        jail_list = subprocess.run(['sudo', 'fail2ban-client', 'status'], capture_output=True, text=True)
        jails = jail_list.stdout.strip().split('\n')[-1].split('\t')[-1].split(', ')
        current_bans['jails'] = jails

        for jail in jails:
            jail_status = subprocess.run(['sudo', 'fail2ban-client', 'status', jail], capture_output=True, text=True)
            status_lines = jail_status.stdout.strip().split('\n')
            for line in status_lines:
                if 'Currently banned:' in line:
                    banned_count = int(line.split('\t')[-1])
                    current_bans['total_bans'] += banned_count
                elif 'Banned IP list:' in line:
                    banned_ips = line.split('\t')[-1].split()
                    for ip in banned_ips:
                        current_bans['banned_ips'][ip] += 1
    except subprocess.CalledProcessError as e:
        console.print(f"Error running fail2ban-client: {e}", style="bold red")
    return current_bans

def parse_fail2ban_log(filename):
    fail2ban_data = {'total_bans': 0, 'banned_ips': Counter(), 'current_bans': 0, 'currently_banned_ips': Counter(), 'active_jails': []}
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
    
    # Double-check with fail2ban-client
    current_bans = get_fail2ban_status()
    fail2ban_data['current_bans'] = current_bans['total_bans']
    fail2ban_data['currently_banned_ips'] = current_bans['banned_ips']
    fail2ban_data['active_jails'] = current_bans['jails']
    
    return fail2ban_data

def format_ufw_log(ufw_data, verbose_settings):
    text = Text()
    text.append("Total Blocked Connections: ", style="white")
    text.append(f"{sum(ufw_data['blocked_ips'].values())}\n", style="green")
    text.append(f"Top {verbose_settings['blocked_ips']} Blocked IPs:\n", style="white")
    for ip, count in ufw_data['blocked_ips'].most_common(verbose_settings['blocked_ips']):
        text.append(f"{ip:<39}", style="green")
        text.append(f"({count} blocks)\n", style="white")
    text.append(f"Top {verbose_settings['targeted_ports']} Most Targeted Ports:\n", style="white")
    for port, count in ufw_data['targeted_ports'].most_common(verbose_settings['targeted_ports']):
        text.append(f"{port:<6}", style="green")
        text.append(f" - {count} attempts\n", style="white")
    return text

def format_auth_log(auth_data, verbose_settings):
    text = Text()
    text.append("Failed Login Attempts: ", style="white")
    text.append(f"{auth_data['failed_logins']}\n", style="red")
    text.append("Successful Logins: ", style="white")
    text.append(f"{auth_data['successful_logins']}\n", style="green")
    text.append(f"Top {verbose_settings['failed_usernames']} Usernames for Failed Logins:\n", style="white")
    for username, count in auth_data['failed_usernames'].most_common(verbose_settings['failed_usernames']):
        text.append(f"{username:<15}", style="red")
        text.append(f"({count} attempts)\n", style="white")
    text.append(f"Top {verbose_settings['failed_ips']} IPs for Failed Logins:\n", style="white")
    for ip, count in auth_data['failed_ips'].most_common(verbose_settings['failed_ips']):
        text.append(f"{ip:<39}", style="red")
        text.append(f"({count} attempts)\n", style="white")
    text.append(f"Top {verbose_settings['successful_usernames']} Usernames for Successful Logins:\n", style="white")
    for username, count in auth_data['successful_usernames'].most_common(verbose_settings['successful_usernames']):
        text.append(f"{username:<15}", style="green")
        text.append(f"({count} logins)\n", style="white")
    text.append(f"Top {verbose_settings['successful_ips']} IPs for Successful Logins:\n", style="white")
    for ip, count in auth_data['successful_ips'].most_common(verbose_settings['successful_ips']):
        text.append(f"{ip:<39}", style="green")
        text.append(f"({count} logins)\n", style="white")
    return text

def format_fail2ban_log(fail2ban_data, verbose_settings):
    text = Text()
    text.append("Total Bans (historical): ", style="white")
    text.append(f"{fail2ban_data['total_bans']}\n", style="red")
    text.append("Currently Banned IPs: ", style="white")
    text.append(f"{fail2ban_data['current_bans']}\n", style="red")
    
    # Display currently banned IPs by jail
    text.append("Currently Banned IPs by Jail:\n", style="white")
    for jail in fail2ban_data['active_jails']:
        text.append(f"Jail: {jail}\n", style="yellow")
        jail_status = subprocess.run(['sudo', 'fail2ban-client', 'status', jail], capture_output=True, text=True)
        status_lines = jail_status.stdout.strip().split('\n')
        for line in status_lines:
            if 'Banned IP list:' in line:
                banned_ips = line.split('\t')[-1].split()
                for ip in banned_ips:
                    text.append(f"  {ip:<39}", style="red")
                    text.append(f"(in {jail})\n", style="white")
    
    # Display top banned IPs (historical)
    text.append(f"Top {verbose_settings['banned_ips']} Banned IPs (historical):\n", style="white")
    for ip, count in fail2ban_data['banned_ips'].most_common(verbose_settings['banned_ips']):
        text.append(f"{ip:<39}", style="red")
        text.append(f"({count} bans)", style="white")
        if ip in fail2ban_data['currently_banned_ips']:
            text.append(" [CURRENTLY BANNED]", style="bold red")
        text.append("\n")
    
    text.append("Active Jails: ", style="white")
    text.append(f"{', '.join(fail2ban_data['active_jails'])}\n", style="yellow")
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

def display_log_summary(ufw_data, auth_data, fail2ban_data, verbose_settings):
    layout = create_layout()
    header = Text(f"🔒 Log Analysis Summary - Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    header.stylize("cyan")
    layout["header"].update(header)
    layout["ufw"].update(Panel(format_ufw_log(ufw_data, verbose_settings), title="🛡️ UFW Log", border_style="blue"))
    layout["auth"].update(Panel(format_auth_log(auth_data, verbose_settings), title="🔑 Auth Log", border_style="yellow"))
    layout["fail2ban"].update(Panel(format_fail2ban_log(fail2ban_data, verbose_settings), title="⛔ Fail2ban Log", border_style="red"))
    return layout

def check_for_quit(stop_event):
    while not stop_event.is_set():
        user_input = input()
        if user_input.lower() == 'q':
            console.print("\nQuitting the program...", style="bold yellow")
            stop_event.set()

def display_welcome_message():
    welcome_text = Text()
    welcome_text.append("Welcome to the Log Analyzer!\n\n", style="bold green")
    welcome_text.append("This program will continuously analyze and display summaries of your log files.\n", style="cyan")
    welcome_text.append("The display will update every few seconds based on your settings.\n\n", style="cyan")
    welcome_text.append("Instructions:\n", style="bold yellow")
    welcome_text.append("- The program will start analyzing logs automatically.\n", style="yellow")
    welcome_text.append("- To quit at any time, simply type ", style="yellow")
    welcome_text.append("q", style="bold red")
    welcome_text.append(" and press ", style="yellow")
    welcome_text.append("Enter", style="bold red")
    welcome_text.append(".\n\n", style="yellow")
    welcome_text.append("Press Enter to start...", style="bold green")
    
    console.print(Panel(welcome_text, title="Log Analyzer", border_style="blue"))
    input()

def main():
    settings = load_settings()
    verbose_settings = settings['verbose']
    
    display_welcome_message()
    
    stop_event = threading.Event()
    
    # Start a thread to check for the 'q' input
    quit_thread = threading.Thread(target=check_for_quit, args=(stop_event,))
    quit_thread.daemon = True
    quit_thread.start()
    
    try:
        with Live(refresh_per_second=1/settings['update_interval'], screen=True) as live:
            while not stop_event.is_set():
                ufw_data = parse_ufw_log(settings['ufw_log'])
                auth_data = parse_auth_log(settings['auth_log'])
                fail2ban_data = parse_fail2ban_log(settings['fail2ban_log'])
                live.update(display_log_summary(ufw_data, auth_data, fail2ban_data, verbose_settings))
                time.sleep(settings['update_interval'])
    except KeyboardInterrupt:
        console.print("\nProgram interrupted. Exiting...", style="bold yellow")
    finally:
        stop_event.set()
        console.print("Analysis stopped. Thank you for using Log Analyzer!", style="bold green")

if __name__ == "__main__":
    main()
